"""File transfer relay on the server (protocol-spec section 11).

The server sits between sender A and receiver B:
  FILE_OFFER (A) -> FILE_INCOMING (B) -> FILE_RESPONSE (B) -> FILE_ACCEPT (A)
  -> FILE_READY to both -> DATA from A is copied to B's stream -> FILE_COMPLETE (B) -> A.

File bytes are copied as they arrive, without keeping the whole file. Packets sent to the
receiver are remembered until the receiver ACKs them and are sent again if the ACK is late,
so a lost datagram between server and receiver does not leave a hole in the file.
"""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field

from ..file_transfer.packet import decode_ack_payload

log = logging.getLogger("ccp.relay")

FIRST_FILE_STREAM = 4
CHUNK_SIZE = 1000
RESEND_AFTER = 0.5          # seconds without ACK before a relayed packet is sent again
MAX_RESENDS = 10
MAX_FILE_BYTES = 1 << 30    # refuse offers larger than 1 GiB
SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")


@dataclass(eq=False)
class Transfer:
    file_id: str
    offer_id: str                 # id of the sender's FILE_OFFER message (the ERROR / FILE_ACCEPT carry it)
    sender: object                # ClientSession
    receiver: object
    filename: str
    size_bytes: int
    sha256: str
    sender_stream: int | None = None
    receiver_stream: int | None = None
    accepted: bool = False


@dataclass
class Pending:
    stream_id: int
    offset: int
    data: bytes
    fin: bool
    sent_at: float
    resends: int = 0


class FileRelay:
    """State of all running transfers. The server gives it small callbacks for sending."""

    def __init__(self, send_message, send_error, send_data, user_lookup, user_known) -> None:
        self._send_message = send_message      # (session, type, payload, req_id=None)
        self._send_error = send_error          # (session, code, message, related_type, req_id)
        self._send_data = send_data            # (session, stream_id, offset, data, fin) -> packet number
        self._lookup = user_lookup             # username -> session or None
        self._user_known = user_known          # username -> bool (account exists)
        self._lock = threading.RLock()
        self._transfers: dict[str, Transfer] = {}
        self._next_stream: dict[int, int] = {}                 # connection_id -> next free file stream
        self._pending: dict[int, dict[int, Pending]] = {}      # receiver connection_id -> packet number -> Pending

    # ---- control messages ------------------------------------------------
    def on_offer(self, session, body: dict, req_id: str) -> None:
        target, filename = body.get("target"), body.get("filename")
        size, sha = body.get("size_bytes"), body.get("sha256")
        if (not isinstance(target, str) or not target or not isinstance(filename, str)
                or not filename or type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(sha, str) or not SHA256_HEX.fullmatch(sha)):
            self._send_error(session, "INVALID_PAYLOAD",
                             "target, filename, size_bytes and sha256 are required", "FILE_OFFER", req_id)
            return
        peer = self._lookup(target)
        if peer is None or peer is session:
            code = "USER_OFFLINE" if self._user_known(target) and peer is None else "USER_NOT_FOUND"
            self._send_error(session, code, "recipient is not available", "FILE_OFFER", req_id)
            return
        transfer = Transfer(uuid.uuid4().hex, req_id, session, peer, filename, size, sha)
        with self._lock:
            self._transfers[transfer.file_id] = transfer
        self._send_message(peer, "FILE_INCOMING", {
            "file_id": transfer.file_id, "sender": session.username,
            "filename": filename, "size_bytes": size, "sha256": sha})

    def on_response(self, session, body: dict, req_id: str) -> None:
        transfer = self._find(body.get("file_id"), session, as_receiver=True)
        if transfer is None:
            self._send_error(session, "TRANSFER_NOT_FOUND", "no such transfer", "FILE_RESPONSE", req_id)
            return
        if body.get("accepted") is not True:
            self._send_message(transfer.sender, "FILE_ACCEPT", {
                "file_id": transfer.file_id, "accepted": False,
                "error": "rejected by the receiver"}, transfer.offer_id)
            self._forget(transfer)
            return
        with self._lock:
            if transfer.accepted:
                return
            transfer.accepted = True
            transfer.sender_stream = self._take_stream(transfer.sender)
            transfer.receiver_stream = self._take_stream(transfer.receiver)
        self._send_message(transfer.sender, "FILE_ACCEPT", {
            "file_id": transfer.file_id, "accepted": True, "error": None}, transfer.offer_id)
        self._send_message(transfer.sender, "FILE_READY", {
            "file_id": transfer.file_id, "stream_id": transfer.sender_stream, "chunk_size": CHUNK_SIZE})
        self._send_message(transfer.receiver, "FILE_READY", {
            "file_id": transfer.file_id, "stream_id": transfer.receiver_stream, "chunk_size": CHUNK_SIZE})

    def on_complete(self, session, body: dict, req_id: str) -> None:
        transfer = self._find(body.get("file_id"), session, as_receiver=True)
        if transfer is None:
            self._send_error(session, "TRANSFER_NOT_FOUND", "no such transfer", "FILE_COMPLETE", req_id)
            return
        self._send_message(transfer.sender, "FILE_COMPLETE", {
            "file_id": transfer.file_id, "success": body.get("success") is True,
            "sha256": body.get("sha256") if isinstance(body.get("sha256"), str) else ""})
        self._forget(transfer)

    def on_cancel(self, session, body: dict, req_id: str) -> None:
        transfer = self._find(body.get("file_id"), session)
        if transfer is None:
            self._send_error(session, "TRANSFER_NOT_FOUND", "no such transfer", "FILE_CANCEL", req_id)
            return
        other = transfer.receiver if session is transfer.sender else transfer.sender
        reason = body.get("reason") if isinstance(body.get("reason"), str) else "cancelled"
        self._send_message(other, "FILE_CANCEL", {"file_id": transfer.file_id, "reason": reason})
        self._forget(transfer)

    # ---- file bytes ------------------------------------------------------
    def on_data(self, session, stream_id: int, offset: int, data: bytes, fin: bool) -> None:
        with self._lock:
            transfer = next((t for t in self._transfers.values()
                             if t.sender is session and t.sender_stream == stream_id), None)
            if transfer is None:
                log.debug("drop DATA for unknown file stream %d", stream_id)
                return
            if offset + len(data) > transfer.size_bytes:
                log.debug("drop DATA beyond the announced size of %s", transfer.file_id)
                return
            number = self._send_data(transfer.receiver, transfer.receiver_stream, offset, data, fin)
            self._pending.setdefault(transfer.receiver.connection_id, {})[number] = Pending(
                transfer.receiver_stream, offset, data, fin, time.monotonic())

    def on_ack(self, session, payload: bytes) -> None:
        with self._lock:
            pending = self._pending.get(session.connection_id)
            if not pending:
                return
            try:
                _, _, ranges = decode_ack_payload(payload)
            except ValueError:
                return
            for number in [n for n in pending if any(a <= n <= b for a, b in ranges)]:
                del pending[number]

    def resend_late(self, now: float) -> None:
        """Called by the server's sweeper: send again what the receiver has not acknowledged."""
        with self._lock:
            for transfer_receiver_id, pending in list(self._pending.items()):
                receiver = next((t.receiver for t in self._transfers.values()
                                 if t.receiver.connection_id == transfer_receiver_id), None)
                if receiver is None:
                    del self._pending[transfer_receiver_id]
                    continue
                for number, packet in list(pending.items()):
                    if now - packet.sent_at < RESEND_AFTER:
                        continue
                    del pending[number]
                    if packet.resends >= MAX_RESENDS:
                        log.warning("giving up on a file packet for %s", receiver.username)
                        continue
                    new_number = self._send_data(receiver, packet.stream_id, packet.offset,
                                                 packet.data, packet.fin)
                    pending[new_number] = Pending(packet.stream_id, packet.offset, packet.data,
                                                  packet.fin, now, packet.resends + 1)

    # ---- helpers ---------------------------------------------------------
    def on_session_closed(self, session) -> None:
        """A user left: cancel their transfers and tell the other side."""
        with self._lock:
            mine = [t for t in self._transfers.values() if t.sender is session or t.receiver is session]
            self._pending.pop(session.connection_id, None)
            self._next_stream.pop(session.connection_id, None)
        for transfer in mine:
            other = transfer.receiver if session is transfer.sender else transfer.sender
            try:
                self._send_message(other, "FILE_CANCEL", {
                    "file_id": transfer.file_id, "reason": "the other user disconnected"})
            except Exception:
                log.exception("could not tell %s about a cancelled transfer", other.address)
            self._forget(transfer)

    def _find(self, file_id, session, as_receiver: bool = False):
        if not isinstance(file_id, str):
            return None
        with self._lock:
            transfer = self._transfers.get(file_id)
        if transfer is None:
            return None
        if as_receiver:
            return transfer if transfer.receiver is session else None
        return transfer if session in (transfer.sender, transfer.receiver) else None

    def _take_stream(self, session) -> int:
        number = self._next_stream.get(session.connection_id, FIRST_FILE_STREAM)
        self._next_stream[session.connection_id] = number + 1
        return number

    def _forget(self, transfer: Transfer) -> None:
        with self._lock:
            self._transfers.pop(transfer.file_id, None)

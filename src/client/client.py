"""Application layer: authentication, broadcast/private messaging, and file upload."""

from __future__ import annotations

import logging
import queue
import re
import threading
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable

from ..common.exceptions import AuthenticationError
from ..common.exceptions import MalformedPacketError
from ..file_transfer.models import TransferMetadata, TransferRecord, TransferState
from ..file_transfer.packet import MAX_DATA_BYTES
from ..file_transfer.receiver import FileReceiver
from ..file_transfer.sender import build_file_offer, iter_segments
from .network import FIRST_FILE_STREAM, CcpClient, ConnectionState

log = logging.getLogger("ccp.client")

AUTH_TIMEOUT = 5.0
CONTROL_STREAM = 0
CHAT_STREAM = 1
BROADCAST_TARGET = "*"
PUMP_INTERVAL = 0.25
PARTIAL_DIR = ".partial"
# file_id becomes part of a temporary file name, so only accept plain identifiers.
SAFE_FILE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
TERMINAL_STATES = frozenset(
    {
        TransferState.REJECTED,
        TransferState.COMPLETED,
        TransferState.FAILED,
        TransferState.CANCELLED,
    }
)


class MessageMode(Enum):
    BROADCAST = "broadcast"
    PRIVATE = "private"


class OutgoingTransfer:
    """Sender-side view of one file transfer.

    `record.metadata.file_id` holds the local offer id (the FILE_OFFER message id)
    until the server assigns the real `file_id`.
    """

    def __init__(self, path: Path, record: TransferRecord) -> None:
        self.path = path
        self.record = record
        self.file_id: str | None = None


class IncomingTransfer:
    """Receiver-side view of a file another user wants to send."""

    def __init__(self, record: TransferRecord) -> None:
        self.record = record
        self.file_id: str = record.metadata.file_id
        self.responded = False
        self.receiver: FileReceiver | None = None
        self.saved_path: Path | None = None

    def receive_data(self, offset: int, data: bytes, fin: bool) -> None:
        if self.receiver is None or self.record.error:
            return
        try:
            self.receiver.on_data(offset, data, fin)
        except (ValueError, OSError) as exc:
            self.record.error = str(exc)


def _finished(transfer: OutgoingTransfer | IncomingTransfer) -> bool:
    return transfer.record.state in TERMINAL_STATES


class Client:
    """Provide login, chat, and file send/receive on top of a CCP network client."""

    def __init__(self, connection: CcpClient, download_dir: str | Path = "downloads") -> None:
        self.connection = connection
        self.download_dir = Path(download_dir)
        self.username: str | None = None
        self.transfer_listener: (
            Callable[[OutgoingTransfer | IncomingTransfer], None] | None
        ) = None
        self._lock = threading.RLock()
        self._transfers: list[OutgoingTransfer | IncomingTransfer] = []
        self._inbox: queue.Queue[dict] = queue.Queue()
        self._pump_thread: threading.Thread | None = None
        self._pump_stop = threading.Event()
        self._pump_error: Exception | None = None

    @property
    def authenticated(self) -> bool:
        return self.username is not None

    def login(self, username: str, password: str, timeout: float = AUTH_TIMEOUT) -> dict:
        if self.authenticated:
            raise RuntimeError("client is already authenticated")
        if self.connection.state is ConnectionState.DISCONNECTED:
            self.connection.connect()

        request_id = self.connection.send_message(
            CONTROL_STREAM,
            "AUTH",
            {"username": username, "password": password},
        )
        response = self.connection.wait_for_message(
            "AUTH_ACK", request_id=request_id, timeout=timeout
        )
        if response["type"] == "ERROR":
            raise AuthenticationError(
                str(response["payload"].get("message") or "authentication failed")
            )
        result = response["payload"]
        if result.get("success") is not True:
            raise AuthenticationError(
                str(result.get("error") or "authentication failed")
            )
        self.username = result["username"]
        self._start_pump()
        return result

    def send(
        self,
        mode: MessageMode,
        text: str,
        recipients: Iterable[str] = (),
    ) -> list[str]:
        self._require_authentication()
        if not isinstance(text, str) or not text.strip():
            raise ValueError("message text must not be empty")

        if mode is MessageMode.BROADCAST:
            return [
                self.connection.send_message(
                    CHAT_STREAM,
                    "MSG",
                    {"target": BROADCAST_TARGET, "text": text},
                )
            ]
        if mode is not MessageMode.PRIVATE:
            raise ValueError(f"unsupported message mode: {mode!r}")

        recipient_list = list(recipients)
        if any(not isinstance(target, str) for target in recipient_list):
            raise ValueError("private message recipients must be usernames")
        targets = list(dict.fromkeys(recipient_list))
        if not targets or any(not target.strip() for target in targets):
            raise ValueError("private messages require one or more usernames")
        if BROADCAST_TARGET in targets:
            raise ValueError("'*' is reserved for broadcast messages")

        return [
            self.connection.send_message(
                CHAT_STREAM,
                "MSG",
                {"target": target, "text": text},
            )
            for target in targets
        ]

    def send_broadcast(self, text: str) -> str:
        return self.send(MessageMode.BROADCAST, text)[0]

    def send_private(self, recipients: Iterable[str], text: str) -> list[str]:
        return self.send(MessageMode.PRIVATE, text, recipients)

    def request_users(self, timeout: float = 5.0) -> list[dict]:
        self._require_authentication()
        request_id = self.connection.send_message(
            CONTROL_STREAM, "USER_LIST_REQ", {}
        )
        response = self.connection.wait_for_message(
            "USER_LIST", request_id=request_id, timeout=timeout
        )
        if response["type"] == "ERROR":
            raise RuntimeError(
                str(response["payload"].get("message") or "user-list request failed")
            )
        users = response["payload"].get("users")
        if not isinstance(users, list):
            raise ValueError("server returned an invalid user list")
        return users

    def receive(self, timeout: float | None = None) -> dict:
        """Return the next server message not consumed by file-transfer handling."""
        self._require_authentication()
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            remaining = PUMP_INTERVAL if deadline is None else min(
                PUMP_INTERVAL, max(0.0, deadline - time.monotonic())
            )
            try:
                return self._inbox.get(timeout=remaining)
            except queue.Empty:
                pass
            if self._pump_error is not None:
                raise ConnectionError(
                    f"CCP connection failed: {self._pump_error}"
                ) from self._pump_error
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for a server message")

    def send_file(self, path: str | Path, target: str) -> OutgoingTransfer:
        """Offer a file to `target`; the transfer then proceeds in the background."""
        self._require_authentication()
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"not a file: {path}")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("file transfers require a username")
        if target == BROADCAST_TARGET:
            raise ValueError("files cannot be broadcast")

        offer = build_file_offer(path, target)
        offer_id = uuid.uuid4().hex
        record = TransferRecord(
            TransferMetadata(
                file_id=offer_id,
                sender=self.username,
                target=target,
                filename=offer["filename"],
                size_bytes=offer["size_bytes"],
                sha256=offer["sha256"],
            )
        )
        transfer = OutgoingTransfer(path=path, record=record)
        with self._lock:
            self._transfers.append(transfer)
        try:
            self.connection.send_message(
                CONTROL_STREAM, "FILE_OFFER", offer, request_id=offer_id
            )
        except Exception:
            with self._lock:
                self._transfers.remove(transfer)
            raise
        return transfer

    def cancel_file(
        self,
        transfer: OutgoingTransfer | IncomingTransfer,
        reason: str = "cancelled by user",
    ) -> bool:
        """Cancel an accepted transfer. Returns False if it already finished."""
        if _finished(transfer):
            return False
        if isinstance(transfer, IncomingTransfer) and not transfer.responded:
            raise ValueError("answer the offer with accept or reject instead")
        if transfer.file_id is None:
            raise ValueError("the server has not accepted this offer yet")
        self.connection.send_message(
            CONTROL_STREAM,
            "FILE_CANCEL",
            {"file_id": transfer.file_id, "reason": reason},
        )
        return self._set_state(transfer, TransferState.CANCELLED, reason)

    def respond_file(self, transfer: IncomingTransfer, accepted: bool) -> None:
        """Accept or reject a file offered by another user."""
        self._require_authentication()
        if not isinstance(transfer, IncomingTransfer):
            raise ValueError("only received offers can be accepted or rejected")
        with self._lock:
            if transfer.responded or transfer.record.state is not TransferState.OFFERED:
                raise ValueError("this offer was already answered")
            transfer.responded = True
        try:
            self.connection.send_message(
                CONTROL_STREAM, "FILE_RESPONSE",
                {"file_id": transfer.file_id, "accepted": accepted},
                request_id=transfer.file_id,
            )
        except Exception:
            transfer.responded = False
            raise
        if not accepted:
            self._set_state(transfer, TransferState.REJECTED, "rejected by you")

    def transfers(self) -> list[OutgoingTransfer | IncomingTransfer]:
        with self._lock:
            return list(self._transfers)

    def transfer_progress(self, transfer: OutgoingTransfer | IncomingTransfer) -> int:
        """Bytes of the file acknowledged by the server (sent) or written to disk (received)."""
        size = transfer.record.metadata.size_bytes
        if transfer.record.state is TransferState.COMPLETED:
            return size
        if isinstance(transfer, IncomingTransfer):
            receiver = transfer.receiver
            return receiver.bytes_received if receiver else 0
        stream_id = transfer.record.sender_stream_id
        if stream_id is None:
            return 0
        return min(self.connection.stream_acked_bytes(stream_id), size)

    def logout(self, timeout: float = 2.0) -> None:
        if not self.authenticated:
            self.connection.shutdown()
            return
        try:
            request_id = self.connection.send_message(
                CONTROL_STREAM, "LOGOUT", {}
            )
            response = self.connection.wait_for_message(
                "LOGOUT_ACK", request_id=request_id, timeout=timeout
            )
            if response["type"] == "ERROR":
                raise RuntimeError(
                    str(response["payload"].get("message") or "logout failed")
                )
        finally:
            self.username = None
            self._stop_pump()
            self.connection.shutdown()
            self._abort_transfers("logged out")

    def _require_authentication(self) -> None:
        if not self.authenticated:
            raise AuthenticationError("log in before using messaging")

    def _start_pump(self) -> None:
        self._stop_pump()
        self._pump_error = None
        self._inbox = queue.Queue()
        self._pump_stop = threading.Event()
        self._pump_thread = threading.Thread(
            target=self._pump,
            args=(self._pump_stop,),
            name="ccp-client-dispatch",
            daemon=True,
        )
        self._pump_thread.start()

    def _stop_pump(self) -> None:
        self._pump_stop.set()
        thread = self._pump_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)
        self._pump_thread = None

    def _pump(self, stop: threading.Event) -> None:
        """Route file-transfer messages to their transfers and queue everything else."""
        while not stop.is_set():
            try:
                try:
                    message = self.connection.receive_message(PUMP_INTERVAL)
                except TimeoutError:
                    message = None
                if message is not None and not self._dispatch(message):
                    self._inbox.put(message)
                self._fail_broken_sources()
                self._advance_receives()
            except (ConnectionError, OSError, MalformedPacketError) as exc:
                if not stop.is_set():
                    self._pump_error = exc
                    self._abort_transfers("connection lost")
                return

    def _find_transfer(self, offer_id: str | None = None, file_id: str | None = None):
        with self._lock:
            for transfer in self._transfers:
                if (offer_id is not None and transfer.record.metadata.file_id == offer_id) or (
                    file_id is not None and transfer.file_id == file_id
                ):
                    return transfer
        return None

    def _dispatch(self, message: dict) -> bool:
        """Handle a message that belongs to a file transfer; return True if consumed."""
        message_type = message["type"]
        payload = message["payload"]

        if message_type == "FILE_INCOMING":
            self._on_file_incoming(payload)
            return True

        if message_type == "ERROR":
            transfer = self._find_transfer(offer_id=message["id"])
            if transfer is None:
                return False
            detail = f"{payload.get('code')}: {payload.get('message')}"
            state = (
                TransferState.REJECTED
                if transfer.record.state is TransferState.OFFERED
                else TransferState.FAILED
            )
            self._set_state(transfer, state, detail)
            return True

        if message_type == "FILE_ACCEPT":
            transfer = self._find_transfer(offer_id=message["id"])
            file_id = payload.get("file_id")
            if not isinstance(transfer, OutgoingTransfer):
                return False
            if payload.get("accepted") is not True:
                self._set_state(
                    transfer,
                    TransferState.REJECTED,
                    str(payload.get("error") or "rejected by the receiver"),
                )
            elif isinstance(file_id, str) and file_id:
                with self._lock:
                    transfer.file_id = file_id
            else:
                self._fail_and_cancel(transfer, "server sent an invalid file_id")
            return True

        if message_type not in ("FILE_READY", "FILE_COMPLETE", "FILE_CANCEL"):
            return False
        file_id = payload.get("file_id")
        transfer = self._find_transfer(file_id=file_id) if isinstance(file_id, str) else None
        if transfer is None:
            return False

        if message_type == "FILE_READY":
            if isinstance(transfer, OutgoingTransfer):
                self._start_sending(transfer, payload)
            else:
                self._start_receiving(transfer, payload)
        elif message_type == "FILE_COMPLETE":
            if isinstance(transfer, OutgoingTransfer):
                self._complete(transfer, payload)
        else:
            self._set_state(
                transfer,
                TransferState.CANCELLED,
                str(payload.get("reason") or "cancelled by the server"),
            )
        return True

    def _on_file_incoming(self, payload: dict) -> None:
        file_id = payload.get("file_id")
        if not isinstance(file_id, str) or not SAFE_FILE_ID.fullmatch(file_id):
            log.warning("ignoring FILE_INCOMING with an invalid file_id")
            return
        if self._find_transfer(file_id=file_id) is not None:
            return

        sender = payload.get("sender")
        filename = payload.get("filename")
        size_bytes = payload.get("size_bytes")
        sha256 = payload.get("sha256")
        try:
            if (
                not isinstance(sender, str)
                or not isinstance(filename, str)
                or filename in ("", ".", "..")
                or type(size_bytes) is not int
                or not isinstance(sha256, str)
            ):
                raise ValueError("invalid FILE_INCOMING fields")
            metadata = TransferMetadata(
                file_id=file_id,
                sender=sender,
                target=self.username or "",
                filename=filename,
                size_bytes=size_bytes,
                sha256=sha256,
            )
        except ValueError as exc:
            log.warning("rejecting invalid file offer %s: %s", file_id, exc)
            self.connection.send_message(
                CONTROL_STREAM, "FILE_RESPONSE",
                {"file_id": file_id, "accepted": False}, request_id=file_id,
            )
            return

        transfer = IncomingTransfer(TransferRecord(metadata))
        with self._lock:
            self._transfers.append(transfer)
        self._notify(transfer)

    def _start_receiving(self, transfer: IncomingTransfer, payload: dict) -> None:
        if transfer.record.state is not TransferState.OFFERED or not transfer.responded:
            return
        stream_id = payload.get("stream_id")
        chunk_size = payload.get("chunk_size")
        if (
            type(stream_id) is not int
            or stream_id < FIRST_FILE_STREAM
            or type(chunk_size) is not int
            or not 0 < chunk_size <= MAX_DATA_BYTES
        ):
            self._fail_and_cancel(transfer, "server sent an invalid FILE_READY")
            return

        record = transfer.record
        try:
            receiver = FileReceiver(
                record.metadata, self.download_dir / PARTIAL_DIR, chunk_size
            )
        except OSError as exc:
            self._fail_and_cancel(transfer, f"cannot create the download file: {exc}")
            return
        transfer.receiver = receiver
        record.receiver_stream_id = stream_id
        record.chunk_size = chunk_size
        record.temp_path = receiver.temp_path
        if not self._set_state(transfer, TransferState.READY):
            receiver.abort()
            return
        try:
            self.connection.open_file_stream(stream_id, transfer.receive_data)
        except ValueError as exc:
            self._fail_and_cancel(transfer, f"cannot receive on stream {stream_id}: {exc}")

    def _advance_receives(self) -> None:
        for transfer in self.transfers():
            if not isinstance(transfer, IncomingTransfer):
                continue
            receiver = transfer.receiver
            if receiver is None or _finished(transfer):
                continue
            if transfer.record.state is TransferState.READY and (
                receiver.bytes_received or receiver.fin_received
            ):
                self._set_state(transfer, TransferState.TRANSFERRING)
            if receiver.is_complete and transfer.record.state is TransferState.TRANSFERRING:
                if not self._set_state(transfer, TransferState.VERIFYING):
                    continue
                stream_id = transfer.record.receiver_stream_id
                if stream_id is not None:
                    self.connection.close_file_stream(stream_id)
                try:
                    transfer.saved_path = receiver.finish(self.download_dir)
                    error = None
                except (ValueError, OSError) as exc:
                    error = str(exc)
                success = error is None
                self._set_state(
                    transfer, TransferState.COMPLETED if success else TransferState.FAILED,
                    error,
                )
                self.connection.send_message(
                    CONTROL_STREAM, "FILE_COMPLETE",
                    {"file_id": transfer.file_id, "success": success,
                     "sha256": transfer.record.metadata.sha256 if success else ""},
                )

    def _start_sending(self, transfer: OutgoingTransfer, payload: dict) -> None:
        stream_id = payload.get("stream_id")
        chunk_size = payload.get("chunk_size")
        if (
            type(stream_id) is not int
            or stream_id < FIRST_FILE_STREAM
            or type(chunk_size) is not int
            or not 0 < chunk_size <= MAX_DATA_BYTES
        ):
            self._fail_and_cancel(transfer, "server sent an invalid FILE_READY")
            return
        if not self._set_state(transfer, TransferState.READY):
            return
        transfer.record.sender_stream_id = stream_id
        transfer.record.chunk_size = chunk_size
        try:
            self.connection.attach_file_stream(stream_id, self._segments(transfer))
        except (ValueError, OSError) as exc:
            self._fail_and_cancel(transfer, f"cannot start sending: {exc}")
            return
        self._set_state(transfer, TransferState.TRANSFERRING)

    @staticmethod
    def _segments(transfer: OutgoingTransfer):
        # A changed or unreadable file must end the source, not kill the connection.
        try:
            yield from iter_segments(
                transfer.path,
                transfer.record.metadata.size_bytes,
                transfer.record.chunk_size,
            )
        except (OSError, ValueError) as exc:
            transfer.record.error = str(exc)

    def _fail_broken_sources(self) -> None:
        for transfer in self.transfers():
            if transfer.record.error and not _finished(transfer):
                self._fail_and_cancel(transfer, transfer.record.error)

    def _complete(self, transfer: OutgoingTransfer, payload: dict) -> None:
        if transfer.record.state is not TransferState.TRANSFERRING:
            return
        self._set_state(transfer, TransferState.VERIFYING)
        if payload.get("success") is not True:
            self._set_state(transfer, TransferState.FAILED, "receiver reported failure")
        elif str(payload.get("sha256", "")).lower() != transfer.record.metadata.sha256.lower():
            self._set_state(transfer, TransferState.FAILED, "SHA-256 mismatch")
        else:
            self._set_state(transfer, TransferState.COMPLETED)

    def _fail_and_cancel(
        self, transfer: OutgoingTransfer | IncomingTransfer, reason: str
    ) -> None:
        if transfer.file_id is not None and not _finished(transfer):
            try:
                self.connection.send_message(
                    CONTROL_STREAM,
                    "FILE_CANCEL",
                    {"file_id": transfer.file_id, "reason": reason},
                )
            except (ConnectionError, OSError, MalformedPacketError):
                pass
        self._set_state(transfer, TransferState.FAILED, reason)

    def _abort_transfers(self, reason: str) -> None:
        for transfer in self.transfers():
            self._set_state(transfer, TransferState.FAILED, reason)

    def _set_state(
        self,
        transfer: OutgoingTransfer | IncomingTransfer,
        state: TransferState,
        error: str | None = None,
    ) -> bool:
        with self._lock:
            if _finished(transfer):
                return False
            try:
                transfer.record.transition(state, error)
            except ValueError:
                return False
        if state in TERMINAL_STATES:
            self._release(transfer, state)
        self._notify(transfer)
        return True

    def _release(self, transfer: OutgoingTransfer | IncomingTransfer, state: TransferState) -> None:
        """Free the stream and partial file of a transfer that reached a final state."""
        if isinstance(transfer, OutgoingTransfer):
            stream_id = transfer.record.sender_stream_id
            if stream_id and state is not TransferState.COMPLETED:
                self.connection.detach_file_stream(stream_id)
            return
        stream_id = transfer.record.receiver_stream_id
        if stream_id:
            self.connection.close_file_stream(stream_id)
        if transfer.receiver is not None and state is not TransferState.COMPLETED:
            transfer.receiver.abort()

    def _notify(self, transfer: OutgoingTransfer | IncomingTransfer) -> None:
        listener = self.transfer_listener
        if listener is not None:
            try:
                listener(transfer)
            except Exception:
                log.exception("transfer listener failed")

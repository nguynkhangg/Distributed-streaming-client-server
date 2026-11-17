"""CCP UDP Server: connection handshake, session lifecycle, authentication,
online presence, and broadcast/private message routing.
"""
from __future__ import annotations

import argparse
import itertools
import json
import logging
import os
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum

from .auth import UsersFileError, UserStore
from .session_manager import (
    KEY_SIZE,
    MAX_AUTH_FAILURES,
    NONCE_SIZE,
    Address,
    BindResult,
    ClientSession,
    CloseReason,
    RemoveResult,
    SessionLimitError,
    SessionManager,
    SessionState,
)
from ..security.encryption import (
    DIR_C2S,
    DIR_S2C,
    GCM_TAG_SIZE,
    CryptoError,
    derive_keys,
    open as gcm_open,
    seal,
)

log = logging.getLogger("ccp.server")

MAGIC = 0xA5C3
VERSION = 1
HEADER_FORMAT = "!HBBBBIIH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)             # 16 bytes
STREAM_HEADER_FORMAT = "!IQ"                             # stream_id (4B) + offset (8B)
STREAM_HEADER_SIZE = struct.calcsize(STREAM_HEADER_FORMAT)  # 12 bytes
MAX_DATAGRAM = 1200
MAX_PAYLOAD = MAX_DATAGRAM - HEADER_SIZE                 # 1184 bytes

FLAG_FIN = 0x01
FLAG_ENC = 0x02

WORKERS = 16
QUEUE_PER_WORKER = 64

class PacketType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    DATA = 0x03
    AUTH = 0x03
    ACK = 0x04
    AUTH_ACK = 0x04
    PING = 0x05
    LOGOUT = 0x05
    PONG = 0x06
    LOGOUT_ACK = 0x06
    CLOSE = 0x07
    HEARTBEAT = 0x08
    MSG_OFFER = 0x0A
    MSG = 0x0B
    MSG_ACK = 0x0C
    FILE_OFFER = 0x14
    FILE_ACK = 0x15
    FILE_DATA = 0x16
    FILE_FIN = 0x17
    ONLINE_LIST = 0x20
    ERROR = 0xFF


class PacketError(ValueError):
    """Raised when an incoming UDP datagram violates the 16-byte CCP header rules."""


@dataclass(frozen=True)
class PacketHeader:
    packet_type: PacketType
    connection_id: int
    packet_number: int
    payload_length: int
    flags: int = 0
    version: int = VERSION
    magic: int = MAGIC
    reserved: int = 0


def pack_packet(
    packet_type: PacketType,
    connection_id: int,
    packet_number: int,
    payload: bytes = b"",
    flags: int = 0,
) -> bytes:
    """Serialize a CCP header and payload into a single UDP datagram."""
    if len(payload) > MAX_PAYLOAD:
        raise PacketError(f"payload too large: {len(payload)}")
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        int(packet_type),
        flags,
        0,
        connection_id,
        packet_number,
        len(payload),
    )
    return header + payload


def unpack_packet(data: bytes) -> tuple[PacketHeader, bytes]:
    """Parse and validate a raw UDP datagram into (PacketHeader, payload)."""
    if len(data) < HEADER_SIZE:
        raise PacketError("datagram shorter than header")
    if len(data) > MAX_DATAGRAM:
        raise PacketError("datagram exceeds max size")

    magic, version, raw_type, flags, reserved, conn_id, pkt_num, payload_len = (
        struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    )
    if magic != MAGIC:
        raise PacketError("bad magic")
    if version != VERSION:
        raise PacketError("unsupported version")
    try:
        packet_type = PacketType(raw_type)
    except ValueError:
        raise PacketError("unknown packet type") from None
    if payload_len != len(data) - HEADER_SIZE:
        raise PacketError("payload_length mismatch")

    header = PacketHeader(
        packet_type=packet_type,
        connection_id=conn_id,
        packet_number=pkt_num,
        payload_length=payload_len,
        flags=flags,
        version=version,
        magic=magic,
        reserved=reserved,
    )
    return header, data[HEADER_SIZE:]


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9000
RECV_BUFFER = 65535
SOCKET_TIMEOUT = 1.0
SWEEP_INTERVAL = 1.0

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024
MAX_TEXT_CHARS = 4096
BROADCAST_TARGET = "*"
DEFAULT_USERS_FILE = "data/users.json"

# Stream assignment per server message type (stream 0: control, stream 1: chat)
STREAM_OF = {
    "AUTH_ACK": 0,
    "USER_LIST": 0,
    "PRESENCE": 0,
    "LOGOUT_ACK": 0,
    "ERROR": 0,
    "MSG_DELIVER": 1,
}


class ErrorCode:
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNKNOWN_MESSAGE_TYPE = "UNKNOWN_MESSAGE_TYPE"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    AUTH_FAILED = "AUTH_FAILED"
    ALREADY_LOGGED_IN = "ALREADY_LOGGED_IN"
    ALREADY_AUTHENTICATED = "ALREADY_AUTHENTICATED"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    USER_OFFLINE = "USER_OFFLINE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class CcpServer:
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        users: UserStore | None = None,
    ) -> None:
        self._sessions = SessionManager()
        self._users = users if users is not None else UserStore()
        self._presence_lock = threading.Lock()
        self._event_ids = itertools.count(1)
        self._message_handlers = {
            "AUTH": self._handle_auth,
            "USER_LIST_REQ": self._handle_user_list_req,
            "MSG": self._handle_msg,
            "LOGOUT": self._handle_logout,
        }
        self._stop = threading.Event()
        self._queues = [queue.Queue(QUEUE_PER_WORKER) for _ in range(WORKERS)]
        self._workers = [threading.Thread(target=self._worker, args=(q,), daemon=True, name=f"ccp-worker-{i}") for i, q in enumerate(self._queues)]
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.bind((host, port))
        except OSError:
            self._sock.close()
            raise
        self._sock.settimeout(SOCKET_TIMEOUT)
        self._handlers = {
            PacketType.DATA: self._on_data,
            PacketType.ACK: self._on_ack,
            PacketType.PING: self._on_ping,
            PacketType.PONG: self._on_pong,
            PacketType.CLOSE: self._on_close,
            PacketType.HEARTBEAT: self._on_ping,
            PacketType.MSG_OFFER: self._on_data,
            PacketType.MSG: self._on_data,
            PacketType.ONLINE_LIST: self._on_data,
        }
        log.info("listening on udp://%s:%d", *self.address)

    @property
    def address(self) -> Address:
        return self._sock.getsockname()[:2]

    # ---- server lifecycle & background sweeper ------------------------

    def serve_forever(self) -> None:
        threading.Thread(target=self._sweep_loop, name="sweeper", daemon=True).start()
        for worker in self._workers:
            worker.start()
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(RECV_BUFFER)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                log.error("recvfrom failed: %s", exc)
                time.sleep(0.1)
                continue
            # Same connection → same worker. HELLO (cid 0) shards by address.
            cid = int.from_bytes(data[6:10], "big") if len(data) >= 10 else 0
            shard = cid % WORKERS if cid else hash(addr) % WORKERS
            try:
                self._queues[shard].put_nowait((data, addr))
            except queue.Full:
                log.warning("worker %d busy, dropping datagram from %s", shard, addr)

    def _worker(self, inbox: queue.Queue) -> None:
        while not self._stop.is_set():
            try:
                data, addr = inbox.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle_datagram(data, addr)
            except Exception:
                log.exception("error while handling datagram from %s", addr)

    def shutdown(self) -> None:
        """Stop workers, notify active sessions with CLOSE, and release socket."""
        self._stop.set()
        for result in self._sessions.remove_all():
            self._send_close(result.session, CloseReason.SERVER_SHUTDOWN)
        self._sock.close()
        for worker in self._workers:
            if worker.is_alive():
                worker.join(timeout=1)

    def _sweep_loop(self) -> None:
        while not self._stop.wait(SWEEP_INTERVAL):
            try:
                self._sweep_once()
            except Exception:
                log.exception("sweeper error")

    def _sweep_once(self) -> None:
        now = time.monotonic()
        for session in self._sessions.find_expired(now):
            self._close_session(session, CloseReason.TIMEOUT, "timeout")
        for session in self._sessions.find_idle(now):
            self._send(session, PacketType.PING)

    # ---- packet-layer dispatch ----------------------------------------

    def _handle_datagram(self, data: bytes, addr: Address) -> None:
        try:
            header, payload = unpack_packet(data)
        except PacketError as exc:
            log.debug("drop datagram from %s: %s", addr, exc)
            return
        if header.packet_type is PacketType.HELLO:
            self._on_hello(header, payload, addr)
            return

        session = self._sessions.lookup(header.connection_id, addr)
        if session is None:
            log.debug(
                "drop %s from %s: unknown connection_id/address",
                header.packet_type.name,
                addr,
            )
            return
        # Post-HELLO: require ENC.
        if not (header.flags & FLAG_ENC) or session.key_c2s is None:
            log.debug(
                "drop %s from %s: missing ENC or keys",
                header.packet_type.name,
                addr,
            )
            return
        try:
            payload = gcm_open(
                session.key_c2s,
                header.packet_number,
                data[:HEADER_SIZE],
                payload,
                direction=DIR_C2S,
            )
        except CryptoError:
            log.debug(
                "drop %s from %s: GCM auth failed",
                header.packet_type.name,
                addr,
            )
            return
        session.use_encryption = True

        handler = self._handlers.get(header.packet_type)
        if handler is None:
            log.debug(
                "drop %s from %s: not valid client-to-server",
                header.packet_type.name,
                addr,
            )
            return
        session.touch()
        handler(session, payload)

    def _on_hello(self, header: PacketHeader, payload: bytes, addr: Address) -> None:
        if header.connection_id != 0:
            log.debug("drop HELLO from %s: connection_id must be 0", addr)
            return
        if len(payload) != KEY_SIZE + NONCE_SIZE:
            log.debug(
                "drop HELLO from %s: payload must be %d bytes",
                addr,
                KEY_SIZE + NONCE_SIZE,
            )
            return
        client_key, client_nonce = payload[:KEY_SIZE], payload[KEY_SIZE:]

        try:
            result = self._sessions.get_or_create_session(addr, client_key, client_nonce)
        except SessionLimitError:
            log.warning("session table full, drop HELLO from %s", addr)
            return

        if result.replaced is not None:
            self._handle_removed(result.replaced, "client restarted")

        session = result.session
        if result.is_new:
            if session.server_private_key is None:
                log.warning("drop HELLO from %s: missing server private key", addr)
                return
            try:
                session.key_c2s, session.key_s2c = derive_keys(
                    session.server_private_key,
                    session.client_public_key,
                    session.client_nonce,
                    session.server_nonce,
                )
            except CryptoError as exc:
                log.debug("drop HELLO from %s: %s", addr, exc)
                return
            session.use_encryption = True
            log.info("new session %08x for %s:%d", session.connection_id, *addr)
        else:
            log.debug("HELLO retransmission from %s: resend HELLO_ACK", addr)

        self._send(
            session,
            PacketType.HELLO_ACK,
            session.server_public_key + session.server_nonce,
        )

    def _on_ping(self, session: ClientSession, payload: bytes) -> None:
        if payload and payload.strip():
            self._dispatch_control_json(session, payload)
            return
        self._send(session, PacketType.PONG)

    def _on_pong(self, session: ClientSession, payload: bytes) -> None:
        pass

    def _on_close(self, session: ClientSession, payload: bytes) -> None:
        result = self._sessions.remove_session(session.connection_id)
        if result is not None:
            self._handle_removed(result, "client CLOSE")

    def _on_data(self, session: ClientSession, payload: bytes) -> None:
        if not payload:
            return
        # Support direct unframed JSON as well as stream-framed DATA segments
        if payload.lstrip().startswith(b"{"):
            self._dispatch_control_json(session, payload)
            return
        if len(payload) < STREAM_HEADER_SIZE:
            log.debug("drop short DATA segment (%d bytes) from %s", len(payload), session.address)
            return
        stream_id, _offset = struct.unpack(STREAM_HEADER_FORMAT, payload[:STREAM_HEADER_SIZE])
        stream_body = payload[STREAM_HEADER_SIZE:]
        if stream_id in (0, 1):
            for frame_bytes in self._extract_stream_frames(stream_body):
                self._dispatch_control_json(session, frame_bytes)

    @staticmethod
    def _extract_stream_frames(stream_body: bytes) -> list[bytes]:
        if stream_body.lstrip().startswith(b"{"):
            return [stream_body.lstrip()]
        frames: list[bytes] = []
        cursor = 0
        total = len(stream_body)
        while cursor + 4 <= total:
            (frame_len,) = struct.unpack("!I", stream_body[cursor : cursor + 4])
            cursor += 4
            if frame_len == 0 or cursor + frame_len > total:
                break
            frames.append(stream_body[cursor : cursor + frame_len])
            cursor += frame_len
        return frames

    def _on_ack(self, session: ClientSession, payload: bytes) -> None:
        log.debug("ACK from %s (%d bytes)", session.address, len(payload))

    # ---- session removal & presence helpers ---------------------------

    def _handle_removed(self, result: RemoveResult, why: str) -> None:
        session = result.session
        log.info("session %08x (%s:%d) closed: %s", session.connection_id, *session.address, why)
        if result.went_offline:
            with self._presence_lock:
                self._fan_out(
                    self._sessions.authenticated_sessions(),
                    "PRESENCE",
                    {"username": session.username, "status": "offline"},
                )

    def _close_session(self, session: ClientSession, reason: CloseReason, why: str) -> None:
        result = self._sessions.remove_session(session.connection_id)
        if result is None:
            return
        self._send_close(session, reason)
        self._handle_removed(result, why)

    # ---- control & chat message layer ---------------------------------

    def _dispatch_control_json(self, session: ClientSession, raw: bytes | str) -> None:
        """Validate envelope and route control/chat JSON frame to its handler."""
        if len(raw) > MAX_MESSAGE_BYTES:
            log.debug("drop oversize frame from %s", session.address)
            return
        try:
            message = json.loads(raw)
        except (ValueError, RecursionError):
            log.debug("drop malformed JSON from %s", session.address)
            return
        if not isinstance(message, dict) or not isinstance(message.get("type"), str):
            log.debug("drop message without a string type from %s", session.address)
            return

        msg_type = message["type"]
        req_id = message.get("id") if isinstance(message.get("id"), str) else None
        # Log only the message type, never the body (which holds passwords in AUTH)
        log.debug("message %s from %s", msg_type[:32], session.address)

        if message.get("version") != PROTOCOL_VERSION:
            self._send_error(
                session,
                ErrorCode.UNSUPPORTED_VERSION,
                "unsupported protocol version",
                msg_type,
                req_id,
            )
            return

        if session.state is not SessionState.AUTHENTICATED and msg_type != "AUTH":
            self._send_error(
                session,
                ErrorCode.NOT_AUTHENTICATED,
                "authentication required",
                msg_type,
                req_id,
            )
            return

        body = message.get("payload")
        if req_id is None or not isinstance(body, dict):
            self._send_error(
                session,
                ErrorCode.INVALID_PAYLOAD,
                "id must be a string and payload an object",
                msg_type,
                req_id,
            )
            return

        handler = self._message_handlers.get(msg_type)
        if handler is None:
            self._send_error(
                session,
                ErrorCode.UNKNOWN_MESSAGE_TYPE,
                "unknown message type",
                msg_type,
                req_id,
            )
            return

        try:
            handler(session, body, req_id)
        except Exception:
            log.exception("handler for %s failed", msg_type[:32])
            self._send_error(
                session,
                ErrorCode.INTERNAL_ERROR,
                "internal server error",
                msg_type,
                req_id,
            )

    def _handle_auth(self, session: ClientSession, body: dict, req_id: str) -> None:
        if session.state is SessionState.AUTHENTICATED:
            self._send_error(
                session,
                ErrorCode.ALREADY_AUTHENTICATED,
                "already logged in",
                "AUTH",
                req_id,
            )
            return

        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            self._send_error(
                session,
                ErrorCode.INVALID_PAYLOAD,
                "username and password must be strings",
                "AUTH",
                req_id,
            )
            return

        if not self._users.verify_credentials(username, password):
            failures = self._sessions.record_auth_failure(session)
            self._send_message(
                session,
                "AUTH_ACK",
                {"success": False, "username": None, "error": ErrorCode.AUTH_FAILED},
                req_id,
            )
            if failures >= MAX_AUTH_FAILURES:
                self._close_session(
                    session,
                    CloseReason.PROTOCOL_ERROR,
                    "too many failed logins",
                )
            return

        outcome = self._sessions.bind_username(session, username)
        if outcome is BindResult.OK:
            self._send_message(
                session,
                "AUTH_ACK",
                {"success": True, "username": username, "error": None},
                req_id,
            )
            self._send_message(
                session,
                "USER_LIST",
                {"users": self._sessions.online_users()},
            )
            self._announce_online(session)
        elif outcome is BindResult.ALREADY_LOGGED_IN:
            self._send_message(
                session,
                "AUTH_ACK",
                {
                    "success": False,
                    "username": None,
                    "error": ErrorCode.ALREADY_LOGGED_IN,
                },
                req_id,
            )
        elif outcome is BindResult.ALREADY_AUTHENTICATED:
            self._send_error(
                session,
                ErrorCode.ALREADY_AUTHENTICATED,
                "already logged in",
                "AUTH",
                req_id,
            )
        else:
            log.debug("AUTH ignored: session %08x is no longer open", session.connection_id)

    def _handle_user_list_req(self, session: ClientSession, body: dict, req_id: str) -> None:
        self._send_message(
            session,
            "USER_LIST",
            {"users": self._sessions.online_users()},
            req_id,
        )

    def _handle_logout(self, session: ClientSession, body: dict, req_id: str) -> None:
        self._send_message(session, "LOGOUT_ACK", {"success": True}, req_id)
        self._close_session(session, CloseReason.NORMAL, "logout")

    def _handle_msg(self, session: ClientSession, body: dict, req_id: str) -> None:
        target = body.get("target")
        text = body.get("text")
        if (
            not isinstance(target, str)
            or not target
            or not isinstance(text, str)
            or not text.strip()
            or len(text) > MAX_TEXT_CHARS
            or not _is_encodable(text)
        ):
            self._send_error(
                session,
                ErrorCode.INVALID_PAYLOAD,
                f"target and text are required (text up to {MAX_TEXT_CHARS} characters)",
                "MSG",
                req_id,
            )
            return

        deliver = {
            "sender": session.username,
            "target": target,
            "text": text,
            "timestamp": (
                datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            ),
        }
        if target == BROADCAST_TARGET:
            others = [
                peer
                for peer in self._sessions.authenticated_sessions()
                if peer is not session
            ]
            self._fan_out(others, "MSG_DELIVER", deliver)
            return

        peer = self._sessions.get_by_username(target)
        if peer is None:
            code = (
                ErrorCode.USER_OFFLINE
                if self._users.user_exists(target)
                else ErrorCode.USER_NOT_FOUND
            )
            self._send_error(session, code, "recipient is not available", "MSG", req_id)
            return
        self._send_message(peer, "MSG_DELIVER", deliver)

    # ---- outbound framing & packet transmission -----------------------

    def _announce_online(self, session: ClientSession) -> None:
        with self._presence_lock:
            if session.state is not SessionState.AUTHENTICATED:
                return
            peers = [
                peer
                for peer in self._sessions.authenticated_sessions()
                if peer is not session
            ]
            self._fan_out(
                peers,
                "PRESENCE",
                {"username": session.username, "status": "online"},
            )

    def _fan_out(self, recipients: list[ClientSession], msg_type: str, payload: dict) -> None:
        for peer in recipients:
            try:
                self._send_message(peer, msg_type, payload)
            except Exception:
                log.exception("could not deliver %s to %s", msg_type, peer.address)

    def _send_error(
        self,
        session: ClientSession,
        code: str,
        message: str,
        related_type: str,
        req_id: str | None,
    ) -> None:
        self._send_message(
            session,
            "ERROR",
            {"code": code, "message": message, "related_type": related_type},
            req_id,
        )

    def _send_message(
        self,
        session: ClientSession,
        msg_type: str,
        payload: dict,
        req_id: str | None = None,
    ) -> None:
        message = {
            "type": msg_type,
            "payload": payload,
            "id": req_id if req_id is not None else f"srv-{next(self._event_ids)}",
            "version": PROTOCOL_VERSION,
        }
        body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_frame(session, STREAM_OF[msg_type], struct.pack("!I", len(body)) + body)

    def _send_frame(self, session: ClientSession, stream_id: int, frame: bytes) -> None:
        offset = session.stream_offsets.get(stream_id, 0)
        session.stream_offsets[stream_id] = offset + len(frame)
        stream_header = struct.pack(STREAM_HEADER_FORMAT, stream_id, offset)
        self._send(session, PacketType.DATA, stream_header + frame)

    def _send(
        self,
        session: ClientSession,
        packet_type: PacketType,
        payload: bytes = b"",
    ) -> None:
        pn = session.allocate_packet_number()
        use_enc = (
            session.key_s2c is not None
            and packet_type not in (PacketType.HELLO, PacketType.HELLO_ACK)
        )
        if use_enc:
            sealed_len = len(payload) + GCM_TAG_SIZE
            header16 = struct.pack(
                HEADER_FORMAT,
                MAGIC,
                VERSION,
                int(packet_type),
                FLAG_ENC,
                0,
                session.connection_id,
                pn,
                sealed_len,
            )
            body = seal(session.key_s2c, pn, header16, payload, direction=DIR_S2C)
            raw = header16 + body
        else:
            raw = pack_packet(packet_type, session.connection_id, pn, payload, 0)
        try:
            self._sock.sendto(raw, session.address)
        except OSError as exc:
            log.warning("send %s to %s failed: %s", packet_type.name, session.address, exc)

    def _send_close(self, session: ClientSession, reason: CloseReason) -> None:
        self._send(session, PacketType.CLOSE, bytes([reason]))


def _is_encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CCP collaboration server (UDP)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--users-file",
        default=DEFAULT_USERS_FILE,
        help="JSON file with salted password hashes (default: %(default)s)",
    )
    parser.add_argument(
        "--demo-password",
        default=os.environ.get("CCP_DEMO_PASSWORD"),
        help="create the demo accounts with this password if they are missing",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        users = UserStore(args.users_file)
        if args.demo_password:
            added = users.seed_demo_users(args.demo_password)
            if added:
                log.info("created demo accounts: %s", ", ".join(added))
    except (UsersFileError, ValueError, OSError) as exc:
        log.error("cannot prepare the user store: %s", exc)
        return 1
    try:
        server = CcpServer(args.host, args.port, users)
    except OSError as exc:
        log.error("cannot bind %s:%d: %s", args.host, args.port, exc)
        return 1
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

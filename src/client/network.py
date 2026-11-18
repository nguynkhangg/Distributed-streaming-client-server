"""UDP CCP client: ECDH HELLO, ENC, idle heartbeats, framed JSON."""
from __future__ import annotations

import itertools
import json
import logging
import secrets
import socket
import struct
import threading
import time
import uuid
from collections import deque
from enum import Enum

from ..common.constants import (
    MAGIC,
    VERSION,
    PacketType,
    PacketFlag,
    HEADER_FORMAT,
    MAX_DATAGRAM_SIZE,
    DATA_SEGMENT_SIZE,
    CloseReason,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT,
)
from ..common.exceptions import (HandshakeTimeoutError,MalformedPacketError,UnknownPacketTypeError)
from ..security.encryption import (DIR_C2S,DIR_S2C,GCM_TAG_SIZE,KEY_SIZE,CryptoError,derive_keys,generate_x25519_keypair,open as gcm_open,seal)

log = logging.getLogger("ccp.client.network")
HEADER = struct.Struct(HEADER_FORMAT)
HEADER_SIZE = HEADER.size
STREAM_HEADER = struct.Struct("!IQ")
STREAM_HEADER_SIZE = STREAM_HEADER.size
FRAME_HEADER = struct.Struct("!I")
PROTOCOL_VERSION = 1
NONCE_SIZE = 16
FLAG_ENC = PacketFlag.ENC


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    HELLO_SENT = "hello_sent"
    ESTABLISHED = "established"
    CLOSING = "closing"


class CcpClient:
    """CCP UDP: ECDH HELLO, ENC after real keys, inbox, idle PING/timeout."""

    def __init__(
        self,
        server_host: str = "127.0.0.1",
        server_port: int = 9000,
        receive_timeout: float = 1.0,
        hello_attempts: int = 3,
        hello_retry_interval: float = 1.0,
    ) -> None:
        if hello_attempts < 1:
            raise ValueError("hello_attempts must be at least 1")
        if receive_timeout <= 0 or hello_retry_interval < 0:
            raise ValueError("timeouts must be positive (retry interval may be zero)")

        self.server_address = (socket.gethostbyname(server_host), server_port)
        self.receive_timeout = receive_timeout
        self.hello_attempts = hello_attempts
        self.hello_retry_interval = hello_retry_interval

        self.state = ConnectionState.DISCONNECTED
        self.connection_id = 0
        self.server_public_key = b""
        self.server_nonce = b""
        self.key_c2s: bytes | None = None
        self.key_s2c: bytes | None = None
        self._private_key = b""
        self._client_public = b""
        self._enc_enabled = False
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._packet_numbers = itertools.count(1)
        self._lock = threading.RLock()
        self._stop_receive = threading.Event()
        self._pong_received = threading.Event()
        self._receiver_thread: threading.Thread | None = None
        self._messages: deque[dict] = deque()
        self._responses: deque[dict] = deque()
        self._pending_responses: dict[str, str] = {}
        self._messages_ready = threading.Condition()
        self._receiver_error: OSError | None = None
        self._stream_offsets = {0: 0, 1: 0}
        self._last_recv = self._last_send = time.monotonic()
        self.last_recv_pn = -1

    def clear_keys(self) -> None:
        self.key_c2s = self.key_s2c = None
        self._private_key = self._client_public = b""
        self._enc_enabled = False
        self.server_public_key = self.server_nonce = b""
        self.last_recv_pn = -1

    def _next_packet_number(self) -> int:
        n = next(self._packet_numbers)
        if n > 0xFFFFFFFF:
            raise OverflowError("CCP packet number space exhausted")
        return n

    def _encode_packet(
        self,
        packet_type: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: int | None = None,
        packet_number: int | None = None,
    ) -> bytes:
        cid = self.connection_id if connection_id is None else connection_id
        pn = self._next_packet_number() if packet_number is None else packet_number
        use_enc = (
            self._enc_enabled
            and self.key_c2s is not None
            and packet_type not in (PacketType.HELLO, PacketType.HELLO_ACK)
        )
        if use_enc:
            flags |= FLAG_ENC
            length = len(payload) + GCM_TAG_SIZE
            if HEADER_SIZE + length > MAX_DATAGRAM_SIZE:
                raise MalformedPacketError("CCP datagram is too large")
            header = HEADER.pack(
                MAGIC, VERSION, int(packet_type), flags, 0, cid, pn, length
            )
            return header + seal(self.key_c2s, pn, header, payload, direction=DIR_C2S)

        if HEADER_SIZE + len(payload) > MAX_DATAGRAM_SIZE:
            raise MalformedPacketError("CCP datagram is too large")
        header = HEADER.pack(
            MAGIC, VERSION, int(packet_type), flags, 0, cid, pn, len(payload)
        )
        return header + payload

    def build_packet(
        self,
        packet_type: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: int | None = None,
        packet_number: int | None = None,
    ) -> bytes:
        with self._lock:
            return self._encode_packet(
                packet_type, payload, flags, connection_id, packet_number
            )

    @staticmethod
    def parse_packet(data: bytes) -> tuple[PacketType, int, bytes, int, int]:
        if not (HEADER_SIZE <= len(data) <= MAX_DATAGRAM_SIZE):
            raise MalformedPacketError("bad datagram size")
        magic, version, raw_type, flags, _, cid, pn, length = HEADER.unpack(
            data[:HEADER_SIZE]
        )
        if magic != MAGIC or version != VERSION or length != len(data) - HEADER_SIZE:
            raise MalformedPacketError("bad CCP header")
        try:
            ptype = PacketType(raw_type)
        except ValueError as exc:
            raise UnknownPacketTypeError(f"unknown type 0x{raw_type:02x}") from exc
        return ptype, cid, data[HEADER_SIZE:], flags, pn

    def _send_packet(
        self,
        packet_type: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: int | None = None,
        packet_number: int | None = None,
    ) -> None:
        with self._lock:
            try:
                packet = self._encode_packet(
                    packet_type, payload, flags, connection_id, packet_number
                )
            except OverflowError:
                self.state = ConnectionState.DISCONNECTED
                raise
            self._socket.sendto(packet, self.server_address)
            self._last_send = time.monotonic()

    def _receive_packet(self, timeout: float):
        self._socket.settimeout(timeout)
        while True:
            data, address = self._socket.recvfrom(MAX_DATAGRAM_SIZE)
            if address != self.server_address:
                continue
            try:
                ptype, cid, payload, flags, pn = self.parse_packet(data)
            except (MalformedPacketError, UnknownPacketTypeError) as exc:
                log.debug("discarding malformed server datagram: %s", exc)
                continue

            if flags & FLAG_ENC:
                if self.key_s2c is None:
                    continue
                try:
                    payload = gcm_open(
                        self.key_s2c, pn, data[:HEADER_SIZE], payload, direction=DIR_S2C
                    )
                except CryptoError:
                    continue
            elif self._enc_enabled and ptype != PacketType.HELLO_ACK:
                continue

            if ptype != PacketType.HELLO_ACK:
                if pn <= self.last_recv_pn:
                    continue
                self.last_recv_pn = pn
            return ptype, cid, payload, flags, pn

    def connect(self) -> int:
        if self.state not in (ConnectionState.DISCONNECTED, ConnectionState.CLOSING):
            raise RuntimeError(f"cannot connect while state is {self.state.value}")

        self._stop_receive.clear()
        self._receiver_error = None
        self.connection_id = 0
        self._stream_offsets = {0: 0, 1: 0}
        self.clear_keys()
        self._private_key, self._client_public = generate_x25519_keypair()
        client_nonce = secrets.token_bytes(NONCE_SIZE)
        hello = self._client_public + client_nonce
        self.state = ConnectionState.HELLO_SENT

        for attempt in range(self.hello_attempts):
            try:
                self._send_packet(
                    PacketType.HELLO, hello, connection_id=0, packet_number=0
                )
            except OSError:
                self.clear_keys()
                self.state = ConnectionState.DISCONNECTED
                raise

            try:
                ptype, cid, payload, _flags, _pn = self._receive_packet(
                    self.receive_timeout
                )
            except (socket.timeout, TimeoutError):
                if attempt + 1 < self.hello_attempts:
                    time.sleep(self.hello_retry_interval)
                    continue
                self.clear_keys()
                self.state = ConnectionState.DISCONNECTED
                raise HandshakeTimeoutError(
                    f"server did not reply to HELLO after {self.hello_attempts} attempts"
                )

            if ptype != PacketType.HELLO_ACK:
                continue
            if cid == 0 or len(payload) != KEY_SIZE + NONCE_SIZE:
                self.clear_keys()
                self.state = ConnectionState.DISCONNECTED
                raise MalformedPacketError("invalid HELLO_ACK from server")

            self.server_public_key = payload[:KEY_SIZE]
            self.server_nonce = payload[KEY_SIZE:]
            try:
                self.key_c2s, self.key_s2c = derive_keys(
                    self._private_key,
                    self.server_public_key,
                    client_nonce,
                    self.server_nonce,
                )
            except CryptoError as exc:
                self.clear_keys()
                self.state = ConnectionState.DISCONNECTED
                raise MalformedPacketError(
                    f"failed to derive session keys: {exc}"
                ) from exc
            self._enc_enabled = True

            self.connection_id = cid
            self.state = ConnectionState.ESTABLISHED
            now = time.monotonic()
            self._last_recv = self._last_send = now
            self._receiver_thread = threading.Thread(
                target=self._receive_loop,
                name=f"ccp-client-recv-{cid:08x}",
                daemon=True,
            )
            self._receiver_thread.start()
            return cid

        self.clear_keys()
        self.state = ConnectionState.DISCONNECTED
        raise HandshakeTimeoutError("failed to establish CCP connection")

    def _on_tick(self) -> bool:
        now = time.monotonic()
        if now - self._last_recv > HEARTBEAT_TIMEOUT:
            try:
                self._send_packet(PacketType.CLOSE, bytes([int(CloseReason.TIMEOUT)]))
            except OSError:
                pass
            self.state = ConnectionState.DISCONNECTED
            with self._messages_ready:
                self._messages_ready.notify_all()
            return False
        if (
            self.state is ConnectionState.ESTABLISHED
            and now - self._last_send > HEARTBEAT_INTERVAL
        ):
            try:
                self._send_packet(PacketType.PING)
            except OSError:
                self.state = ConnectionState.DISCONNECTED
                with self._messages_ready:
                    self._messages_ready.notify_all()
                return False
        return True

    def _receive_loop(self) -> None:
        while not self._stop_receive.is_set():
            try:
                ptype, cid, payload, _flags, _pn = self._receive_packet(0.25)
            except (socket.timeout, TimeoutError):
                if not self._on_tick():
                    return
                continue
            except OSError as exc:
                if not self._stop_receive.is_set():
                    log.info("link down: socket error")
                    self._receiver_error = exc
                    self.state = ConnectionState.DISCONNECTED
                    with self._messages_ready:
                        self._messages_ready.notify_all()
                return

            if cid != self.connection_id:
                continue
            self._last_recv = time.monotonic()
            if ptype == PacketType.PING:
                try:
                    self._send_packet(PacketType.PONG)
                except OSError as exc:
                    log.warning("could not answer server PING: %s", exc)
            elif ptype == PacketType.PONG:
                self._pong_received.set()
            elif ptype == PacketType.CLOSE:
                self.state = ConnectionState.DISCONNECTED
                with self._messages_ready:
                    self._messages_ready.notify_all()
                return
            elif ptype == PacketType.DATA:
                self._receive_data(payload)

    def _receive_data(self, payload: bytes) -> None:
        if len(payload) < STREAM_HEADER_SIZE + FRAME_HEADER.size:
            return
        stream_data = memoryview(payload)[STREAM_HEADER_SIZE:]
        cursor = 0
        while cursor + FRAME_HEADER.size <= len(stream_data):
            (frame_len,) = FRAME_HEADER.unpack(
                stream_data[cursor : cursor + FRAME_HEADER.size]
            )
            cursor += FRAME_HEADER.size
            if frame_len == 0 or cursor + frame_len > len(stream_data):
                return
            frame = bytes(stream_data[cursor : cursor + frame_len])
            cursor += frame_len
            try:
                message = json.loads(frame.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                not isinstance(message, dict)
                or not isinstance(message.get("type"), str)
                or not isinstance(message.get("payload"), dict)
                or not isinstance(message.get("id"), str)
                or message.get("version") != PROTOCOL_VERSION
            ):
                continue
            with self._messages_ready:
                rid = message["id"]
                expected = self._pending_responses.get(rid)
                if message["type"] == expected or (
                    message["type"] == "ERROR" and rid in self._pending_responses
                ):
                    self._responses.append(message)
                    self._pending_responses.pop(rid, None)
                else:
                    self._messages.append(message)
                self._messages_ready.notify()

    def send_message(
        self,
        stream_id: int,
        message_type: str,
        payload: dict,
        request_id: str | None = None,
    ) -> str:
        if self.state != ConnectionState.ESTABLISHED:
            raise ConnectionError("CCP connection is not established")
        if stream_id not in (0, 1):
            raise ValueError("only the control and chat streams are available")

        message_id = request_id or uuid.uuid4().hex
        body = json.dumps(
            {
                "type": message_type,
                "payload": payload,
                "id": message_id,
                "version": PROTOCOL_VERSION,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        frame = FRAME_HEADER.pack(len(body)) + body
        max_data = min(
            DATA_SEGMENT_SIZE, MAX_DATAGRAM_SIZE - HEADER_SIZE - STREAM_HEADER_SIZE
        )
        if STREAM_HEADER_SIZE + len(frame) > max_data:
            raise MalformedPacketError(
                f"framed message exceeds DATA limit "
                f"({STREAM_HEADER_SIZE + len(frame)} > {max_data})"
            )

        with self._lock:
            offset = self._stream_offsets[stream_id]
            segment = STREAM_HEADER.pack(stream_id, offset) + frame
            expected = {
                "AUTH": "AUTH_ACK",
                "USER_LIST_REQ": "USER_LIST",
                "LOGOUT": "LOGOUT_ACK",
            }.get(message_type)
            if expected is not None:
                with self._messages_ready:
                    self._pending_responses[message_id] = expected
            try:
                self._send_packet(PacketType.DATA, segment)
            except OSError:
                if expected is not None:
                    with self._messages_ready:
                        self._pending_responses.pop(message_id, None)
                raise
            self._stream_offsets[stream_id] += len(frame)
        return message_id

    def receive_message(self, timeout: float | None = None) -> dict:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._messages_ready:
            while not self._messages:
                if self._receiver_error is not None:
                    raise ConnectionError(
                        f"CCP receive loop failed: {self._receiver_error}"
                    ) from self._receiver_error
                if self.state == ConnectionState.DISCONNECTED:
                    raise ConnectionError("CCP server closed the connection")
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("timed out waiting for a server message")
                self._messages_ready.wait(remaining)
            return self._messages.popleft()

    def wait_for_message(
        self,
        message_type: str,
        request_id: str | None = None,
        timeout: float = 5.0,
    ) -> dict:
        deadline = time.monotonic() + timeout
        with self._messages_ready:
            while True:
                for i, message in enumerate(self._responses):
                    if (
                        message.get("type") == message_type
                        or message.get("type") == "ERROR"
                    ) and (request_id is None or message.get("id") == request_id):
                        del self._responses[i]
                        return message
                if self._receiver_error is not None:
                    raise ConnectionError(
                        f"CCP receive loop failed: {self._receiver_error}"
                    ) from self._receiver_error
                if self.state == ConnectionState.DISCONNECTED:
                    raise ConnectionError("CCP server closed the connection")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"timed out waiting for {message_type} response")
                self._messages_ready.wait(remaining)

    def ping(self) -> bool:
        if self.state != ConnectionState.ESTABLISHED:
            return False
        self._pong_received.clear()
        try:
            self._send_packet(PacketType.PING)
        except OSError:
            return False
        return self._pong_received.wait(self.receive_timeout)

    def close(self, reason: CloseReason = CloseReason.NORMAL) -> None:
        if self.state == ConnectionState.DISCONNECTED:
            return
        if self.connection_id:
            self.state = ConnectionState.CLOSING
            try:
                self._send_packet(PacketType.CLOSE, bytes([int(reason)]))
            except OSError as exc:
                log.debug("failed to send CLOSE: %s", exc)
        self.connection_id = 0
        self.state = ConnectionState.DISCONNECTED
        self.clear_keys()
        with self._messages_ready:
            self._messages_ready.notify_all()

    def __enter__(self) -> "CcpClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.shutdown()

    def shutdown(self) -> None:
        self._stop_receive.set()
        self.close()
        self._socket.close()
        thread = self._receiver_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)

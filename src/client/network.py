"""UDP client transport: HELLO/ENC, idle heartbeats, framed JSON messages."""
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
    CloseReason,
    DATA_SEGMENT_SIZE,
    HEADER_FORMAT,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT,
    MAGIC,
    MAX_DATAGRAM_SIZE,
    PacketFlag,
    PacketType,
    VERSION,
)
from ..common.exceptions import (
    HandshakeTimeoutError,
    MalformedPacketError,
    NetworkErrorClass,
    UnknownPacketTypeError,
    classify_network_error,
)
from ..security.encryption import (
    DIR_C2S,
    DIR_S2C,
    GCM_TAG_SIZE,
    KEY_SIZE,
    CryptoError,
    derive_keys,
    new_keypair,
    open as gcm_open,
    seal,
)

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
    ESTABLISHED = "established"


class CcpClient:
    """CCP UDP endpoint: HELLO, ENC after keys, message inbox, idle PING/timeout."""

    def __init__(
        self,
        server_host: str = "127.0.0.1",
        server_port: int = 9000,
        receive_timeout: float = 1.0,
        hello_attempts: int = 3,
        hello_retry_interval: float = 1.0,
    ) -> None:
        if hello_attempts < 1 or receive_timeout <= 0 or hello_retry_interval < 0:
            raise ValueError("invalid connect timeouts/attempts")
        self.server_address = (socket.gethostbyname(server_host), server_port)
        self.receive_timeout = receive_timeout
        self.hello_attempts = hello_attempts
        self.hello_retry_interval = hello_retry_interval
        self.state = ConnectionState.DISCONNECTED
        self.connection_id = 0
        self.key_c2s: bytes | None = None
        self.key_s2c: bytes | None = None
        self.last_error: NetworkErrorClass | None = None
        self._private_key = b""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._pns = itertools.count(1)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._messages: deque[dict] = deque()
        self._responses: deque[dict] = deque()
        self._pending: dict[str, str] = {}
        self._ready = threading.Condition()
        self._stream_offsets = {0: 0, 1: 0}
        self._last_recv = self._last_send = time.monotonic()
        self.last_recv_pn = -1

    def clear_keys(self) -> None:
        self.key_c2s = self.key_s2c = None
        self._private_key = b""
        self.last_recv_pn = -1

    def _next_pn(self) -> int:
        n = next(self._pns)
        if n > 0xFFFFFFFF:
            raise OverflowError("CCP packet number space exhausted")
        return n

    def _encode(
        self,
        ptype: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: int | None = None,
        packet_number: int | None = None,
    ) -> bytes:
        cid = self.connection_id if connection_id is None else connection_id
        pn = self._next_pn() if packet_number is None else packet_number
        use_enc = self.key_c2s is not None and ptype not in (
            PacketType.HELLO,
            PacketType.HELLO_ACK,
        )
        if use_enc:
            flags |= FLAG_ENC
            length = len(payload) + GCM_TAG_SIZE
            header = HEADER.pack(
                MAGIC, VERSION, int(ptype), flags, 0, cid, pn, length
            )
            return header + seal(
                self.key_c2s, pn, header, payload, direction=DIR_C2S
            )
        header = HEADER.pack(
            MAGIC, VERSION, int(ptype), flags, 0, cid, pn, len(payload)
        )
        return header + payload

    def build_packet(self, *args, **kwargs) -> bytes:
        with self._lock:
            return self._encode(*args, **kwargs)

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

    def _send(self, ptype: PacketType, payload: bytes = b"", **kwargs) -> None:
        with self._lock:
            try:
                raw = self._encode(ptype, payload, **kwargs)
            except OverflowError:
                self.last_error = NetworkErrorClass.CLOSED
                self.state = ConnectionState.DISCONNECTED
                raise
            try:
                self._socket.sendto(raw, self.server_address)
                self._last_send = time.monotonic()
            except OSError as exc:
                self.last_error = classify_network_error(exc)
                raise

    def _recv(self, timeout: float):
        self._socket.settimeout(timeout)
        while True:
            data, addr = self._socket.recvfrom(MAX_DATAGRAM_SIZE)
            if addr != self.server_address:
                continue
            try:
                ptype, cid, payload, flags, pn = self.parse_packet(data)
            except (MalformedPacketError, UnknownPacketTypeError):
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
            elif self.key_s2c is not None and ptype != PacketType.HELLO_ACK:
                continue
            if ptype != PacketType.HELLO_ACK:
                if pn <= self.last_recv_pn:
                    continue
                self.last_recv_pn = pn
            return ptype, cid, payload, flags, pn

    def connect(self) -> int:
        if self.state is not ConnectionState.DISCONNECTED:
            raise RuntimeError(f"cannot connect while {self.state.value}")
        self._stop.clear()
        self.clear_keys()
        self._private_key, public = new_keypair()
        client_nonce = secrets.token_bytes(NONCE_SIZE)
        hello = public + client_nonce
        for attempt in range(self.hello_attempts):
            try:
                self._send(PacketType.HELLO, hello, connection_id=0, packet_number=0)
            except OSError as exc:
                self.last_error = classify_network_error(exc)
                self.clear_keys()
                raise
            try:
                ptype, cid, payload, _, _ = self._recv(self.receive_timeout)
            except (socket.timeout, TimeoutError):
                if attempt + 1 < self.hello_attempts:
                    time.sleep(self.hello_retry_interval)
                    continue
                self.last_error = NetworkErrorClass.TIMEOUT
                self.clear_keys()
                raise HandshakeTimeoutError(
                    f"no HELLO_ACK after {self.hello_attempts} attempts"
                )
            if ptype != PacketType.HELLO_ACK:
                continue
            if cid == 0 or len(payload) != KEY_SIZE + NONCE_SIZE:
                self.clear_keys()
                raise MalformedPacketError("invalid HELLO_ACK")
            try:
                self.key_c2s, self.key_s2c = derive_keys(
                    self._private_key, payload[:KEY_SIZE], client_nonce, payload[KEY_SIZE:]
                )
            except CryptoError as exc:
                self.clear_keys()
                raise MalformedPacketError(f"failed to derive session keys: {exc}") from exc
            self.connection_id = cid
            self.state = ConnectionState.ESTABLISHED
            now = time.monotonic()
            self._last_recv = self._last_send = now
            self._thread = threading.Thread(
                target=self._receive_loop,
                name=f"ccp-client-recv-{cid:08x}",
                daemon=True,
            )
            self._thread.start()
            return cid
        self.last_error = NetworkErrorClass.TIMEOUT
        self.clear_keys()
        raise HandshakeTimeoutError("failed to establish CCP connection")

    def _on_tick(self) -> bool:
        now = time.monotonic()
        if now - self._last_recv > HEARTBEAT_TIMEOUT:
            try:
                self._send(PacketType.CLOSE, bytes([CloseReason.TIMEOUT]))
            except OSError:
                pass
            self.state = ConnectionState.DISCONNECTED
            with self._ready:
                self._ready.notify_all()
            return False
        if self.state is ConnectionState.ESTABLISHED and now - self._last_send > HEARTBEAT_INTERVAL:
            try:
                self._send(PacketType.PING)
            except OSError:
                self.state = ConnectionState.DISCONNECTED
                with self._ready:
                    self._ready.notify_all()
                return False
        return True

    def _receive_loop(self) -> None:
        while not self._stop.is_set():
            try:
                ptype, cid, payload, _, _ = self._recv(0.25)
            except (socket.timeout, TimeoutError):
                if not self._on_tick():
                    return
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    self.last_error = classify_network_error(exc)
                    self.state = ConnectionState.DISCONNECTED
                    with self._ready:
                        self._ready.notify_all()
                return
            if cid != self.connection_id:
                continue
            self._last_recv = time.monotonic()
            if ptype == PacketType.PING:
                try:
                    self._send(PacketType.PONG)
                except OSError:
                    pass
            elif ptype == PacketType.CLOSE:
                self.state = ConnectionState.DISCONNECTED
                with self._ready:
                    self._ready.notify_all()
                return
            elif ptype == PacketType.DATA:
                self._ingest_data(payload)

    def _ingest_data(self, payload: bytes) -> None:
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
            with self._ready:
                expected = self._pending.get(message["id"])
                if message["type"] == expected or (
                    message["type"] == "ERROR" and message["id"] in self._pending
                ):
                    self._responses.append(message)
                else:
                    self._messages.append(message)
                self._ready.notify_all()

    def send_message(
        self,
        stream_id: int,
        message_type: str,
        payload: dict,
        request_id: str | None = None,
    ) -> str:
        if stream_id not in (0, 1):
            raise ValueError("only control/chat streams are available")
        if self.state is not ConnectionState.ESTABLISHED:
            raise ConnectionError("CCP connection is not established")
        msg_id = request_id or uuid.uuid4().hex
        body = json.dumps(
            {
                "type": message_type,
                "payload": payload,
                "id": msg_id,
                "version": PROTOCOL_VERSION,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        frame = FRAME_HEADER.pack(len(body)) + body
        if len(frame) > DATA_SEGMENT_SIZE:
            raise ValueError(f"framed message exceeds {DATA_SEGMENT_SIZE} bytes")
        with self._lock:
            offset = self._stream_offsets[stream_id]
            self._stream_offsets[stream_id] = offset + len(frame)
            segment = STREAM_HEADER.pack(stream_id, offset) + frame
            if message_type.endswith("_REQ") or message_type in {
                "AUTH",
                "MSG",
                "LOGOUT",
                "USER_LIST_REQ",
            }:
                self._pending[msg_id] = {
                    "AUTH": "AUTH_ACK",
                    "MSG": "MSG_ACK",
                    "LOGOUT": "LOGOUT_ACK",
                    "USER_LIST_REQ": "USER_LIST",
                }.get(message_type, message_type.replace("_REQ", "_ACK"))
        self._send(PacketType.DATA, segment)
        return msg_id

    def receive_message(self, timeout: float | None = None) -> dict:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._ready:
            while not self._messages:
                if self.state is ConnectionState.DISCONNECTED:
                    raise ConnectionError("CCP server closed the connection")
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("timed out waiting for a server message")
                self._ready.wait(remaining)
            return self._messages.popleft()

    def wait_for_message(
        self,
        message_type: str,
        request_id: str | None = None,
        timeout: float | None = 5.0,
    ) -> dict:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._ready:
            while True:
                for i, msg in enumerate(self._responses):
                    if msg["type"] == message_type and (
                        request_id is None or msg["id"] == request_id
                    ):
                        del self._responses[i]
                        if request_id is not None:
                            self._pending.pop(request_id, None)
                        return msg
                    if (
                        msg["type"] == "ERROR"
                        and request_id is not None
                        and msg["id"] == request_id
                    ):
                        del self._responses[i]
                        self._pending.pop(request_id, None)
                        return msg
                if self.state is ConnectionState.DISCONNECTED:
                    raise ConnectionError("CCP server closed the connection")
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError(f"timed out waiting for {message_type}")
                self._ready.wait(remaining)

    def ping(self) -> None:
        self._send(PacketType.PING)

    def close(self, reason: CloseReason = CloseReason.NORMAL) -> None:
        self._stop.set()
        if self.state is ConnectionState.ESTABLISHED:
            try:
                self._send(PacketType.CLOSE, bytes([reason]))
            except OSError as exc:
                log.debug("failed to send CLOSE: %s", exc)
        self.state = ConnectionState.DISCONNECTED
        self.clear_keys()
        with self._ready:
            self._ready.notify_all()

    def shutdown(self) -> None:
        self.close()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)
        self._socket.close()

    def __enter__(self) -> "CcpClient":
        return self

    def __exit__(self, *_) -> None:
        self.shutdown()

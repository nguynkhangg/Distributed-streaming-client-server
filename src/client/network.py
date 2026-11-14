"""UDP connection management for the CCP client."""

from __future__ import annotations

import itertools
import json
import logging
import socket
import struct
import threading
import time
import uuid
from collections import deque
from enum import Enum

try:
    from ..common.constants import (
        MAGIC,
        VERSION,
        PacketType,
        HEADER_FORMAT,
        MAX_DATAGRAM_SIZE,
        DATA_SEGMENT_SIZE,
        CloseReason,
    )
    from ..common.exceptions import (
        HandshakeTimeoutError,
        MalformedPacketError,
        UnknownPacketTypeError,
    )
except ImportError:
    from common.constants import (
        MAGIC,
        VERSION,
        PacketType,
        HEADER_FORMAT,
        MAX_DATAGRAM_SIZE,
        DATA_SEGMENT_SIZE,
        CloseReason,
    )
    from common.exceptions import (
        HandshakeTimeoutError,
        MalformedPacketError,
        UnknownPacketTypeError,
    )

log = logging.getLogger("ccp.client.network")
HEADER = struct.Struct(HEADER_FORMAT)
HEADER_SIZE = HEADER.size
STREAM_HEADER = struct.Struct("!IQ")
STREAM_HEADER_SIZE = STREAM_HEADER.size
FRAME_HEADER = struct.Struct("!I")
PROTOCOL_VERSION = 1


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    HELLO_SENT = "hello_sent"
    ESTABLISHED = "established"
    CLOSING = "closing"


class CcpClient:
    """Own a CCP UDP endpoint, HELLO/HELLO_ACK handshake, and message receive queue."""

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

    def _next_packet_number(self) -> int:
        number = next(self._packet_numbers)
        if number > 0xFFFFFFFF:
            raise OverflowError("CCP packet number space exhausted")
        return number

    def _encode_packet(
        self,
        packet_type: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: int | None = None,
        packet_number: int | None = None,
    ) -> bytes:
        if connection_id is None:
            connection_id = self.connection_id
        if packet_number is None:
            packet_number = self._next_packet_number()

        if HEADER_SIZE + len(payload) > MAX_DATAGRAM_SIZE:
            raise MalformedPacketError("CCP datagram is too large")

        header = HEADER.pack(
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

    def build_packet(
        self,
        packet_type: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: int | None = None,
        packet_number: int | None = None,
    ) -> bytes:
        """Build a plaintext CCP datagram."""
        with self._lock:
            return self._encode_packet(
                packet_type, payload, flags, connection_id, packet_number
            )

    @staticmethod
    def parse_packet(data: bytes) -> tuple[PacketType, int, bytes, int, int]:
        if len(data) < HEADER_SIZE:
            raise MalformedPacketError("datagram is shorter than the CCP header")
        if len(data) > MAX_DATAGRAM_SIZE:
            raise MalformedPacketError("CCP datagram exceeds the maximum size")
        magic, version, raw_type, flags, _reserved, connection_id, packet_number, length = (
            HEADER.unpack(data[:HEADER_SIZE])
        )
        if magic != MAGIC:
            raise MalformedPacketError("invalid CCP magic")
        if version != VERSION:
            raise MalformedPacketError("unsupported CCP version")
        if length != len(data) - HEADER_SIZE:
            raise MalformedPacketError("payload length mismatch")
        try:
            packet_type = PacketType(raw_type)
        except ValueError as exc:
            raise UnknownPacketTypeError(
                f"unknown CCP packet type 0x{raw_type:02x}"
            ) from exc
        return (
            packet_type,
            connection_id,
            data[HEADER_SIZE:],
            flags,
            packet_number,
        )

    def _send_packet(
        self,
        packet_type: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: int | None = None,
    ) -> None:
        with self._lock:
            packet = self._encode_packet(
                packet_type,
                payload,
                flags,
                connection_id,
            )
            self._socket.sendto(packet, self.server_address)

    def _receive_packet(self, timeout: float):
        self._socket.settimeout(timeout)
        while True:
            data, address = self._socket.recvfrom(MAX_DATAGRAM_SIZE)
            if address != self.server_address:
                continue
            try:
                packet_type, connection_id, payload, flags, packet_number = (
                    self.parse_packet(data)
                )
            except (MalformedPacketError, UnknownPacketTypeError) as exc:
                log.debug("discarding malformed server datagram: %s", exc)
                continue

            if flags & 0x02:
                log.debug("discarding encrypted packet; encryption is disabled")
                continue
            return packet_type, connection_id, payload, flags, packet_number

    def connect(self) -> int:
        """Perform the plaintext HELLO/HELLO_ACK exchange and start receiving."""
        if self.state not in (ConnectionState.DISCONNECTED, ConnectionState.CLOSING):
            raise RuntimeError(f"cannot connect while state is {self.state.value}")

        self._stop_receive.clear()
        self._receiver_error = None
        self.connection_id = 0
        self._stream_offsets = {0: 0, 1: 0}
        self.state = ConnectionState.HELLO_SENT
        for attempt in range(self.hello_attempts):
            self._send_packet(
                PacketType.HELLO,
                b"",
                connection_id=0,
            )
            try:
                packet_type, connection_id, payload, _flags, _number = (
                    self._receive_packet(self.receive_timeout)
                )
            except (socket.timeout, TimeoutError):
                if attempt + 1 < self.hello_attempts:
                    time.sleep(self.hello_retry_interval)
                    continue
                self.state = ConnectionState.DISCONNECTED
                raise HandshakeTimeoutError(
                    f"server did not reply to HELLO after {self.hello_attempts} attempts"
                )

            if packet_type != PacketType.HELLO_ACK:
                continue
            if connection_id == 0 or len(payload) != 32 + 16:
                self.state = ConnectionState.DISCONNECTED
                raise MalformedPacketError("invalid HELLO_ACK from server")

            self.connection_id = connection_id
            self.server_public_key = payload[:32]
            self.server_nonce = payload[32:]
            self.state = ConnectionState.ESTABLISHED
            self._receiver_thread = threading.Thread(
                target=self._receive_loop,
                name=f"ccp-client-recv-{connection_id:08x}",
                daemon=True,
            )
            self._receiver_thread.start()
            return self.connection_id

        self.state = ConnectionState.DISCONNECTED
        raise HandshakeTimeoutError("failed to establish CCP connection")

    def _receive_loop(self) -> None:
        while not self._stop_receive.is_set():
            try:
                packet_type, connection_id, payload, _flags, _number = (
                    self._receive_packet(0.25)
                )
            except (socket.timeout, TimeoutError):
                continue
            except OSError as exc:
                if not self._stop_receive.is_set():
                    self._receiver_error = exc
                    self.state = ConnectionState.DISCONNECTED
                    with self._messages_ready:
                        self._messages_ready.notify_all()
                return

            if connection_id != self.connection_id:
                continue
            if packet_type == PacketType.PING:
                try:
                    self._send_packet(PacketType.PONG)
                except OSError as exc:
                    log.warning("could not answer server PING: %s", exc)
                continue
            if packet_type == PacketType.PONG:
                self._pong_received.set()
                continue
            if packet_type == PacketType.CLOSE:
                self.state = ConnectionState.DISCONNECTED
                with self._messages_ready:
                    self._messages_ready.notify_all()
                return
            if packet_type == PacketType.DATA:
                self._receive_data(payload)

    def _receive_data(self, payload: bytes) -> None:
        if len(payload) < STREAM_HEADER_SIZE + FRAME_HEADER.size:
            log.debug("discarding short DATA payload")
            return
        _stream_id, _offset = STREAM_HEADER.unpack(payload[:STREAM_HEADER_SIZE])
        stream_data = memoryview(payload)[STREAM_HEADER_SIZE:]
        cursor = 0
        while cursor + FRAME_HEADER.size <= len(stream_data):
            (frame_length,) = FRAME_HEADER.unpack(
                stream_data[cursor : cursor + FRAME_HEADER.size]
            )
            cursor += FRAME_HEADER.size
            if frame_length == 0 or cursor + frame_length > len(stream_data):
                log.debug("discarding incomplete message frame")
                return
            frame = bytes(stream_data[cursor : cursor + frame_length])
            cursor += frame_length
            try:
                message = json.loads(frame.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                log.debug("discarding invalid JSON message: %s", exc)
                continue
            if (
                not isinstance(message, dict)
                or not isinstance(message.get("type"), str)
                or not isinstance(message.get("payload"), dict)
                or not isinstance(message.get("id"), str)
                or message.get("version") != PROTOCOL_VERSION
            ):
                log.debug("discarding message with invalid envelope")
                continue
            with self._messages_ready:
                request_id = message["id"]
                expected_type = self._pending_responses.get(request_id)
                if message["type"] == expected_type or (
                    message["type"] == "ERROR" and request_id in self._pending_responses
                ):
                    self._responses.append(message)
                    self._pending_responses.pop(request_id, None)
                else:
                    self._messages.append(message)
                self._messages_ready.notify()

        if cursor != len(stream_data):
            log.debug("discarding DATA payload with trailing bytes")

    def send_message(
        self,
        stream_id: int,
        message_type: str,
        payload: dict,
        request_id: str | None = None,
    ) -> str:
        """Send one framed JSON message on control stream 0 or chat stream 1."""
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
        max_data_size = (
            min(
                DATA_SEGMENT_SIZE,
                MAX_DATAGRAM_SIZE - HEADER_SIZE - STREAM_HEADER_SIZE,
            )
        )
        if STREAM_HEADER_SIZE + len(frame) > max_data_size:
            raise MalformedPacketError(
                "framed message exceeds the DATA segment limit "
                f"({STREAM_HEADER_SIZE + len(frame)} > {max_data_size})"
            )

        with self._lock:
            offset = self._stream_offsets[stream_id]
            segment = STREAM_HEADER.pack(stream_id, offset) + frame
            expected_response = {
                "AUTH": "AUTH_ACK",
                "USER_LIST_REQ": "USER_LIST",
                "LOGOUT": "LOGOUT_ACK",
            }.get(message_type)
            if expected_response is not None:
                with self._messages_ready:
                    self._pending_responses[message_id] = expected_response
            try:
                self._send_packet(PacketType.DATA, segment)
            except OSError:
                if expected_response is not None:
                    with self._messages_ready:
                        self._pending_responses.pop(message_id, None)
                raise
            self._stream_offsets[stream_id] += len(frame)
        return message_id

    def receive_message(self, timeout: float | None = None) -> dict:
        """Return the next decoded server message, or raise on timeout/disconnect."""
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
        """Wait for a correlated response without consuming unrelated events."""
        deadline = time.monotonic() + timeout
        with self._messages_ready:
            while True:
                for index, message in enumerate(self._responses):
                    if (
                        message.get("type") == message_type
                        or message.get("type") == "ERROR"
                    ) and (
                        request_id is None or message.get("id") == request_id
                    ):
                        del self._responses[index]
                        return message
                if self._receiver_error is not None:
                    raise ConnectionError(
                        f"CCP receive loop failed: {self._receiver_error}"
                    ) from self._receiver_error
                if self.state == ConnectionState.DISCONNECTED:
                    raise ConnectionError("CCP server closed the connection")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"timed out waiting for {message_type} response"
                    )
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

"""UDP connection management for the CCP client."""

from __future__ import annotations

import itertools
import json
import logging
import os
import socket
import struct
import threading
import time
import uuid
from collections import deque
from enum import Enum
from typing import Callable
from ..common.exceptions import (
    HandshakeTimeoutError,
    MalformedPacketError,
)

from ..file_transfer.congestion import CubicController
from ..file_transfer.packet import (
    FLAG_ENC,
    HEADER_SIZE,
    MAX_DATA_BYTES,
    PacketHeader,
    build_packet as build_datagram,
)
from ..file_transfer.reliability import ConnectionFailed
from .transport import ClientReliableConnection
from ..common.constants import (
    MAGIC,
    VERSION,
    PacketType,
    HEADER_FORMAT,
    MAX_DATAGRAM_SIZE,
    DATA_SEGMENT_SIZE,
    CloseReason,
)
from ..security.encryption import (
    DIR_C2S,
    DIR_S2C,
    GCM_TAG_SIZE,
    KEY_SIZE,
    CryptoError,
    derive_keys,
    generate_x25519_keypair,
    open as gcm_open,
    seal,
)
from ..common.exceptions import (
    HandshakeTimeoutError,
    MalformedPacketError,
    UnknownPacketTypeError,
)

log = logging.getLogger("ccp.client.network")
FRAME_HEADER = struct.Struct("!I")
PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024
MAX_BUFFERED_BYTES = 256 * MAX_DATA_BYTES
POLL_INTERVAL = 0.01
FIRST_FILE_STREAM = 4
NONCE_SIZE = 16


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
        encryption: bool = True,
    ) -> None:
        if hello_attempts < 1:
            raise ValueError("hello_attempts must be at least 1")
        if receive_timeout <= 0 or hello_retry_interval < 0:
            raise ValueError("timeouts must be positive (retry interval may be zero)")

        self.server_address = (socket.gethostbyname(server_host), server_port)
        self.receive_timeout = receive_timeout
        self.hello_attempts = hello_attempts
        self.hello_retry_interval = hello_retry_interval
        self.encryption = encryption

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
        self._receiver_error: Exception | None = None
        self._key_c2s: bytes | None = None
        self._key_s2c: bytes | None = None
        self._transport: ClientReliableConnection | None = None
        self._receive_offsets: dict[int, int] = {}
        self._receive_segments: dict[int, list[tuple[int, bytes]]] = {}
        self._frame_buffers: dict[int, bytearray] = {}
        self._stream_ends: dict[int, int] = {}
        self._file_sinks: dict[int, Callable[[int, bytes, bool], None]] = {}
        self._early_file_data: dict[int, list[tuple[int, bytes, bool]]] = {}
        self._closed_file_streams: set[int] = set()
        self._last_receive = self._last_send = time.monotonic()
        self._stream_offsets = {0: 0, 1: 0}

    def clear_keys(self) -> None:
        self._key_c2s = self._key_s2c = None
        self.server_public_key = self.server_nonce = b""

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
        encrypt: bool = False,
    ) -> bytes:
        if connection_id is None:
            connection_id = self.connection_id
        if packet_number is None:
            packet_number = self._next_packet_number()

        if encrypt:
            if self._key_c2s is None:
                raise ConnectionError("encryption keys are not established")
            flags |= FLAG_ENC
        payload_length = len(payload) + (GCM_TAG_SIZE if encrypt else 0)
        if HEADER_SIZE + payload_length > MAX_DATAGRAM_SIZE:
            raise MalformedPacketError("CCP datagram is too large")

        header = PacketHeader(
            packet_type=int(packet_type),
            flags=flags,
            connection_id=connection_id,
            packet_number=packet_number,
            payload_length=payload_length,
        )
        if encrypt:
            payload = seal(
                self._key_c2s, packet_number, header.encode(), payload,
                direction=DIR_C2S,
            )
        return build_datagram(header, payload)

    @staticmethod
    def parse_packet(data: bytes) -> tuple[PacketType, int, bytes, int, int]:
        try:
            header = PacketHeader.decode(data)
        except ValueError as exc:
            raise MalformedPacketError(str(exc)) from exc
        return (
            PacketType(header.packet_type),
            header.connection_id,
            data[HEADER_SIZE:],
            header.flags,
            header.packet_number,
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
                packet_number,
                encrypt=self.encryption and packet_type != PacketType.HELLO,
            )
            self._socket.sendto(packet, self.server_address)

    def _receive_packet(self, timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout()
            self._socket.settimeout(remaining)
            data, address = self._socket.recvfrom(MAX_DATAGRAM_SIZE + 1)
            if address != self.server_address:
                continue
            try:
                packet_type, connection_id, payload, flags, packet_number = self.parse_packet(data)
            except MalformedPacketError as exc:
                log.debug("discarding malformed server datagram: %s", exc)
                continue

            if packet_type == PacketType.HELLO_ACK:
                if self.state is not ConnectionState.HELLO_SENT:
                    continue
            else:
                if self.encryption:
                    if not flags & FLAG_ENC or self._key_s2c is None:
                        log.debug("discarding unencrypted or premature server packet")
                        continue
                    try:
                        payload = gcm_open(
                            self._key_s2c, packet_number, data[:HEADER_SIZE],
                            payload, direction=DIR_S2C,
                        )
                    except CryptoError:
                        log.debug("discarding packet with invalid authentication tag")
                        continue
                elif flags & FLAG_ENC:
                    log.debug("discarding encrypted packet in plaintext mode")
                    continue
            return packet_type, connection_id, payload, flags, packet_number

    def connect(self) -> int:
        """Exchange HELLO packets, establish keys, and start the transport loop."""
        if self.state not in (ConnectionState.DISCONNECTED, ConnectionState.CLOSING):
            raise RuntimeError(f"cannot connect while state is {self.state.value}")

        previous_thread = self._receiver_thread
        if previous_thread is not None and previous_thread.is_alive():
            self._stop_receive.set()
            previous_thread.join(timeout=1)
            if previous_thread.is_alive():
                raise RuntimeError("previous receive loop has not stopped")
        self._stop_receive.clear()
        self._pong_received.clear()
        self._receiver_error = None
        self.connection_id = 0
        self.clear_keys()
        self._receive_offsets.clear()
        self._receive_segments.clear()
        self._frame_buffers.clear()
        self._stream_ends.clear()
        self._file_sinks.clear()
        self._early_file_data.clear()
        self._closed_file_streams.clear()
        with self._messages_ready:
            self._messages.clear()
            self._responses.clear()
            self._pending_responses.clear()
        if self.encryption:
            private_key, public_key = generate_x25519_keypair()
            client_nonce = os.urandom(NONCE_SIZE)
            hello = public_key + client_nonce
        else:
            private_key = b""
            client_nonce = b""
            hello = b""
        self.state = ConnectionState.HELLO_SENT
        for attempt in range(self.hello_attempts):
            self._send_packet(
                PacketType.HELLO,
                b"",
                connection_id=0,
            )
            try:
                self._send_packet(
                    PacketType.HELLO, hello, connection_id=0
                )
            except OSError:
                self.clear_keys()
                self.state = ConnectionState.DISCONNECTED
                raise

            try:
                packet_type, connection_id, payload, flags, number = self._receive_packet(
                    self.receive_timeout
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
            if connection_id == 0 or len(payload) != KEY_SIZE + NONCE_SIZE:
                self.clear_keys()
                self.state = ConnectionState.DISCONNECTED
                raise MalformedPacketError("invalid HELLO_ACK from server")

            self.connection_id = connection_id
            self.server_public_key = payload[:KEY_SIZE]
            self.server_nonce = payload[KEY_SIZE:]
            if self.encryption:
                try:
                    self._key_c2s, self._key_s2c = derive_keys(
                        private_key, self.server_public_key, client_nonce, self.server_nonce
                    )
                except CryptoError as exc:
                    self.connection_id = 0
                    self.clear_keys()
                    self.state = ConnectionState.DISCONNECTED
                    raise MalformedPacketError("invalid server key in HELLO_ACK") from exc
            self._transport = ClientReliableConnection(
                allocate_packet_number=self._next_packet_number,
                on_stream_data=self._on_stream_data,
                congestion=CubicController(),
            )
            self._transport.on_packet(
                int(packet_type), number, flags, payload, time.monotonic()
            )
            self.state = ConnectionState.ESTABLISHED
            now = time.monotonic()
            self._last_receive = self._last_send = now
            self._receiver_thread = threading.Thread(
                target=self._receive_loop,
                name=f"ccp-client-recv-{connection_id:08x}",
                daemon=True,
            )
            self._receiver_thread.start()
            return connection_id

        self.state = ConnectionState.DISCONNECTED
        raise HandshakeTimeoutError("failed to establish CCP connection")

    def _receive_loop(self) -> None:
        while not self._stop_receive.is_set() and self.state is ConnectionState.ESTABLISHED:
            try:
                packet_type, connection_id, payload, flags, number = (
                    self._receive_packet(POLL_INTERVAL)
                )
            except (socket.timeout, TimeoutError):
                packet_type = None
            except OSError as exc:
                if not self._stop_receive.is_set():
                    self._fail_connection(exc, CloseReason.TIMEOUT)
                return

            try:
                with self._lock:
                    if self.state is not ConnectionState.ESTABLISHED:
                        return
                    if packet_type is not None and connection_id == self.connection_id:
                        self._last_receive = time.monotonic()
                        if self._transport is None:
                            raise ConnectionError("reliable transport is not established")
                        self._transport.on_packet(
                            int(packet_type), number, flags, payload, time.monotonic()
                        )
                        if packet_type == PacketType.PING:
                            self._send_packet(PacketType.PONG)
                        elif packet_type == PacketType.PONG:
                            self._pong_received.set()
                        elif packet_type == PacketType.CLOSE:
                            self.connection_id = 0
                            self.clear_keys()
                            self.state = ConnectionState.DISCONNECTED
                            with self._messages_ready:
                                self._messages_ready.notify_all()
                            return
                    self._poll_transport()
                    now = time.monotonic()
                    if now - self._last_receive >= HEARTBEAT_TIMEOUT:
                        raise TimeoutError("server heartbeat timed out")
                    if now - self._last_send >= HEARTBEAT_INTERVAL:
                        self._send_packet(PacketType.PING)
            except ConnectionFailed as exc:
                self._fail_connection(exc, CloseReason.TIMEOUT)
                return
            except (ValueError, MalformedPacketError) as exc:
                self._fail_connection(exc, CloseReason.PROTOCOL_ERROR)
                return
            except (OSError, ConnectionError, OverflowError) as exc:
                if not self._stop_receive.is_set():
                    self._fail_connection(exc, CloseReason.TIMEOUT)
                return

    def _poll_transport(self) -> None:
        if self._transport is None:
            raise ConnectionError("connection is not established")
        buffered = sum(
            len(chunk) for group in self._receive_segments.values() for _, chunk in group
        ) + sum(len(buffer) for buffer in self._frame_buffers.values()) + self._early_file_bytes()
        self._transport.recv_window = max(
            0, (MAX_BUFFERED_BYTES - buffered) // MAX_DATA_BYTES
        )
        for outgoing in self._transport.poll(time.monotonic()):
            self._send_packet(
                PacketType(outgoing.packet_type), outgoing.payload, outgoing.flags,
                packet_number=outgoing.packet_number,
            )

    def _fail_connection(self, exc: Exception, reason: CloseReason) -> None:
        log.warning("client transport failed: %s", exc)
        self._receiver_error = exc
        self.close(reason)

    def _order_stream_data(self, stream_id: int, offset: int, data: bytes) -> bytes:
        """Return newly contiguous stream bytes, retaining out-of-order segments."""
        expected = self._receive_offsets.get(stream_id, 0)
        end = offset + len(data)
        if end <= expected:
            return b""
        if offset < expected:
            data = data[expected - offset:]
            offset = expected
        if offset - expected > MAX_BUFFERED_BYTES:
            raise ValueError("stream offset exceeds receive buffer")

        segments = self._receive_segments.setdefault(stream_id, [])
        merged: list[tuple[int, bytes]] = []
        for start, chunk in sorted(segments + [(offset, data)]):
            if not merged or start > merged[-1][0] + len(merged[-1][1]):
                merged.append((start, chunk))
                continue
            previous_start, previous = merged[-1]
            overlap = previous_start + len(previous) - start
            common = min(overlap, len(chunk))
            if previous[start - previous_start:start - previous_start + common] != chunk[:common]:
                raise ValueError("conflicting overlapping stream data")
            merged[-1] = (previous_start, previous + chunk[overlap:])

        self._receive_segments[stream_id] = merged
        if sum(len(chunk) for group in self._receive_segments.values()
               for _, chunk in group) + sum(
                   len(buffer) for buffer in self._frame_buffers.values()
               ) > MAX_BUFFERED_BYTES:
            raise ValueError("stream receive buffer exceeded")
        if not merged or merged[0][0] != expected:
            return b""
        _, contiguous = merged.pop(0)
        self._receive_offsets[stream_id] = expected + len(contiguous)
        return contiguous

    def _early_file_bytes(self) -> int:
        return sum(
            len(data) for segments in self._early_file_data.values()
            for _, data, _ in segments
        )

    def open_file_stream(
        self, stream_id: int, sink: Callable[[int, bytes, bool], None]
    ) -> None:
        """Deliver raw segments (offset, data, fin) of a file stream to `sink`.

        The sink runs on the receive thread, so it must be quick and must not raise.
        Segments that arrived before this call are delivered first.
        """
        if stream_id < FIRST_FILE_STREAM:
            raise ValueError(f"file streams start at {FIRST_FILE_STREAM}")
        with self._lock:
            if stream_id in self._file_sinks or stream_id in self._closed_file_streams:
                raise ValueError(f"file stream {stream_id} is already in use")
            self._file_sinks[stream_id] = sink
            for offset, data, fin in self._early_file_data.pop(stream_id, []):
                sink(offset, data, fin)

    def close_file_stream(self, stream_id: int) -> None:
        """Stop delivering a file stream; late segments for it are ignored."""
        with self._lock:
            self._file_sinks.pop(stream_id, None)
            self._early_file_data.pop(stream_id, None)
            if stream_id >= FIRST_FILE_STREAM:
                self._closed_file_streams.add(stream_id)

    def _on_file_data(self, stream_id: int, offset: int, data: bytes, fin: bool) -> None:
        sink = self._file_sinks.get(stream_id)
        if sink is not None:
            sink(offset, data, fin)
            return
        if stream_id in self._closed_file_streams:
            return
        # FILE_READY travels on another stream and may be processed after the first data.
        self._early_file_data.setdefault(stream_id, []).append((offset, data, fin))
        if self._early_file_bytes() > MAX_BUFFERED_BYTES:
            raise ValueError("too much data for an unknown file stream")

    def _on_stream_data(
        self, stream_id: int, offset: int, data: bytes, fin: bool
    ) -> None:
        if stream_id >= FIRST_FILE_STREAM:
            self._on_file_data(stream_id, offset, data, fin)
            return
        if stream_id not in (0, 1):
            raise ValueError(f"unsupported stream: {stream_id}")
        end = offset + len(data)
        final_offset = self._stream_ends.get(stream_id)
        if fin:
            if final_offset is not None and final_offset != end:
                raise ValueError("conflicting stream final offsets")
            if self._receive_offsets.get(stream_id, 0) > end or any(
                start + len(chunk) > end
                for start, chunk in self._receive_segments.get(stream_id, [])
            ):
                raise ValueError("stream data extends beyond final offset")
            self._stream_ends[stream_id] = end
            final_offset = end
        if final_offset is not None and end > final_offset:
            raise ValueError("stream data extends beyond final offset")
        ordered = self._order_stream_data(stream_id, offset, data)
        buffer = self._frame_buffers.setdefault(stream_id, bytearray())
        buffer.extend(ordered)
        while len(buffer) >= FRAME_HEADER.size:
            (frame_length,) = FRAME_HEADER.unpack_from(buffer)
            if frame_length == 0 or frame_length > MAX_MESSAGE_BYTES:
                raise ValueError("invalid message frame length")
            end = FRAME_HEADER.size + frame_length
            if len(buffer) < end:
                break
            frame = bytes(buffer[FRAME_HEADER.size:end])
            del buffer[:end]
            self._receive_frame(frame)
        if final_offset == self._receive_offsets.get(stream_id, 0) and buffer:
            raise ValueError("stream ended with an incomplete message frame")

    def _receive_frame(self, frame: bytes) -> None:
        try:
            message = json.loads(frame.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.debug("discarding invalid JSON message: %s", exc)
            return
        if (
            not isinstance(message, dict)
            or not isinstance(message.get("type"), str)
            or not isinstance(message.get("payload"), dict)
            or not isinstance(message.get("id"), str)
            or message.get("version") != PROTOCOL_VERSION
        ):
            log.debug("discarding message with invalid envelope")
            return
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
        if len(body) > MAX_MESSAGE_BYTES:
            raise MalformedPacketError("message exceeds the 64 KiB limit")

        with self._lock:
            if self.state is not ConnectionState.ESTABLISHED or self._transport is None:
                raise ConnectionError("CCP connection is not established")
            expected_response = {
                "AUTH": "AUTH_ACK",
                "USER_LIST_REQ": "USER_LIST",
                "LOGOUT": "LOGOUT_ACK",
            }.get(message_type)
            if expected_response is not None:
                with self._messages_ready:
                    self._pending_responses[message_id] = expected_response
            try:
                self._transport.send_stream(stream_id, frame)
                self._poll_transport()
            except (OSError, ConnectionFailed, OverflowError) as exc:
                if expected_response is not None:
                    with self._messages_ready:
                        self._pending_responses.pop(message_id, None)
                self._fail_connection(exc, CloseReason.TIMEOUT)
                raise
        return message_id

    def attach_file_stream(self, stream_id: int, segments) -> None:
        """Send raw file bytes on a file stream; segments yields (offset, data, fin)."""
        if stream_id < FIRST_FILE_STREAM:
            raise ValueError(f"file streams start at {FIRST_FILE_STREAM}")
        with self._lock:
            if self.state is not ConnectionState.ESTABLISHED or self._transport is None:
                raise ConnectionError("CCP connection is not established")
            self._transport.attach_source(stream_id, iter(segments))
            try:
                self._poll_transport()
            except (OSError, ConnectionFailed, OverflowError) as exc:
                self._fail_connection(exc, CloseReason.TIMEOUT)
                raise

    def detach_file_stream(self, stream_id: int) -> None:
        """Stop sending a file stream (cancelled or failed transfer)."""
        with self._lock:
            if self._transport is not None:
                self._transport.detach_source(stream_id)

    def stream_acked_bytes(self, stream_id: int) -> int:
        with self._lock:
            return self._transport.acked_bytes(stream_id) if self._transport else 0

    @property
    def has_unacked_data(self) -> bool:
        with self._lock:
            return self._transport is not None and self._transport.has_unacked_data

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
        self._stop_receive.set()
        if self.state == ConnectionState.DISCONNECTED:
            return
        if self.connection_id:
            self.state = ConnectionState.CLOSING
            try:
                self._send_packet(PacketType.CLOSE, bytes([int(reason)]))
            except (OSError, OverflowError, ConnectionError) as exc:
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

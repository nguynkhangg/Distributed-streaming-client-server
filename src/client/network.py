"""UDP connection management for the CCP client."""

from __future__ import annotations

import itertools
import os
import socket
import struct
import threading
import time
from enum import Enum
from typing import Optional

try:
    from ..common.constants import (
        MAGIC, VERSION, PacketType, HEADER_FORMAT, HEADER_SIZE,
        MAX_DATAGRAM_SIZE, CloseReason, DEFAULT_SERVER_HOST,
    )
    from ..common.exceptions import (
        HandshakeTimeoutError, MalformedPacketError, UnknownPacketTypeError,
    )
except ImportError:
    from common.constants import (
        MAGIC, VERSION, PacketType, HEADER_FORMAT, HEADER_SIZE,
        MAX_DATAGRAM_SIZE, CloseReason, DEFAULT_SERVER_HOST,
    )
    from common.exceptions import (
        HandshakeTimeoutError, MalformedPacketError, UnknownPacketTypeError,
    )

HEADER = struct.Struct(HEADER_FORMAT)
HEADER_SIZE = HEADER.size


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    HELLO_SENT = "hello_sent"
    ESTABLISHED = "established"
    CLOSING = "closing"


class CcpClient:
    """Own a CCP UDP endpoint and perform the HELLO/HELLO_ACK handshake."""

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

        self.server_address = (server_host, server_port)
        self.receive_timeout = receive_timeout
        self.hello_attempts = hello_attempts
        self.hello_retry_interval = hello_retry_interval

        self.state = ConnectionState.DISCONNECTED
        self.connection_id = 0
        self.server_public_key = b""
        self.server_nonce = b""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._packet_numbers = itertools.count(1)
        self._lock = threading.Lock()
        self._stop_receive = threading.Event()

    def _next_packet_number(self) -> int:
        return next(self._packet_numbers)

    def build_packet(
        self,
        packet_type: PacketType,
        payload: bytes = b"",
        flags: int = 0,
        connection_id: Optional[int] = None,
        packet_number: Optional[int] = None,
    ) -> bytes:
        if len(payload) > MAX_DATAGRAM_SIZE - HEADER_SIZE:
            raise MalformedPacketError("CCP payload is too large")
        with self._lock:
            if connection_id is None:
                connection_id = self.connection_id
            if packet_number is None:
                packet_number = self._next_packet_number()
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

    @staticmethod
    def parse_packet(data: bytes) -> tuple[PacketType, int, bytes, int, int]:
        if len(data) < HEADER_SIZE:
            raise MalformedPacketError("datagram is shorter than the CCP header")
        magic, version, raw_type, flags, _reserved, connection_id, packet_number, length = \
            HEADER.unpack(data[:HEADER_SIZE])
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
        return packet_type, connection_id, data[HEADER_SIZE:], flags, packet_number

    def _send_packet(self, packet_type: PacketType, payload: bytes = b"",
                     flags: int = 0, connection_id: Optional[int] = None) -> None:
        self._socket.sendto(
            self.build_packet(packet_type, payload, flags, connection_id),
            self.server_address,
        )

    def _receive_packet(self, timeout: Optional[float] = None):
        self._socket.settimeout(self.receive_timeout if timeout is None else timeout)
        while True:
            data, address = self._socket.recvfrom(MAX_DATAGRAM_SIZE)
            if address != self.server_address:
                continue
            packet_type, connection_id, payload, flags, packet_number = \
                self.parse_packet(data)
            if packet_type not in (
                PacketType.HELLO_ACK, PacketType.CLOSE, PacketType.PING, PacketType.PONG,
            ):
                continue
            return packet_type, connection_id, payload, flags, packet_number

    def connect(self, dev_mode: bool = True) -> int:
        """Perform HELLO/HELLO_ACK and return the assigned connection ID."""
        if self.state not in (ConnectionState.DISCONNECTED, ConnectionState.CLOSING):
            raise RuntimeError(f"cannot connect while state is {self.state.value}")

        hello_payload = b"" if dev_mode else os.urandom(32 + 16)
        self.connection_id = 0
        self.state = ConnectionState.HELLO_SENT

        for attempt in range(self.hello_attempts):
            self._send_packet(PacketType.HELLO, hello_payload, connection_id=0)
            try:
                packet_type, connection_id, payload, _flags, _number = \
                    self._receive_packet(self.receive_timeout)
            except (socket.timeout, TimeoutError):
                if attempt + 1 < self.hello_attempts:
                    time.sleep(self.hello_retry_interval)
                    continue
                self.state = ConnectionState.DISCONNECTED
                raise HandshakeTimeoutError(
                    f"server did not reply to HELLO after {self.hello_attempts} attempts"
                )

            if packet_type == PacketType.PING:
                continue
            if packet_type != PacketType.HELLO_ACK:
                continue
            if connection_id == 0 or len(payload) != 32 + 16:
                raise MalformedPacketError("invalid HELLO_ACK from server")

            self.connection_id = connection_id
            self.server_public_key = payload[:32]
            self.server_nonce = payload[32:]
            self.state = ConnectionState.ESTABLISHED
            return self.connection_id

        self.state = ConnectionState.DISCONNECTED
        raise HandshakeTimeoutError("failed to establish CCP connection")

    def ping(self) -> bool:
        if self.state != ConnectionState.ESTABLISHED:
            return False
        self._send_packet(PacketType.PING)
        try:
            packet_type, connection_id, _payload, _flags, _number = \
                self._receive_packet()
            return packet_type == PacketType.PONG and connection_id == self.connection_id
        except (socket.timeout, TimeoutError):
            return False

    def close(self, reason: CloseReason = CloseReason.NORMAL) -> None:
        if self.state == ConnectionState.DISCONNECTED:
            return
        if self.connection_id:
            self.state = ConnectionState.CLOSING
            self._send_packet(PacketType.CLOSE, bytes([int(reason)]))
        self.connection_id = 0
        self.state = ConnectionState.DISCONNECTED

    def __enter__(self) -> "CcpClient":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
        self._socket.close()

    def shutdown(self) -> None:
        self._stop_receive.set()
        self.close()
        self._socket.close()
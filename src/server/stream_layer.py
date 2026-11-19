"""Reliable framed streams for the control and chat streams (0 and 1) on the server.

Two small pieces, one per direction:

* StreamReceiver (client -> server): puts DATA segments back in order by offset, ignores
  segments it already has, and cuts the byte stream into `[4-byte length][JSON]` frames.
  A client that resends a packet (new packet number, same offset) therefore never makes the
  server handle the same message twice.
* SendBuffer (server -> client): remembers every frame sent until the client ACKs the packet,
  so the sweeper can send it again with a new packet number. The client ignores a segment
  whose offset it already has, so a late copy does no harm.
"""
from __future__ import annotations

import struct
import threading
from dataclasses import dataclass

try:
    from ..file_transfer.packet import decode_ack_payload
except ImportError:
    from src.file_transfer.packet import decode_ack_payload

MAX_FRAME_BYTES = 64 * 1024        # same limit as the message layer (protocol-spec section 5)
MAX_PENDING_BYTES = 256 * 1024     # out-of-order bytes kept per stream
RESEND_AFTER = 0.5                 # seconds without ACK before a frame is sent again
MAX_RESENDS = 8
_LENGTH = struct.Struct("!I")


class FrameError(ValueError):
    """The byte stream does not follow the framing rules (length 0 or too large)."""


class StreamReceiver:
    """One incoming stream: order by offset, drop duplicates, cut into frames."""

    def __init__(self) -> None:
        self.next_offset = 0
        self._ahead: dict[int, bytes] = {}      # segments that arrived before the gap was filled
        self._buffer = bytearray()

    def feed(self, offset: int, data: bytes) -> list[bytes]:
        """Add one segment; return the JSON frames that are complete now (possibly none)."""
        end = offset + len(data)
        if end <= self.next_offset:
            return []                            # duplicate
        if offset > self.next_offset:
            known = self._ahead.get(offset)
            if (known is None or len(known) < len(data)) and \
                    sum(len(v) for v in self._ahead.values()) + len(data) <= MAX_PENDING_BYTES:
                self._ahead[offset] = data
            return []
        self._append(data[self.next_offset - offset:])
        while True:                              # use any stored segment that now touches the data
            start = next((o for o in self._ahead if o <= self.next_offset), None)
            if start is None:
                break
            segment = self._ahead.pop(start)
            if start + len(segment) > self.next_offset:
                self._append(segment[self.next_offset - start:])
        return self._frames()

    def _append(self, data: bytes) -> None:
        self._buffer.extend(data)
        self.next_offset += len(data)

    def _frames(self) -> list[bytes]:
        frames = []
        while len(self._buffer) >= _LENGTH.size:
            (length,) = _LENGTH.unpack_from(self._buffer)
            if length == 0 or length > MAX_FRAME_BYTES:
                raise FrameError("invalid frame length %d" % length)
            if len(self._buffer) < _LENGTH.size + length:
                break
            frames.append(bytes(self._buffer[_LENGTH.size:_LENGTH.size + length]))
            del self._buffer[:_LENGTH.size + length]
        return frames


@dataclass
class _Sent:
    stream_id: int
    offset: int
    frame: bytes
    sent_at: float
    resends: int = 0


class SendBuffer:
    """Frames sent to one client that have not been acknowledged yet."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sent: dict[int, _Sent] = {}        # packet number -> frame
        self.offsets: dict[int, int] = {}        # stream id -> next offset to use

    def next_offset(self, stream_id: int, length: int) -> int:
        offset = self.offsets.get(stream_id, 0)
        self.offsets[stream_id] = offset + length
        return offset

    def remember(self, number: int, stream_id: int, offset: int, frame: bytes, now: float) -> None:
        with self._lock:
            self._sent[number] = _Sent(stream_id, offset, frame, now)

    def on_ack(self, payload: bytes) -> None:
        try:
            _, _, ranges = decode_ack_payload(payload)
        except ValueError:
            return
        with self._lock:
            for number in [n for n in self._sent if any(a <= n <= b for a, b in ranges)]:
                del self._sent[number]

    def take_due(self, now: float) -> list[_Sent]:
        """Remove and return frames that have waited long enough; the caller sends them again."""
        due = []
        with self._lock:
            for number, item in list(self._sent.items()):
                if now - item.sent_at >= RESEND_AFTER:
                    del self._sent[number]
                    if item.resends < MAX_RESENDS:
                        due.append(item)
        return due

    def __len__(self) -> int:
        with self._lock:
            return len(self._sent)

"""
ReliableConnection joins SendTracker and AckTracker into one object per connection:
- send side: cuts stream data into DATA segments (<= 1000 bytes), keeps them until ACK,
  resends lost ones in new packets
- receive side: records packet numbers, decides when to ACK, hands stream data to a callback

Rules for the caller (server session or client):
- on_packet() gets the header fields and the DECRYPTED payload
- poll() returns OutgoingPacket objects that are NOT encrypted yet; the caller builds
  the 16-byte header (with ENC flag) and encrypts, because the header is the AEAD data
- not thread-safe: only one thread may use one connection at a time
- the callback may get the same offset twice (late duplicate), the receiver ignores it
"""
from collections import deque
from dataclasses import dataclass

from .packet import (FLAG_FIN, MAX_DATA_BYTES, TYPE_ACK, TYPE_DATA,
                     decode_ack_payload, decode_data_payload, encode_data_payload)
from .reliability import AckTracker, SentPacket, SendTracker

RECV_WINDOW = 256  # packets the receiver can buffer (spec 11: 256 KiB relay buffer)


@dataclass(frozen=True)
class OutgoingPacket:
    packet_type: int
    packet_number: int
    payload: bytes # not encrupted
    flags: int = 0


class ReliableConnection:
    def __init__(self, allocate_packet_number=None, on_stream_data=None):
        self._send = SendTracker(allocate_packet_number)
        self._ack = AckTracker()
        self._on_stream_data = on_stream_data
        self.recv_window = RECV_WINDOW  

        self._queues: dict[int, deque] = {}  
        self._sources: dict[int, object] = {}  
        self._next_offset: dict[int, int] = {}
        self._acked_bytes: dict[int, int] = {}
        self._resend: list[SentPacket] = []  

    def send_stream(self, stream_id: int, data: bytes, fin: bool = False) -> None:
        """Xếp thành các đoạn 1000 byte có offset liên tục (nhớ offset)"""
        if stream_id in self._sources:
            raise ValueError("stream already has file source")
        queue = self._queues.setdefault(stream_id, deque())
        offset = self._next_offset.get(stream_id, 0)

        if not data:
            if fin:
                queue.append((offset, b"", True))
            return

        for start in range(0, len(data), MAX_DATA_BYTES):
            chunk = data[start:start + MAX_DATA_BYTES]
            last = start + len(chunk) == len(data)
            queue.append((offset, chunk, fin and last))
            offset += len(chunk)
        self._next_offset[stream_id] = offset

    def attach_source(self, stream_id: int, segments) -> None:
        """Quăng thông tin lên sources, nếu stream đc dùng rồi thì báo lỗi"""
        if stream_id in self._sources or stream_id in self._queues:
            raise ValueError("stream already in use")
        self._sources[stream_id] = segments

    def acked_bytes(self, stream_id: int) -> int:
        """Bytes of the stream acknowledged by sender """
        return self._acked_bytes.get(stream_id, 0)

    @property
    def has_unacked_data(self) -> bool:
        """Check if finish data transfer. True when something still queued, in flight or waiting for resend"""
        return bool(self._send.in_flight_count or self._resend
                    or self._sources or any(self._queues.values()))

    def on_packet(self, packet_type: int, packet_number: int, flags: int,
                  payload: bytes, now: float) -> None:
        """
        Feed every received packet (after decryption).
        DATA and ACK are handled here; PING/PONG/CLOSE are only recorded,
        the caller still handles them.
        """
        is_data = packet_type == TYPE_DATA
        is_new = self._ack.on_packet(packet_number, is_data, now)

        if is_data:
            if not is_new:
                return  # duplicate packet number, already delivered
            stream_id, offset, data = decode_data_payload(payload)
            if self._on_stream_data is not None: #!!!
                self._on_stream_data(stream_id, offset, data, bool(flags & FLAG_FIN))

        elif packet_type == TYPE_ACK:
            largest, window, ranges = decode_ack_payload(payload)
            acked, lost = self._send.on_ack(largest, window, ranges, now)
            for packet in acked:
                self._acked_bytes[packet.stream_id] = (
                    self._acked_bytes.get(packet.stream_id, 0) + len(packet.data))
            self._resend.extend(lost)

    def poll(self, now: float) -> list[OutgoingPacket]:
        """
        Return the packet to send:
        1. lost data 
        2. new data when the window has room, lower stream_id first
        3. one ACK if AckTracker says time's up
        """
        out = []

        self._resend.extend(self._send.on_timer(now))
        for packet in self._send.retransmit(self._resend, now):
            out.append(self._data_packet(packet))
        self._resend = []

        while self._send.can_send(now):
            segment = self._next_segment()
            if segment is None:
                break
            stream_id, offset, data, fin = segment
            packet = SentPacket(self._send.allocate_packet_number(),
                                stream_id, offset, data, fin, now)
            self._send.on_data_sent(packet)
            out.append(self._data_packet(packet))

        if self._ack.should_send_ack(now):
            payload = self._ack.build_ack(self.recv_window)
            out.append(OutgoingPacket(TYPE_ACK, self._send.allocate_packet_number(), payload))

        return out

    def _next_segment(self):
        """Pick the next segment (lowest stream_id with data waiting)"""
        for stream_id in sorted(set(self._queues) | set(self._sources)):
            queue = self._queues.get(stream_id)
            if queue: 
                return (stream_id, *queue.popleft())
            if stream_id in self._sources:
                segment = next(self._sources[stream_id], None)
                if segment is None:
                    del self._sources[stream_id]
                    continue
                return (stream_id, *segment)
        return None

    @staticmethod
    def _data_packet(packet: SentPacket) -> OutgoingPacket:
        payload = encode_data_payload(packet.stream_id, packet.offset, packet.data)
        flags = FLAG_FIN if packet.fin else 0
        return OutgoingPacket(TYPE_DATA, packet.packet_number, payload, flags)
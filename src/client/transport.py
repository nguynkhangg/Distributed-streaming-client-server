"""Client-specific adaptation of the shared reliable transport."""

from ..file_transfer.connection import OutgoingPacket, ReliableConnection
from ..file_transfer.packet import TYPE_ACK, decode_ack_payload
from ..file_transfer.reliability import SentPacket, SendTracker


class ClientSendTracker(SendTracker):
    """Enforce the protocol's receive window and RTT sampling rules."""

    def __init__(self, allocate_packet_number=None, congestion=None):
        super().__init__(allocate_packet_number, congestion)
        self._sample_rtt = True
        self._newly_acked_keys = set()

    def can_send(self, now=None):
        return self.peer_window > 0 and super().can_send(now)

    def on_ack(self, largest_acked, recv_window, ranges, now):
        packets = [
            packet for number, packet in self._in_flight.items()
            if any(start <= number <= end for start, end in ranges)
        ]
        newest = max(packets, key=lambda packet: packet.packet_number, default=None)
        self._sample_rtt = newest is None or newest.retransmissions == 0
        self._newly_acked_keys = {(packet.stream_id, packet.offset) for packet in packets}
        try:
            return super().on_ack(largest_acked, recv_window, ranges, now)
        finally:
            self._sample_rtt = True
            self._newly_acked_keys = set()

    def _update_rtt(self, sample):
        if self._sample_rtt:
            super()._update_rtt(sample)

    def _on_late_ack(self, ranges):
        delivered = {
            (packet.stream_id, packet.offset): packet
            for number, packet in self._lost_packets.items()
            if any(start <= number <= end for start, end in ranges)
        }
        self._lost_packets = {
            number: packet for number, packet in self._lost_packets.items()
            if (packet.stream_id, packet.offset) not in delivered
            and (packet.stream_id, packet.offset) not in self._newly_acked_keys
        }
        copies = [
            packet for packet in self._in_flight.values()
            if (packet.stream_id, packet.offset) in delivered
        ]
        for packet in copies:
            del self._in_flight[packet.packet_number]
        copy_keys = {(packet.stream_id, packet.offset) for packet in copies}
        return copies + [
            packet for key, packet in delivered.items()
            if key not in copy_keys and key not in self._newly_acked_keys
        ]


class ClientReliableConnection(ReliableConnection):
    def __init__(self, allocate_packet_number=None, on_stream_data=None, congestion=None):
        super().__init__(allocate_packet_number, on_stream_data, congestion)
        self._send = ClientSendTracker(allocate_packet_number, congestion)

    def detach_source(self, stream_id):
        """Stop producing new segments for a stream (used when a transfer is cancelled)."""
        self._sources.pop(stream_id, None)
        self._queues.pop(stream_id, None)

    def on_packet(self, packet_type, packet_number, flags, payload, now):
        delivered = set()
        if packet_type == TYPE_ACK:
            if self._ack._contains(packet_number):
                return
            largest, _, ranges = decode_ack_payload(payload)
            if not ranges or max(end for _, end in ranges) != largest:
                raise ValueError("invalid ACK ranges")
            delivered = {
                (packet.stream_id, packet.offset)
                for number, packet in (
                    list(self._send._in_flight.items())
                    + list(self._send._lost_packets.items())
                )
                if any(start <= number <= end for start, end in ranges)
            }
        super().on_packet(packet_type, packet_number, flags, payload, now)
        if delivered:
            self._resend = [
                packet for packet in self._resend
                if (packet.stream_id, packet.offset) not in delivered
            ]

    def poll(self, now):
        # The shared poll retransmits the entire queue without consulting cwnd.
        out = []
        self._resend.extend(self._send.on_timer(now))
        while self._resend and self._send.can_send(now):
            lost = self._resend.pop(0)
            out.extend(self._data_packet(packet)
                       for packet in self._send.retransmit([lost], now))
        while not self._resend and self._send.can_send(now):
            segment = self._next_segment()
            if segment is None:
                break
            stream_id, offset, data, fin = segment
            packet = SentPacket(
                self._send.allocate_packet_number(), stream_id, offset, data, fin, now
            )
            self._send.on_data_sent(packet)
            out.append(self._data_packet(packet))
        if self._ack.should_send_ack(now):
            payload = self._ack.build_ack(self.recv_window)
            out.append(OutgoingPacket(TYPE_ACK, self._send.allocate_packet_number(), payload))
        return out

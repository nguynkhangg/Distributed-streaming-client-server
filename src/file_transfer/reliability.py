import bisect
from dataclasses import dataclass

from .packet import encode_ack_payload

ACK_EVERY_DATA_PACKETS = 2
ACK_DELAY = 0.025
PACKET_THRESHOLD = 3
INITIAL_RTO = 1.0
MIN_RTO = 0.2
MAX_RETRANSMISSIONS = 8
FIXED_WINDOW = 16


class ConnectionFailed(Exception):
    """Time out with MAX_RETRANSMISSIONS times => Dead"""


class AckTracker:
    """Storage which packet numbers arrived and decides when to send an ACK"""

    def __init__(self):
        self._ranges = []  # received packet numbers as [start, end] inclusive, sorted and merged
        self._unacked_data = 0
        self._first_unacked_time = None
        self._ack_now = False
    @property
    def largest(self):
        return self._ranges[-1][1] if self._ranges else None

    def on_packet(self, packet_number: int, is_data: bool, now: float) -> bool:
        """
        Record every received packet (DATA + ACK + PING)
        False if packet number was already received
        """
        if self._contains(packet_number):
            if is_data:
                self._ack_now = True
            return False

        gap = self.largest is not None and packet_number != self.largest + 1
        self._insert(packet_number)

        if is_data:
            self._unacked_data += 1
            if self._first_unacked_time is None:
                self._first_unacked_time = now
            if gap:
                self._ack_now = True

        return True

    def should_send_ack(self, now: float) -> bool:
        if self._ack_now:
            return True
        if self._unacked_data == 0:
            return False
        return (
            self._unacked_data >= ACK_EVERY_DATA_PACKETS
            or now - self._first_unacked_time >= ACK_DELAY
        )

    def build_ack(self, recv_window: int) -> bytes:
        """Build the ACK payload and reset the ACK counter """
        self._unacked_data = 0
        self._first_unacked_time = None
        self._ack_now = False
        ranges = []
        for start, end in self._ranges:
            ranges.append((start, end))
        return encode_ack_payload(self.largest, recv_window, ranges)

    def _contains(self, packet_number: int) -> bool:
        i = bisect.bisect_right(self._ranges, [packet_number, float("inf")]) - 1
        return i >= 0 and self._ranges[i][1] >= packet_number

    def _insert(self, packet_number: int) -> None:
        ranges = self._ranges
        i = bisect.bisect_left(ranges, [packet_number, packet_number])
        ranges.insert(i, [packet_number, packet_number])

        if i + 1 < len(ranges) and ranges[i + 1][0] == packet_number + 1:
            ranges[i][1] = ranges[i + 1][1]
            del ranges[i + 1]

        if i > 0 and ranges[i - 1][1] == packet_number - 1:
            ranges[i - 1][1] = ranges[i][1]
            del ranges[i]


@dataclass
class SentPacket:
    packet_number: int
    stream_id: int
    offset: int
    data: bytes
    fin: bool
    sent_time: float
    retransmissions: int = 0


class SendTracker:
    """
    Keeps DATA packet until ACK, detects lost packets
    (3 later packets acknowledged, or RTO expired), and computes the RTO.
    Lost data => resent in a new packet number
    """

    def __init__(self):
        self._next_packet_number = 0
        self._in_flight: dict[int, SentPacket] = {}
        self.peer_window = FIXED_WINDOW
        self.srtt = None
        self.rttvar = None
        self.rto = INITIAL_RTO
        self._acked_numbers = []

    def allocate_packet_number(self) -> int:
        """numbers never reused."""
        packet_number = self._next_packet_number
        self._next_packet_number += 1
        return packet_number

    def can_send(self) -> bool:
        return len(self._in_flight) < max(1,min(FIXED_WINDOW, self.peer_window)) #Tránh deadlock do window_rêcive = 0

    @property
    def in_flight_count(self) -> int:
        return len(self._in_flight)

    def on_data_sent(self, packet: SentPacket) -> None:
        self._in_flight[packet.packet_number] = packet

    def on_ack(self, largest_acked, recv_window, ranges, now):
        """
        Process ACK
        Returns (acked, lost) lists of SentPacket
        ConnectionFailed if reached the retransmission limit
        """
        self.peer_window = recv_window

        acked = []                                         
        for packet_number, packet in self._in_flight.items():    
            found = False
            for start, end in ranges:                             
                if start <= packet_number <= end:                 
                    found = True
                    break                                         
            if found:
                acked.append(packet) 

        for packet in acked:
            del self._in_flight[packet.packet_number]

        newest = max(acked, key=lambda packet: packet.packet_number, default=None)
        if newest is not None and newest.packet_number == largest_acked:
            self._update_rtt(now - newest.sent_time)

        self._acked_numbers.extend(packet.packet_number for packet in acked)

        lost = []
        for packet_number, packet in self._in_flight.items():
            acked_after = sum(1 for number in self._acked_numbers if number > packet_number)
            if acked_after >= PACKET_THRESHOLD:
                lost.append(packet)
        self._declare_lost(lost)

        if self._in_flight:
            oldest = min(self._in_flight)
        else:
            oldest = None

        new_list = []
        for number in self._acked_numbers:
            if oldest is not None and number > oldest:
                new_list.append(number)
        self._acked_numbers = new_list
        return acked, lost

    def on_timer(self, now: float):
        """Return packets when RTO expired"""
        lost = [
            packet for packet in self._in_flight.values()
            if now - packet.sent_time >= self.rto
        ]
        if lost:
            self.rto *= 2 #double when timeout
            self._declare_lost(lost)
        return lost

    def _declare_lost(self, lost) -> None:
        for packet in lost:
            del self._in_flight[packet.packet_number]
            if packet.retransmissions >= MAX_RETRANSMISSIONS:
                raise ConnectionFailed("Retransmission limit reached")

    def _update_rtt(self, sample: float) -> None:
        """RFC 6298: RTO = SRTT + 4 * RTTVAR, at least MIN_RTO."""
        if self.srtt is None:
            self.srtt = sample
            self.rttvar = sample / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
            self.srtt = 0.875 * self.srtt + 0.125 * sample
        self.rto = max(MIN_RTO, self.srtt + 4 * self.rttvar)
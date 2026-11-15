import math
from collections import deque

INITIAL_CWND = 10
MIN_CWND = 2


class CongestionController:
    """Hooks called by SendTracker"""

    cwnd = INITIAL_CWND

    def ready(self, now: float) -> bool:
        """Pacing: False if the next packet must wait"""
        return True

    def on_sent(self, packet, now: float, in_flight: int) -> None:
        """A DATA packet (new or resent) is sent; in_flight is counted before it"""

    def on_acked(self, packets, now: float, srtt, in_flight: int) -> None:
        """packets were acknowledged in one ACK; in_flight is counted after removing them"""

    def on_lost(self, packets, now: float) -> None:
        """packets declared lost because 3 later packets were acknowledged"""

    def on_timeout(self, now: float) -> None:
        """the RTO expired"""


class FixedWindow(CongestionController):
    def __init__(self, size: int = 16):
        self.cwnd = size


class CubicController(CongestionController):
    """
    Slow start: cwnd + 1 per ACKed packet (doubles every RTT) until ssthresh
    After loss: cwnd * 0.7, then grows by W(t) = C * (t - K)^3 + W_max:
    """

    C = 0.4
    BETA = 0.7

    def __init__(self):
        self.window = float(INITIAL_CWND)
        self.ssthresh = math.inf
        self.w_max = 0.0
        self.k = 0.0
        self.epoch_start = None
        self.w_est = 0.0
        self.recovery_start = -math.inf  # packet sent before this time belong to the last loss event

    @property
    def cwnd(self) -> int:
        return max(1, int(self.window))

    def on_acked(self, packets, now, srtt, in_flight):
        if 2 * (in_flight + len(packets)) < self.cwnd:
            return #chưa dùng hết => ko tăng
        for packet in packets:
            if packet.sent_time <= self.recovery_start:
                continue  # gửi trc lần giảm => nghẽn => ko tăng
            if self.window < self.ssthresh:
                self.window += 1
            else:
                self._cubic_increase(now, srtt or 0.0)

    def on_lost(self, packets, now):
        if all(packet.sent_time <= self.recovery_start for packet in packets):
            return  # gói mất trc lần giảm cũ => cùng 1 đợt => ko giảm 
        self.recovery_start = now
        self._reduce()

    def on_timeout(self, now):
        self.recovery_start = now
        self._reduce()
        self.window = 1.0

    def _reduce(self):
        self.epoch_start = None
        if self.window < self.w_max:
            self.w_max = self.window * (1 + self.BETA) / 2  # maybe có stream khác cũng đang hoạt động, chia nó tý
        else:
            self.w_max = self.window
        self.ssthresh = max(self.window * self.BETA, MIN_CWND)
        self.window = self.ssthresh

    def _cubic_increase(self, now, srtt):
        if self.epoch_start is None:
            self.epoch_start = now
            if self.window < self.w_max:
                self.k = ((self.w_max - self.window) / self.C) ** (1 / 3)
            else:
                self.k = 0.0
                self.w_max = self.window
            self.w_est = self.window

        t = now - self.epoch_start
        target = self.C * (t + srtt - self.k) ** 3 + self.w_max  # where cwnd should be one RTT later
        target = min(max(target, self.window), 1.5 * self.window)

        self.w_est += 3 * (1 - self.BETA) / (1 + self.BETA) / self.window  # Reno
        if self.C * (t - self.k) ** 3 + self.w_max < self.w_est:
            self.window = self.w_est
        else:
            self.window += (target - self.window) / self.window



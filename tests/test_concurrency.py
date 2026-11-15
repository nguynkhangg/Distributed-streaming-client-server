"""Hard CSR Concurrency: session locks, backpressure, ordered handling, shutdown."""
from __future__ import annotations

import os
import sys
import threading
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.security import concurrency as conc  # noqa: E402
from src.server.auth import UserStore  # noqa: E402
from src.server.server import CcpServer, PacketType, pack_packet  # noqa: E402
from src.server.session_manager import KEY_SIZE, NONCE_SIZE  # noqa: E402


class TestSessionLock(unittest.TestCase):
    def test_same_key_never_overlaps(self) -> None:
        active = 0
        max_active = 0
        guard = threading.Lock()

        def worker() -> None:
            nonlocal active, max_active
            with conc.session_lock("same"):
                with guard:
                    active += 1
                    max_active = max(max_active, active)
                time.sleep(0.08)
                with guard:
                    active -= 1

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)
        self.assertEqual(max_active, 1)

    def test_different_keys_can_overlap(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        overlapped = threading.Event()

        def hold_a() -> None:
            with conc.session_lock("a"):
                entered.set()
                release.wait(timeout=2.0)

        def try_b() -> None:
            entered.wait(timeout=2.0)
            with conc.session_lock("b"):
                overlapped.set()
                release.set()

        t1 = threading.Thread(target=hold_a)
        t2 = threading.Thread(target=try_b)
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)
        self.assertTrue(overlapped.is_set())


class TestBackpressure(unittest.TestCase):
    def tearDown(self) -> None:
        conc.shutdown_workers(wait=True)
        conc._MAX_PENDING = 256

    def test_submit_drops_when_queue_full(self) -> None:
        conc.shutdown_workers(wait=True)
        conc._MAX_PENDING = 2
        gate = threading.Event()
        started = threading.Event()

        def blocker(_data: bytes, _addr: tuple) -> None:
            started.set()
            gate.wait(timeout=2.0)

        self.assertTrue(conc.submit_datagram(blocker, b"a", ("127.0.0.1", 1)))
        self.assertTrue(conc.submit_datagram(blocker, b"b", ("127.0.0.1", 2)))
        started.wait(timeout=1.0)
        time.sleep(0.05)
        self.assertFalse(conc.submit_datagram(blocker, b"c", ("127.0.0.1", 3)))
        gate.set()


class TestSameSessionOrdering(unittest.TestCase):
    def setUp(self) -> None:
        self.server = CcpServer("127.0.0.1", 0, users=UserStore())
        self.addr = ("127.0.0.1", 40222)

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_handlers_for_same_connection_do_not_interleave(self) -> None:
        result = self.server._sessions.get_or_create_session(
            self.addr, bytes(KEY_SIZE), bytes(NONCE_SIZE)
        )
        session = result.session
        active = 0
        max_active = 0
        guard = threading.Lock()

        def spy(_sess, _payload) -> None:
            nonlocal active, max_active
            with guard:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.08)
            with guard:
                active -= 1

        self.server._handlers[PacketType.PING] = spy

        def send_pn(pn: int) -> None:
            raw = pack_packet(PacketType.PING, session.connection_id, pn, b"", flags=0)
            self.server._handle_datagram(raw, self.addr)

        t1 = threading.Thread(target=send_pn, args=(1,))
        t2 = threading.Thread(target=send_pn, args=(2,))
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)
        self.assertEqual(max_active, 1)
        self.assertEqual(session.last_recv_pn, 2)


class TestServerShutdown(unittest.TestCase):
    def test_shutdown_closes_socket_and_is_idempotent(self) -> None:
        server = CcpServer("127.0.0.1", 0, users=UserStore())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)
        server.shutdown()
        thread.join(timeout=2.0)
        # Socket should be unusable after close.
        with self.assertRaises(OSError):
            server._sock.sendto(b"x", ("127.0.0.1", 9))
        server.shutdown()  # second call must not raise
        conc.shutdown_workers(wait=True)


if __name__ == "__main__":
    unittest.main()

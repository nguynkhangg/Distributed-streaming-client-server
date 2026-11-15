"""Hard CSR Resilience: invalid packets, contained errors, expiry, disconnect."""
from __future__ import annotations

import errno
import os
import sys
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.security.resilience import (  # noqa: E402
    ActiveTransferRegistry,
    NetworkErrorClass,
    classify_network_error,
)
from src.server.auth import UserStore  # noqa: E402
from src.server.server import CcpServer, PacketType, pack_packet  # noqa: E402
from src.server.session_manager import (  # noqa: E402
    AUTH_DEADLINE,
    KEY_SIZE,
    NONCE_SIZE,
    SessionManager,
    SessionState,
)


class TestInvalidPacketsContained(unittest.TestCase):
    def setUp(self) -> None:
        self.server = CcpServer("127.0.0.1", 0, users=UserStore())
        self.addr = ("127.0.0.1", 40333)

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_garbage_and_bad_magic_do_not_raise(self) -> None:
        self.server._handle_datagram_safe(b"\x00\x01\x02", self.addr)
        bad_magic = pack_packet(PacketType.PING, 1, 1, b"")
        bad_magic = b"\x11\x11" + bad_magic[2:]
        self.server._handle_datagram_safe(bad_magic, self.addr)

    def test_handler_exception_is_contained(self) -> None:
        result = self.server._sessions.get_or_create_session(
            self.addr, bytes(KEY_SIZE), bytes(NONCE_SIZE)
        )
        session = result.session

        def boom(_sess, _payload) -> None:
            raise RuntimeError("client-specific failure")

        self.server._handlers[PacketType.PING] = boom
        raw = pack_packet(PacketType.PING, session.connection_id, 1, b"", flags=0)
        # Safe wrapper must swallow handler exceptions.
        self.server._handle_datagram_safe(raw, self.addr)
        # Server still usable for a later packet.
        seen = {"ok": False}

        def spy(_sess, _payload) -> None:
            seen["ok"] = True

        self.server._handlers[PacketType.PING] = spy
        self.server._handle_datagram(
            pack_packet(PacketType.PING, session.connection_id, 2, b"", flags=0),
            self.addr,
        )
        self.assertTrue(seen["ok"])


class TestSessionExpiryAndDisconnect(unittest.TestCase):
    def test_find_expired_auth_deadline(self) -> None:
        mgr = SessionManager()
        result = mgr.get_or_create_session(
            ("127.0.0.1", 9), bytes(KEY_SIZE), bytes(NONCE_SIZE)
        )
        session = result.session
        self.assertEqual(session.state, SessionState.ESTABLISHED)
        now = time.monotonic()
        session.created_at = now - (AUTH_DEADLINE + 1.0)
        session.last_recv = now  # not heartbeat-idle
        expired = mgr.find_expired(now)
        self.assertIn(session, expired)

    def test_sweep_closes_expired_session(self) -> None:
        server = CcpServer("127.0.0.1", 0, users=UserStore())
        try:
            addr = ("127.0.0.1", 40334)
            result = server._sessions.get_or_create_session(
                addr, bytes(KEY_SIZE), bytes(NONCE_SIZE)
            )
            session = result.session
            cid = session.connection_id
            now = time.monotonic()
            session.created_at = now - (AUTH_DEADLINE + 1.0)
            session.last_recv = now
            server._sweep_once()
            self.assertIsNone(server._sessions.lookup(cid, addr))
            self.assertNotIn(cid, {s.connection_id for s in server._sessions.all_sessions()})
        finally:
            server.shutdown()

    def test_remove_session_clears_keys(self) -> None:
        mgr = SessionManager()
        result = mgr.get_or_create_session(
            ("127.0.0.1", 10), bytes(KEY_SIZE), bytes(NONCE_SIZE)
        )
        session = result.session
        session.key_c2s = b"\x01" * 32
        session.key_s2c = b"\x02" * 32
        removed = mgr.remove_session(session.connection_id)
        self.assertIsNotNone(removed)
        self.assertIsNone(session.key_c2s)
        self.assertIsNone(session.key_s2c)

    def test_active_transfer_cancel_on_disconnect(self) -> None:
        reg = ActiveTransferRegistry()
        reg.register("f1", 42, peer="alice")
        reg.register("f2", 42, peer="alice")
        cancelled = reg.cancel_for_connection(42)
        self.assertEqual(sorted(r.transfer_id for r in cancelled), ["f1", "f2"])
        self.assertEqual(len(reg), 0)


class TestClassifyNetworkError(unittest.TestCase):
    def test_classes(self) -> None:
        self.assertEqual(
            classify_network_error(TimeoutError()), NetworkErrorClass.TIMEOUT
        )
        self.assertEqual(
            classify_network_error(ConnectionResetError()), NetworkErrorClass.RESET
        )
        self.assertEqual(
            classify_network_error(OSError(errno.EHOSTUNREACH, "gone")),
            NetworkErrorClass.UNREACHABLE,
        )


if __name__ == "__main__":
    unittest.main()

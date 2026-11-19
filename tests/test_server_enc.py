"""ENC dispatcher edge cases on CcpServer (CSR drop paths)."""
from __future__ import annotations

import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.server.server import (  # noqa: E402
    FLAG_ENC,
    GCM_TAG_SIZE,
    CcpServer,
    PacketHeader,
    PacketType,
    pack_packet,
)
from src.server.session_manager import KEY_SIZE, NONCE_SIZE  # noqa: E402


class TestServerEncBeforeKeys(unittest.TestCase):
    def setUp(self) -> None:
        self.server = CcpServer("127.0.0.1", 0, require_encryption=False)   # these tests send a HELLO without a key
        self.addr = ("127.0.0.1", 54321)

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_enc_before_keys_is_dropped(self) -> None:
        hello = PacketHeader(PacketType.HELLO, 0, 0, 0)
        self.server._on_hello(hello, b"", self.addr)

        result = self.server._sessions.get_or_create_session(
            self.addr, bytes(KEY_SIZE), bytes(NONCE_SIZE)
        )
        self.assertFalse(result.is_new)
        session = result.session
        self.assertIsNotNone(session.key_c2s)

        session.key_c2s = None
        session.key_s2c = None
        last_recv = session.last_recv
        pinged = {"called": False}
        original_ping = self.server._on_ping

        def spy_ping(sess, payload):
            pinged["called"] = True
            return original_ping(sess, payload)

        self.server._handlers[PacketType.PING] = spy_ping

        fake_gcm = b"\x00" * GCM_TAG_SIZE
        raw = pack_packet(
            PacketType.PING,
            session.connection_id,
            1,
            fake_gcm,
            flags=FLAG_ENC,
        )
        self.server._handle_datagram(raw, self.addr)

        self.assertFalse(pinged["called"])
        self.assertEqual(session.last_recv, last_recv)


if __name__ == "__main__":
    unittest.main()

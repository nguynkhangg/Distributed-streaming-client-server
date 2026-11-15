"""Hard CSR Security: X25519/HKDF/GCM, ENC policy, anti-replay, key cleanup."""
from __future__ import annotations

import os
import secrets
import struct
import sys
import threading
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.client.network import CcpClient, ConnectionState  # noqa: E402
from src.common.exceptions import HandshakeTimeoutError  # noqa: E402
from src.security.encryption import (  # noqa: E402
    DIR_C2S,
    DIR_S2C,
    CryptoError,
    derive_session_keys,
    generate_x25519_keypair,
    open as gcm_open,
    seal,
    x25519_shared_secret,
)
from src.server.auth import UserStore  # noqa: E402
from src.server.server import (  # noqa: E402
    FLAG_ENC,
    GCM_TAG_SIZE,
    CcpServer,
    PacketHeader,
    PacketType,
    pack_packet,
)
from src.server.session_manager import KEY_SIZE, NONCE_SIZE  # noqa: E402


def _header(payload_len: int = 0, flags: int = FLAG_ENC) -> bytes:
    return struct.pack("!HBBBBIIH", 0xA5C3, 1, 3, flags, 0, 1, 7, payload_len)


class TestCryptoPrimitives(unittest.TestCase):
    def test_x25519_ecdh_symmetric_and_session_keys(self) -> None:
        priv_c, pub_c = generate_x25519_keypair()
        priv_s, pub_s = generate_x25519_keypair()
        shared_a = x25519_shared_secret(priv_c, pub_s)
        shared_b = x25519_shared_secret(priv_s, pub_c)
        self.assertEqual(shared_a, shared_b)
        c2s, s2c = derive_session_keys(shared_a, b"\x01" * 16, b"\x02" * 16)
        self.assertEqual(len(c2s), 32)
        self.assertEqual(len(s2c), 32)
        self.assertNotEqual(c2s, s2c)

    def test_gcm_roundtrip(self) -> None:
        priv_c, pub_c = generate_x25519_keypair()
        priv_s, pub_s = generate_x25519_keypair()
        shared = x25519_shared_secret(priv_c, pub_s)
        c2s, s2c = derive_session_keys(shared, b"\xaa" * 16, b"\xbb" * 16)
        plain = b"hard-gcm"
        header = _header(len(plain) + 16)
        blob = seal(c2s, 9, header, plain, direction=DIR_C2S)
        self.assertEqual(gcm_open(c2s, 9, header, blob, direction=DIR_C2S), plain)

    def test_gcm_wrong_key_direction_aad_tag(self) -> None:
        priv_c, pub_c = generate_x25519_keypair()
        priv_s, pub_s = generate_x25519_keypair()
        shared = x25519_shared_secret(priv_c, pub_s)
        c2s, s2c = derive_session_keys(shared, b"\x11" * 16, b"\x22" * 16)
        plain = b"secret"
        header = _header(len(plain) + 16)
        blob = seal(c2s, 1, header, plain, direction=DIR_C2S)

        with self.assertRaises(CryptoError):
            gcm_open(s2c, 1, header, blob, direction=DIR_C2S)
        with self.assertRaises(CryptoError):
            gcm_open(c2s, 1, header, blob, direction=DIR_S2C)
        bad_aad = _header(len(plain) + 16, flags=FLAG_ENC | 0x01)
        with self.assertRaises(CryptoError):
            gcm_open(c2s, 1, bad_aad, blob, direction=DIR_C2S)
        with self.assertRaises(CryptoError):
            gcm_open(c2s, 1, header, blob[:-1], direction=DIR_C2S)


class TestEncPolicyAndReplay(unittest.TestCase):
    def setUp(self) -> None:
        self.server = CcpServer("127.0.0.1", 0, users=UserStore())
        self.addr = ("127.0.0.1", 40111)

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_enc_before_keys_and_plaintext_after_hello_dropped(self) -> None:
        hello = PacketHeader(PacketType.HELLO, 0, 0, 0)
        _priv, pub = generate_x25519_keypair()
        nonce = secrets.token_bytes(NONCE_SIZE)
        self.server._on_hello(hello, pub + nonce, self.addr)
        result = self.server._sessions.get_or_create_session(self.addr, pub, nonce)
        session = result.session
        self.assertTrue(session.use_encryption)
        self.assertIsNotNone(session.key_c2s)

        called = {"n": 0}

        def spy(_sess, _payload):
            called["n"] += 1

        self.server._handlers[PacketType.PING] = spy

        # Plaintext after keys must be dropped.
        self.server._handle_datagram(
            pack_packet(PacketType.PING, session.connection_id, 1, b"", flags=0),
            self.addr,
        )
        self.assertEqual(called["n"], 0)

        # ENC with keys cleared must be dropped.
        session.key_c2s = None
        session.key_s2c = None
        fake = b"\x00" * GCM_TAG_SIZE
        self.server._handle_datagram(
            pack_packet(
                PacketType.PING, session.connection_id, 2, fake, flags=FLAG_ENC
            ),
            self.addr,
        )
        self.assertEqual(called["n"], 0)

    def test_replay_and_older_pn_dropped(self) -> None:
        result = self.server._sessions.get_or_create_session(
            self.addr, bytes(KEY_SIZE), bytes(NONCE_SIZE)
        )
        session = result.session
        calls: list[int] = []

        def spy(sess, _payload):
            calls.append(sess.last_recv_pn)

        self.server._handlers[PacketType.PING] = spy
        raw = pack_packet(PacketType.PING, session.connection_id, 7, b"", flags=0)
        self.server._handle_datagram(raw, self.addr)
        self.server._handle_datagram(raw, self.addr)  # replay
        self.server._handle_datagram(
            pack_packet(PacketType.PING, session.connection_id, 6, b"", flags=0),
            self.addr,
        )
        self.assertEqual(calls, [7])
        self.assertEqual(session.last_recv_pn, 7)


class TestLiveHandshakeAndKeyCleanup(unittest.TestCase):
    def setUp(self) -> None:
        self.server = CcpServer("127.0.0.1", 0, users=UserStore())
        self.port = self.server.address[1]
        self._thread = threading.Thread(
            target=self.server.serve_forever, name="csr-sec-srv", daemon=True
        )
        self._thread.start()
        time.sleep(0.05)

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_hello_keys_and_encrypted_ping(self) -> None:
        client = CcpClient("127.0.0.1", self.port, receive_timeout=1.0)
        try:
            cid = client.connect()
            self.assertNotEqual(cid, 0)
            self.assertEqual(client.state, ConnectionState.ESTABLISHED)
            self.assertIsNotNone(client.key_c2s)
            self.assertIsNotNone(client.key_s2c)
            self.assertTrue(client.ping())
        finally:
            client.shutdown()

    def test_handshake_timeout_clears_keys(self) -> None:
        client = CcpClient(
            "127.0.0.1",
            1,  # nothing listening
            receive_timeout=0.05,
            hello_attempts=1,
            hello_retry_interval=0,
        )
        try:
            with self.assertRaises(HandshakeTimeoutError):
                client.connect()
            self.assertIsNone(client.key_c2s)
            self.assertIsNone(client.key_s2c)
            self.assertEqual(client.state, ConnectionState.DISCONNECTED)
        finally:
            client.shutdown()


if __name__ == "__main__":
    unittest.main()

"""Unit tests for src.security.encryption (shared CSR crypto API)."""
from __future__ import annotations

import os
import struct
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

from security.encryption import (  # noqa: E402
    DIR_C2S,
    DIR_S2C,
    CryptoError,
    derive_keys,
    derive_session_keys,
    generate_x25519_keypair,
    open as gcm_open,
    seal,
    x25519_shared_secret,
)


def _dummy_header(payload_len: int = 0, flags: int = 0) -> bytes:
    return struct.pack("!HBBBBIIH", 0xA5C3, 1, 3, flags, 0, 1, 7, payload_len)


class TestEncryption(unittest.TestCase):
    def test_roundtrip(self):
        c2s, s2c = derive_keys(b"\x01" * 32, b"\x02" * 32, b"\x03" * 16, b"\x04" * 16)
        plain = b"hello-ccp"
        header = _dummy_header(len(plain) + 16, flags=0x02)
        blob = seal(s2c, 7, header, plain, direction=DIR_S2C)
        self.assertEqual(gcm_open(s2c, 7, header, blob, direction=DIR_S2C), plain)

    def test_wrong_key_fails(self):
        c2s, s2c = derive_keys(b"\x01" * 32, b"\x02" * 32, b"\x03" * 16, b"\x04" * 16)
        other, _ = derive_keys(b"\xff" * 32, b"\x02" * 32, b"\x03" * 16, b"\x04" * 16)
        plain = b"secret"
        header = _dummy_header(len(plain) + 16, flags=0x02)
        blob = seal(c2s, 1, header, plain, direction=DIR_C2S)
        with self.assertRaises(CryptoError):
            gcm_open(other, 1, header, blob, direction=DIR_C2S)

    def test_empty_plaintext(self):
        c2s, s2c = derive_keys(b"\x11" * 32, b"\x22" * 32, b"\x33" * 16, b"\x44" * 16)
        header = _dummy_header(16, flags=0x02)
        blob = seal(s2c, 0, header, b"", direction=DIR_S2C)
        self.assertEqual(gcm_open(s2c, 0, header, blob, direction=DIR_S2C), b"")

    def test_derive_keys_distinct_directions(self):
        c2s, s2c = derive_keys(b"\xaa" * 32, b"\xbb" * 32, b"\xcc" * 16, b"\xdd" * 16)
        self.assertEqual(len(c2s), 32)
        self.assertEqual(len(s2c), 32)
        self.assertNotEqual(c2s, s2c)

    def test_x25519_shared_secret_symmetric(self):
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()
        self.assertEqual(
            x25519_shared_secret(priv_a, pub_b),
            x25519_shared_secret(priv_b, pub_a),
        )

    def test_x25519_session_keys_seal_roundtrip(self):
        priv_c, pub_c = generate_x25519_keypair()
        priv_s, pub_s = generate_x25519_keypair()
        shared = x25519_shared_secret(priv_c, pub_s)
        self.assertEqual(shared, x25519_shared_secret(priv_s, pub_c))
        c2s, s2c = derive_session_keys(shared, b"\x01" * 16, b"\x02" * 16)
        plain = b"ecdh-hello"
        header = _dummy_header(len(plain) + 16, flags=0x02)
        blob = seal(s2c, 3, header, plain, direction=DIR_S2C)
        self.assertEqual(gcm_open(s2c, 3, header, blob, direction=DIR_S2C), plain)
        self.assertEqual(len(c2s), 32)

    def test_short_blob_raises_crypto_error(self):
        c2s, s2c = derive_keys(b"\x01" * 32, b"\x02" * 32, b"\x03" * 16, b"\x04" * 16)
        plain = b"short-blob"
        header = _dummy_header(len(plain) + 16, flags=0x02)
        blob = seal(s2c, 2, header, plain, direction=DIR_S2C)
        with self.assertRaises(CryptoError):
            gcm_open(s2c, 2, header, blob[:-1], direction=DIR_S2C)

    def test_tampered_aad_fails(self):
        c2s, s2c = derive_keys(b"\x01" * 32, b"\x02" * 32, b"\x03" * 16, b"\x04" * 16)
        plain = b"aad-check"
        header_a = _dummy_header(len(plain) + 16, flags=0x02)
        header_b = _dummy_header(len(plain) + 16, flags=0x03)
        blob = seal(c2s, 5, header_a, plain, direction=DIR_C2S)
        with self.assertRaises(CryptoError):
            gcm_open(c2s, 5, header_b, blob, direction=DIR_C2S)

    def test_x25519_bad_key_length(self):
        priv, pub = generate_x25519_keypair()
        with self.assertRaises(ValueError):
            x25519_shared_secret(priv[:31], pub)
        with self.assertRaises(ValueError):
            x25519_shared_secret(priv, pub[:31])


if __name__ == "__main__":
    unittest.main()

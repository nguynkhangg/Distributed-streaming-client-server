"""X25519 + HKDF + AES-256-GCM (protocol-spec §12)."""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32
GCM_TAG_SIZE = 16
DIR_C2S = 0
DIR_S2C = 1


class CryptoError(ValueError):
    """Bad key material or GCM auth failure."""


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def new_keypair() -> tuple[bytes, bytes]:
    return generate_x25519_keypair()


def derive_keys(
    private_raw: bytes,
    peer_public: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> tuple[bytes, bytes]:
    """ECDH + HKDF → (key_c2s, key_s2c)."""
    if len(private_raw) != KEY_SIZE or len(peer_public) != KEY_SIZE:
        raise CryptoError("X25519 keys must be 32 bytes")
    try:
        shared = X25519PrivateKey.from_private_bytes(private_raw).exchange(
            X25519PublicKey.from_public_bytes(peer_public)
        )
    except ValueError as exc:
        raise CryptoError(str(exc)) from exc
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=client_nonce + server_nonce,
        info=b"ccp-session-keys",
    ).derive(shared)
    return okm[:KEY_SIZE], okm[KEY_SIZE:]


def _nonce(direction: int, packet_number: int) -> bytes:
    return bytes([direction, 0, 0, 0]) + struct.pack("!Q", packet_number)


def seal(
    key: bytes, packet_number: int, header16: bytes, plaintext: bytes, *, direction: int
) -> bytes:
    return AESGCM(key).encrypt(_nonce(direction, packet_number), plaintext, header16)


def open(
    key: bytes, packet_number: int, header16: bytes, blob: bytes, *, direction: int
) -> bytes:
    try:
        return AESGCM(key).decrypt(_nonce(direction, packet_number), blob, header16)
    except InvalidTag as exc:
        raise CryptoError("GCM authentication failed") from exc

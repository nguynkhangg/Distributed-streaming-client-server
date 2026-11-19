"""Shared X25519 + AES-256-GCM + HKDF helpers (protocol-spec §12).

Other modules (server, client, auth, messaging, file) should import from here
instead of inventing their own crypto. HELLO stays plaintext; ENC payloads use seal/open.

Preferred HELLO path: generate_x25519_keypair → x25519_shared_secret → derive_session_keys.
derive_keys(...) remains as a compat fallback for all-zero / placeholder HELLO.
"""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32
GCM_TAG_SIZE = 16
DIR_C2S = 0  # client → server
DIR_S2C = 1  # server → client


class CryptoError(ValueError):
    """Authentication/decryption failed; caller should drop the packet."""


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Return (private_raw_32, public_raw_32) for HELLO / HELLO_ACK."""
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes_raw()
    public_raw = private.public_key().public_bytes_raw()
    return private_raw, public_raw


def x25519_shared_secret(private_raw: bytes, peer_public_raw: bytes) -> bytes:
    """ECDH shared secret (32 bytes) from local private + peer public."""
    if len(private_raw) != KEY_SIZE or len(peer_public_raw) != KEY_SIZE:
        raise ValueError("X25519 keys must be 32 bytes")
    private = X25519PrivateKey.from_private_bytes(private_raw)
    peer = X25519PublicKey.from_public_bytes(peer_public_raw)
    return private.exchange(peer)


def derive_session_keys(
    shared_secret: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> tuple[bytes, bytes]:
    """HKDF-SHA256 over ECDH shared secret → (key_c2s, key_s2c)."""
    if len(shared_secret) != KEY_SIZE:
        raise ValueError("shared_secret must be 32 bytes")
    salt = client_nonce + server_nonce
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=salt,
        info=b"ccp-session-keys",
    ).derive(shared_secret)
    return okm[:KEY_SIZE], okm[KEY_SIZE:]


def derive_keys(
    client_material: bytes,
    server_material: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> tuple[bytes, bytes]:
    """Compat fallback when HELLO has no real X25519 keys (dev / empty payload).

    salt = client_nonce || server_nonce (spec §12).
    ikm  = client_material || server_material.
    Prefer derive_session_keys after x25519_shared_secret for production HELLO.
    """
    salt = client_nonce + server_nonce
    ikm = client_material + server_material
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=salt,
        info=b"ccp-session-keys",
    ).derive(ikm)
    return okm[:KEY_SIZE], okm[KEY_SIZE:]


def _gcm_nonce(direction: int, packet_number: int) -> bytes:
    """12-byte nonce: 1 byte direction, 3 zero bytes, 8 bytes packet number."""
    if direction not in (DIR_C2S, DIR_S2C):
        raise ValueError("direction must be DIR_C2S or DIR_S2C")
    if not 0 <= packet_number <= 0xFFFFFFFF:
        raise ValueError("packet_number out of range")
    return bytes([direction, 0, 0, 0]) + struct.pack("!Q", packet_number)


def seal(
    key: bytes,
    packet_number: int,
    header16: bytes,
    plaintext: bytes,
    *,
    direction: int,
) -> bytes:
    """Encrypt plaintext; AAD = 16-byte CCP header. Returns ciphertext||tag."""
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")
    if len(header16) != 16:
        raise ValueError("header16 must be 16 bytes")
    return AESGCM(key).encrypt(
        _gcm_nonce(direction, packet_number), plaintext, header16
    )


def open(
    key: bytes,
    packet_number: int,
    header16: bytes,
    blob: bytes,
    *,
    direction: int,
) -> bytes:
    """Decrypt blob; raise CryptoError if the tag does not verify."""
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")
    if len(header16) != 16:
        raise ValueError("header16 must be 16 bytes")
    try:
        return AESGCM(key).decrypt(
            _gcm_nonce(direction, packet_number), blob, header16
        )
    except InvalidTag as exc:
        raise CryptoError("GCM authentication failed") from exc

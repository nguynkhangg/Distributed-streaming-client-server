"""Integration tests for both sides of the CCP handshake."""

from __future__ import annotations

import itertools
import secrets
import socket
import struct
import threading
import time
import unittest

from src.client.network import CcpClient, ConnectionState
from src.security.encryption import (
    DIR_C2S,
    KEY_SIZE,
    derive_keys,
    generate_x25519_keypair,
    seal,
)
from src.server.server import CcpServer


HEADER = struct.Struct("!HBBBBIIH")
MAGIC = 0xA5C3
VERSION = 1
HELLO = 0x01
HELLO_ACK = 0x02
PING = 0x05
PONG = 0x06
CLOSE = 0x07
FLAG_ENC = 0x02
NONCE_SIZE = 16


def build_packet(packet_type, connection_id, packet_number, payload=b"", flags=0):
    return HEADER.pack(
        MAGIC, VERSION, packet_type, flags, 0, connection_id, packet_number,
        len(payload),
    ) + payload


def build_enc_packet(packet_type, connection_id, packet_number, key_c2s, payload=b""):
    sealed_len = len(payload) + 16
    header16 = HEADER.pack(
        MAGIC, VERSION, packet_type, FLAG_ENC, 0, connection_id, packet_number, sealed_len
    )
    return header16 + seal(key_c2s, packet_number, header16, payload, direction=DIR_C2S)


def parse_packet(data):
    magic, version, packet_type, _, _, connection_id, _, length = \
        HEADER.unpack(data[:HEADER.size])
    if magic != MAGIC or version != VERSION:
        raise AssertionError("invalid magic or version")
    if length != len(data) - HEADER.size:
        raise AssertionError("payload length mismatch")
    return packet_type, connection_id, data[HEADER.size:]


def unused_local_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class HandshakeIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = unused_local_port()
        cls.server = CcpServer("127.0.0.1", cls.port)
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            name="ccp-test-server",
            daemon=True,
        )
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join(timeout=2)

    def expect_packet(self, sock, wanted_type, wait=2):
        sock.settimeout(wait)
        while True:
            packet_type, connection_id, payload = parse_packet(sock.recvfrom(2048)[0])
            if packet_type == wanted_type:
                return connection_id, payload
            self.assertEqual(packet_type, PING, "unexpected CCP packet type")

    def expect_silence(self, sock, wait=0.5):
        sock.settimeout(wait)
        try:
            sock.recvfrom(2048)
        except socket.timeout:
            return
        self.fail("server unexpectedly answered the packet")

    def test_manual_wire_client_handshake_server(self):
        server_address = ("127.0.0.1", self.port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packet_numbers = itertools.count(1)
        sock.settimeout(2)

        private, public = generate_x25519_keypair()
        client_nonce = secrets.token_bytes(NONCE_SIZE)
        key_c2s = None

        def send_plain(packet_type, connection_id, payload=b"", destination=sock):
            destination.sendto(
                build_packet(packet_type, connection_id, next(packet_numbers), payload),
                server_address,
            )

        def send_enc(packet_type, connection_id, payload=b"", destination=sock):
            destination.sendto(
                build_enc_packet(
                    packet_type, connection_id, next(packet_numbers), key_c2s, payload
                ),
                server_address,
            )

        try:
            send_plain(HELLO, 0, public + client_nonce)
            connection_id, payload = self.expect_packet(sock, HELLO_ACK)
            self.assertNotEqual(connection_id, 0)
            self.assertEqual(len(payload), KEY_SIZE + NONCE_SIZE)
            server_pub, server_nonce = payload[:KEY_SIZE], payload[KEY_SIZE:]
            key_c2s, _key_s2c = derive_keys(
                private, server_pub, client_nonce, server_nonce
            )

            send_plain(HELLO, 0, public + client_nonce)  # same pubkey+nonce → retransmission
            retransmitted_id, _ = self.expect_packet(sock, HELLO_ACK)
            self.assertEqual(retransmitted_id, connection_id)

            send_enc(PING, connection_id)
            self.expect_packet(sock, PONG)

            # Plaintext after HELLO must be ignored; ENC still works.
            send_plain(PING, connection_id)
            send_enc(PING, connection_id)
            self.expect_packet(sock, PONG)

            other.sendto(
                build_packet(PING, connection_id, next(packet_numbers)),
                server_address,
            )
            self.expect_silence(other)

            send_enc(CLOSE, connection_id, b"\x00")
            time.sleep(0.1)
            send_enc(PING, connection_id)
            self.expect_silence(sock)
        finally:
            sock.close()
            other.close()

    def test_ccp_client_handshake_server(self):
        client = CcpClient("127.0.0.1", self.port, receive_timeout=2)
        try:
            connection_id = client.connect()
            self.assertNotEqual(connection_id, 0)
            self.assertEqual(client.connection_id, connection_id)
            self.assertEqual(client.state, ConnectionState.ESTABLISHED)
            self.assertTrue(client.ping())
        finally:
            client.shutdown()

        self.assertEqual(client.connection_id, 0)
        self.assertEqual(client.state, ConnectionState.DISCONNECTED)


if __name__ == "__main__":
    unittest.main()

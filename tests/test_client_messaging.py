"""UDP tests for CCP client handshake and messaging over ECDH/ENC."""

from __future__ import annotations

import json
import secrets
import socket
import struct
import threading
import unittest

from src.client.client import Client
from src.client.network import CcpClient
from src.common.constants import MAGIC, VERSION, PacketFlag, PacketType
from src.security.encryption import (
    DIR_C2S,
    DIR_S2C,
    GCM_TAG_SIZE,
    KEY_SIZE,
    CryptoError,
    derive_keys,
    generate_x25519_keypair,
    open as gcm_open,
    seal,
)

HEADER = struct.Struct("!HBBBBIIH")
STREAM_HEADER = struct.Struct("!IQ")
FRAME_LENGTH = struct.Struct("!I")
NONCE_SIZE = 16
FLAG_ENC = PacketFlag.ENC


class EncryptedTestPeer:
    """CCP test peer with real X25519 HELLO and AES-GCM ENC."""

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.address = self.socket.getsockname()
        self.stop_event = threading.Event()
        # conn_id -> (addr, username, key_c2s, key_s2c)
        self.sessions: dict[int, tuple] = {}
        self.next_connection_id = 100
        self.next_server_packet_number = 1
        self.stream_offsets: dict[tuple[int, int], int] = {}   # (connection, stream) -> next offset
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _send_raw(self, addr: tuple[str, int], packet: bytes) -> None:
        self.socket.sendto(packet, addr)

    def _send(
        self,
        addr: tuple[str, int],
        packet_type: PacketType,
        connection_id: int,
        payload: bytes = b"",
        *,
        key_s2c: bytes | None = None,
    ) -> None:
        pn = self.next_server_packet_number
        self.next_server_packet_number += 1
        if key_s2c is not None and packet_type not in (
            PacketType.HELLO,
            PacketType.HELLO_ACK,
        ):
            length = len(payload) + GCM_TAG_SIZE
            header = HEADER.pack(
                MAGIC, VERSION, int(packet_type), FLAG_ENC, 0, connection_id, pn, length
            )
            packet = header + seal(key_s2c, pn, header, payload, direction=DIR_S2C)
        else:
            packet = HEADER.pack(
                MAGIC,
                VERSION,
                int(packet_type),
                0,
                0,
                connection_id,
                pn,
                len(payload),
            ) + payload
        self._send_raw(addr, packet)

    def _send_message(
        self,
        addr: tuple[str, int],
        connection_id: int,
        message_type: str,
        payload: dict,
        request_id: str,
        key_s2c: bytes,
    ) -> None:
        message = json.dumps(
            {
                "type": message_type,
                "payload": payload,
                "id": request_id,
                "version": 1,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        frame = FRAME_LENGTH.pack(len(message)) + message
        stream_id = 0 if message_type != "MSG_DELIVER" else 1
        offset = self.stream_offsets.get((connection_id, stream_id), 0)
        self.stream_offsets[(connection_id, stream_id)] = offset + len(frame)
        self._send(
            addr,
            PacketType.DATA,
            connection_id,
            STREAM_HEADER.pack(stream_id, offset) + frame,
            key_s2c=key_s2c,
        )

    def _serve(self) -> None:
        self.socket.settimeout(0.1)
        while not self.stop_event.is_set():
            try:
                data, addr = self.socket.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    return
                raise
            if len(data) < HEADER.size:
                continue
            magic, version, raw_type, flags, _reserved, conn_id, pn, length = (
                HEADER.unpack(data[: HEADER.size])
            )
            if magic != MAGIC or version != VERSION or length != len(data) - HEADER.size:
                continue
            payload = data[HEADER.size :]
            packet_type = PacketType(raw_type)

            if packet_type == PacketType.HELLO:
                if len(payload) != KEY_SIZE + NONCE_SIZE:
                    continue
                client_pub, client_nonce = payload[:KEY_SIZE], payload[KEY_SIZE:]
                server_priv, server_pub = generate_x25519_keypair()
                server_nonce = secrets.token_bytes(NONCE_SIZE)
                key_c2s, key_s2c = derive_keys(
                    server_priv, client_pub, client_nonce, server_nonce
                )
                conn_id = self.next_connection_id
                self.next_connection_id += 1
                self.sessions[conn_id] = (addr, None, key_c2s, key_s2c)
                self._send(
                    addr, PacketType.HELLO_ACK, conn_id, server_pub + server_nonce
                )
                continue

            if conn_id not in self.sessions:
                continue
            peer_addr, username, key_c2s, key_s2c = self.sessions[conn_id]

            if flags & FLAG_ENC:
                try:
                    payload = gcm_open(
                        key_c2s, pn, data[: HEADER.size], payload, direction=DIR_C2S
                    )
                except CryptoError:
                    continue
            elif packet_type not in (PacketType.HELLO, PacketType.HELLO_ACK):
                continue

            if packet_type == PacketType.PING:
                self._send(addr, PacketType.PONG, conn_id, key_s2c=key_s2c)
                continue
            if packet_type == PacketType.CLOSE:
                self.sessions.pop(conn_id, None)
                continue
            if packet_type != PacketType.DATA:
                continue

            stream_id, _offset = STREAM_HEADER.unpack(payload[: STREAM_HEADER.size])
            framed = payload[STREAM_HEADER.size :]
            (frame_length,) = FRAME_LENGTH.unpack(framed[: FRAME_LENGTH.size])
            message = json.loads(
                framed[FRAME_LENGTH.size : FRAME_LENGTH.size + frame_length]
            )
            body = message["payload"]
            msg_type = message["type"]
            request_id = message["id"]

            if stream_id == 0 and msg_type == "AUTH":
                if body["password"] != f"{body['username']}-test-password":
                    response = {
                        "success": False,
                        "username": None,
                        "error": "AUTH_FAILED",
                    }
                else:
                    username = body["username"]
                    self.sessions[conn_id] = (peer_addr, username, key_c2s, key_s2c)
                    response = {
                        "success": True,
                        "username": username,
                        "error": None,
                    }
                self._send_message(
                    peer_addr, conn_id, "AUTH_ACK", response, request_id, key_s2c
                )
                if username is not None:
                    self._send_message(
                        peer_addr,
                        conn_id,
                        "USER_LIST",
                        {
                            "users": [
                                {
                                    "username": name,
                                    "ip": address[0],
                                    "port": address[1],
                                    "status": "online",
                                }
                                for address, name, *_ in self.sessions.values()
                                if name is not None
                            ]
                        },
                        "srv-user-list",
                        key_s2c,
                    )
                continue

            if stream_id == 0 and msg_type == "USER_LIST_REQ":
                users = [
                    {
                        "username": name,
                        "ip": address[0],
                        "port": address[1],
                        "status": "online",
                    }
                    for address, name, *_ in self.sessions.values()
                    if name is not None
                ]
                self._send_message(
                    peer_addr, conn_id, "USER_LIST", {"users": users}, request_id, key_s2c
                )
                continue

            if stream_id == 0 and msg_type == "LOGOUT":
                self._send_message(
                    peer_addr,
                    conn_id,
                    "LOGOUT_ACK",
                    {"success": True},
                    request_id,
                    key_s2c,
                )
                continue

            if stream_id != 1 or msg_type != "MSG" or username is None:
                continue
            target = body["target"]
            if target == "*":
                recipients = [
                    (other_id, other_addr, other_name, other_s2c)
                    for other_id, (other_addr, other_name, _, other_s2c) in self.sessions.items()
                    if other_id != conn_id and other_name is not None
                ]
            else:
                recipients = [
                    (other_id, other_addr, other_name, other_s2c)
                    for other_id, (other_addr, other_name, _, other_s2c) in self.sessions.items()
                    if other_name == target
                ]
            for other_id, other_addr, _, other_s2c in recipients:
                self._send_message(
                    other_addr,
                    other_id,
                    "MSG_DELIVER",
                    {
                        "sender": username,
                        "target": target,
                        "text": body["text"],
                        "timestamp": "2026-01-01T00:00:00Z",
                    },
                    f"srv-{self.next_server_packet_number}",
                    other_s2c,
                )

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=1)


class ClientMessagingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.peer = EncryptedTestPeer()
        self.clients: list[Client] = []
        self.addCleanup(self.peer.close)
        self.addCleanup(self._close_clients)

    def _close_clients(self) -> None:
        for client in self.clients:
            client.connection.shutdown()

    def login(self, username: str) -> Client:
        connection = CcpClient(
            self.peer.address[0],
            self.peer.address[1],
            receive_timeout=0.5,
        )
        client = Client(connection)
        client.login(username, f"{username}-test-password")
        self.clients.append(client)
        return client

    def drain(self, client: Client) -> None:
        while True:
            try:
                client.receive(timeout=0.05)
            except TimeoutError:
                return

    def test_login_performs_handshake_and_authentication(self) -> None:
        client = self.login("alice")
        self.assertNotEqual(client.connection.connection_id, 0)
        self.assertTrue(client.authenticated)
        self.assertIsNotNone(client.connection._key_c2s)
        self.assertTrue(client.connection.ping())
        users = client.request_users()
        self.assertEqual([user["username"] for user in users], ["alice"])

    def test_broadcast_and_multi_recipient_private_message(self) -> None:
        alice = self.login("alice")
        bob = self.login("bob")
        carol = self.login("carol")
        for client in (alice, bob, carol):
            self.drain(client)

        alice.send_broadcast("hello everyone")
        bob_broadcast = bob.receive(timeout=2)
        carol_broadcast = carol.receive(timeout=2)
        self.assertEqual(bob_broadcast["type"], "MSG_DELIVER")
        self.assertEqual(bob_broadcast["payload"]["target"], "*")
        self.assertEqual(carol_broadcast["payload"]["text"], "hello everyone")

        alice.send_private(("bob", "carol"), "hello privately")
        bob_private = bob.receive(timeout=2)
        carol_private = carol.receive(timeout=2)
        self.assertEqual(
            (bob_private["payload"]["sender"], bob_private["payload"]["target"]),
            ("alice", "bob"),
        )
        self.assertEqual(
            (
                carol_private["payload"]["sender"],
                carol_private["payload"]["target"],
                carol_private["payload"]["text"],
            ),
            ("alice", "carol", "hello privately"),
        )
        with self.assertRaises(TimeoutError):
            alice.connection.receive_message(timeout=0.1)


if __name__ == "__main__":
    unittest.main()

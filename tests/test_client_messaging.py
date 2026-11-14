"""Plaintext UDP tests for CCP client handshake and messaging."""

from __future__ import annotations

import json
import socket
import struct
import threading
import unittest

from src.client.messaging import MessagingClient
from src.client.network import CcpClient
from src.common.constants import MAGIC, VERSION, PacketType

HEADER = struct.Struct("!HBBBBIIH")
STREAM_HEADER = struct.Struct("!IQ")
FRAME_LENGTH = struct.Struct("!I")


class PlaintextTestPeer:
    """Small plaintext CCP peer for testing client wire behavior without crypto."""

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.address = self.socket.getsockname()
        self.stop_event = threading.Event()
        self.sessions: dict[int, tuple[tuple[str, int], str | None]] = {}
        self.next_connection_id = 100
        self.next_server_packet_number = 1
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _send(
        self,
        addr: tuple[str, int],
        packet_type: PacketType,
        connection_id: int,
        payload: bytes = b"",
    ) -> None:
        packet = HEADER.pack(
            MAGIC,
            VERSION,
            int(packet_type),
            0,
            0,
            connection_id,
            self.next_server_packet_number,
            len(payload),
        ) + payload
        self.next_server_packet_number += 1
        self.socket.sendto(packet, addr)

    def _send_message(
        self,
        addr: tuple[str, int],
        connection_id: int,
        message_type: str,
        payload: dict,
        request_id: str,
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
        self._send(
            addr,
            PacketType.DATA,
            connection_id,
            STREAM_HEADER.pack(0 if message_type != "MSG_DELIVER" else 1, 0)
            + frame,
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
            magic, version, raw_type, _flags, _reserved, conn_id, _number, length = (
                HEADER.unpack(data[:HEADER.size])
            )
            if magic != MAGIC or version != VERSION or length != len(data) - HEADER.size:
                continue
            payload = data[HEADER.size:]
            packet_type = PacketType(raw_type)

            if packet_type == PacketType.HELLO:
                conn_id = self.next_connection_id
                self.next_connection_id += 1
                self.sessions[conn_id] = (addr, None)
                self._send(addr, PacketType.HELLO_ACK, conn_id, bytes(48))
                continue

            if packet_type == PacketType.PING:
                self._send(addr, PacketType.PONG, conn_id)
                continue
            if packet_type == PacketType.CLOSE:
                self.sessions.pop(conn_id, None)
                continue
            if packet_type != PacketType.DATA or conn_id not in self.sessions:
                continue

            stream_id, _offset = STREAM_HEADER.unpack(payload[:STREAM_HEADER.size])
            framed = payload[STREAM_HEADER.size:]
            (frame_length,) = FRAME_LENGTH.unpack(framed[:FRAME_LENGTH.size])
            message = json.loads(framed[FRAME_LENGTH.size:FRAME_LENGTH.size + frame_length])
            body = message["payload"]
            msg_type = message["type"]
            request_id = message["id"]
            peer_addr, username = self.sessions[conn_id]

            if stream_id == 0 and msg_type == "AUTH":
                if body["password"] != f"{body['username']}-test-password":
                    response = {
                        "success": False,
                        "username": None,
                        "error": "AUTH_FAILED",
                    }
                else:
                    username = body["username"]
                    self.sessions[conn_id] = (peer_addr, username)
                    response = {
                        "success": True,
                        "username": username,
                        "error": None,
                    }
                self._send_message(
                    peer_addr, conn_id, "AUTH_ACK", response, request_id
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
                                for address, name in self.sessions.values()
                                if name is not None
                            ]
                        },
                        "srv-user-list",
                    )
                continue

            if stream_id == 0 and msg_type == "USER_LIST_REQ":
                users = [
                    {"username": name, "ip": address[0], "port": address[1], "status": "online"}
                    for address, name in self.sessions.values()
                    if name is not None
                ]
                self._send_message(
                    peer_addr,
                    conn_id,
                    "USER_LIST",
                    {"users": users},
                    request_id,
                )
                continue

            if stream_id == 0 and msg_type == "LOGOUT":
                self._send_message(
                    peer_addr,
                    conn_id,
                    "LOGOUT_ACK",
                    {"success": True},
                    request_id,
                )
                continue

            if stream_id != 1 or msg_type != "MSG" or username is None:
                continue
            target = body["target"]
            if target == "*":
                recipients = [
                    (other_id, other_addr, other_name)
                    for other_id, (other_addr, other_name) in self.sessions.items()
                    if other_id != conn_id and other_name is not None
                ]
            else:
                recipients = [
                    (other_id, other_addr, other_name)
                    for other_id, (other_addr, other_name) in self.sessions.items()
                    if other_name == target
                ]
            for other_id, other_addr, _ in recipients:
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
                )

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=1)


class ClientMessagingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.peer = PlaintextTestPeer()
        self.clients: list[MessagingClient] = []
        self.addCleanup(self.peer.close)
        self.addCleanup(self._close_clients)

    def _close_clients(self) -> None:
        for client in self.clients:
            client.connection.shutdown()

    def login(self, username: str) -> MessagingClient:
        connection = CcpClient(
            self.peer.address[0],
            self.peer.address[1],
            receive_timeout=0.5,
        )
        client = MessagingClient(connection)
        client.login(username, f"{username}-test-password")
        self.clients.append(client)
        return client

    def drain(self, client: MessagingClient) -> None:
        while True:
            try:
                client.receive(timeout=0.05)
            except TimeoutError:
                return

    def test_login_performs_handshake_and_authentication(self) -> None:
        client = self.login("alice")
        self.assertNotEqual(client.connection.connection_id, 0)
        self.assertTrue(client.authenticated)
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

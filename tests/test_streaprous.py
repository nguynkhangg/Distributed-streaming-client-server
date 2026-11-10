"""Unit tests for CO3094_streaprous HTTP daemon and TCP raw-socket theory functions
(reliable delivery, flow control, and congestion control).
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STREAPROUS = os.path.join(_ROOT, "CO3094_streaprous")
if _STREAPROUS not in sys.path:
    sys.path.insert(0, _STREAPROUS)

from daemon.request import Request  # noqa: E402
from daemon.response import Response  # noqa: E402
from streaprous_socket import streaprous_raw_connection as raw_conn  # noqa: E402
from streaprous_socket.streaprous_packet_dispatcher import get_packet_queue  # noqa: E402


class FakeRawSocket:
    def __init__(self) -> None:
        self.sent_packets: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: tuple[str, int]) -> int:
        self.sent_packets.append((data, addr))
        return len(data)


def make_incoming_tcp_ip(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack_seq: int,
    flags: int,
    window: int = 5840,
    payload: bytes = b"",
) -> bytes:
    ip_hdr = raw_conn.build_ip_header(src_ip, dst_ip, socket.IPPROTO_TCP, 20 + len(payload))
    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        (5 << 4),
        flags,
        window,
        0,
        0,
    )
    return ip_hdr + tcp_hdr + payload


class TestStreaprousFramework(unittest.TestCase):
    def setUp(self) -> None:
        raw_conn.close_all_connections()

    def test_http_request_and_response(self) -> None:
        req = Request()
        raw_http = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost:9000\r\n"
            "Cookie: session_id=abc123; theme=dark\r\n"
            "\r\n"
        )
        req.prepare(raw_http, routes={})
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.path, "/index.html")
        self.assertEqual(req.headers["host"], "localhost:9000")
        self.assertEqual(req.cookies["session_id"], "abc123")
        self.assertEqual(req.cookies["theme"], "dark")

        resp = Response()
        out = resp.build_response(req)
        self.assertTrue(out.startswith(b"HTTP/1.1 200 OK\r\n"))

    def test_flow_and_congestion_control(self) -> None:
        key = ("192.168.1.10", 50000)
        state = raw_conn.get_tcp_state(key)
        self.assertEqual(state["cwnd"], raw_conn.TCP_MSS)

        # Slow Start: cwnd increases by 1 MSS per new ACK
        raw_conn.update_congestion_control_on_ack(key, is_new_ack=True)
        self.assertEqual(state["cwnd"], 2 * raw_conn.TCP_MSS)
        raw_conn.update_congestion_control_on_ack(key, is_new_ack=True)
        self.assertEqual(state["cwnd"], 3 * raw_conn.TCP_MSS)

        # Flow control caps effective window at peer rwnd
        raw_conn.update_flow_control_window(key, 2000)
        self.assertEqual(raw_conn.compute_effective_window(state), 2000)

        # 3 duplicate ACKs trigger Fast Retransmit
        self.assertFalse(raw_conn.update_congestion_control_on_ack(key, is_new_ack=False))
        self.assertFalse(raw_conn.update_congestion_control_on_ack(key, is_new_ack=False))
        self.assertTrue(raw_conn.update_congestion_control_on_ack(key, is_new_ack=False))

        # RTO timeout resets cwnd to 1 MSS
        raw_conn.update_congestion_control_on_timeout(key)
        self.assertEqual(state["cwnd"], raw_conn.TCP_MSS)

    def test_reliable_out_of_order_receive_and_send(self) -> None:
        client_ip, client_port = "192.168.1.20", 51000
        server_ip, server_port = "192.168.1.1", 9000
        key = (client_ip, client_port)
        conn_info = raw_conn.conn_struct(
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            state="ESTABLISHED",
            server_seq=2001,
            client_seq=1001,
            expected_final_ack=2001,
            last_activity=0.0,
        )
        raw_conn.connections[key] = conn_info
        q = get_packet_queue(key)
        while not q.empty():
            q.get_nowait()

        fake_sock = FakeRawSocket()

        # Enqueue out-of-order segment (seq=1006, b"WORLD") before in-order segment (seq=1001, b"HELLO")
        pkt2 = make_incoming_tcp_ip(
            client_ip, server_ip, client_port, server_port, 1006, 2001, 0x18, payload=b"WORLD"
        )
        pkt1 = make_incoming_tcp_ip(
            client_ip, server_ip, client_port, server_port, 1001, 2001, 0x18, payload=b"HELLO"
        )
        q.put((pkt2, (client_ip, 0)))
        q.put((pkt1, (client_ip, 0)))

        received = raw_conn.run_conn_recv(fake_sock, conn_info)
        self.assertEqual(received, b"HELLOWORLD")
        self.assertEqual(raw_conn.connections[key].client_seq, 1011)

        # Now test run_conn_send with cumulative ACKs for both segments (1460 + 540)
        fake_sock.sent_packets.clear()
        payload = b"A" * 2000  # > 1460 MSS -> splits into 2 segments (1460 + 540)
        ack1 = make_incoming_tcp_ip(
            client_ip, server_ip, client_port, server_port, 1011, 2001 + 1460, 0x10, window=8192
        )
        ack2 = make_incoming_tcp_ip(
            client_ip, server_ip, client_port, server_port, 1011, 2001 + 2000, 0x10, window=8192
        )
        q.put((ack1, (client_ip, 0)))
        q.put((ack2, (client_ip, 0)))
        sent = raw_conn.run_conn_send(fake_sock, raw_conn.connections[key], payload)
        self.assertEqual(sent, 2000)
        self.assertEqual(len(fake_sock.sent_packets), 2)


if __name__ == "__main__":
    unittest.main()

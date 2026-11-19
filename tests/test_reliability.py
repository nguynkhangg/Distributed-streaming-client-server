"""Server-side reliability: stream reassembly, resending, required encryption, and a lossy network."""
from __future__ import annotations

import hashlib
import os
import random
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.client.client import Client, IncomingTransfer  # noqa: E402
from src.client.network import CcpClient  # noqa: E402
from src.file_transfer.packet import encode_ack_payload  # noqa: E402
from src.server.auth import UserStore  # noqa: E402
from src.server.server import CcpServer, PacketType, pack_packet  # noqa: E402
from src.server.stream_layer import FrameError, SendBuffer, StreamReceiver  # noqa: E402


def frame(text: str) -> bytes:
    body = text.encode()
    return struct.pack("!I", len(body)) + body


class TestStreamReceiver(unittest.TestCase):
    def test_in_order_frames(self):
        r = StreamReceiver()
        data = frame("a") + frame("bb")
        self.assertEqual(r.feed(0, data), [b"a", b"bb"])

    def test_duplicate_segment_is_ignored(self):
        r = StreamReceiver()
        data = frame("hello")
        self.assertEqual(r.feed(0, data), [b"hello"])
        self.assertEqual(r.feed(0, data), [])               # resent packet, same offset

    def test_out_of_order_segments_wait_for_the_gap(self):
        r = StreamReceiver()
        data = frame("x" * 30) + frame("y" * 30)
        first, second, third = data[:20], data[20:50], data[50:]
        self.assertEqual(r.feed(20, second), [])            # arrives first, gap in front
        self.assertEqual(r.feed(50, third), [])
        self.assertEqual(r.feed(0, first), [b"x" * 30, b"y" * 30])

    def test_a_frame_split_over_several_segments(self):
        r = StreamReceiver()
        data = frame("z" * 2500)
        out = []
        for start in range(0, len(data), 1000):
            out += r.feed(start, data[start:start + 1000])
        self.assertEqual(out, [b"z" * 2500])

    def test_overlapping_segment_adds_only_new_bytes(self):
        r = StreamReceiver()
        data = frame("overlap")
        self.assertEqual(r.feed(0, data[:6]), [])
        self.assertEqual(r.feed(3, data[3:]), [b"overlap"])

    def test_bad_frame_length_raises(self):
        with self.assertRaises(FrameError):
            StreamReceiver().feed(0, struct.pack("!I", 0) + b"x")
        with self.assertRaises(FrameError):
            StreamReceiver().feed(0, struct.pack("!I", 10_000_000))


class TestSendBuffer(unittest.TestCase):
    def test_ack_removes_and_silence_resends(self):
        buf = SendBuffer()
        buf.remember(5, 0, 0, b"one", 100.0)
        buf.remember(6, 0, 3, b"two", 100.0)
        buf.on_ack(encode_ack_payload(5, 256, [(5, 5)]))
        self.assertEqual(len(buf), 1)
        self.assertEqual(buf.take_due(100.1), [])           # not late yet
        due = buf.take_due(101.0)
        self.assertEqual([d.frame for d in due], [b"two"])
        self.assertEqual(len(buf), 0)

    def test_offsets_grow_per_stream(self):
        buf = SendBuffer()
        self.assertEqual(buf.next_offset(0, 10), 0)
        self.assertEqual(buf.next_offset(0, 5), 10)
        self.assertEqual(buf.next_offset(1, 7), 0)


class TestEncryptionIsRequired(unittest.TestCase):
    def setUp(self):
        self.server = CcpServer("127.0.0.1", 0)              # default: encryption required
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addr = self.server.address

    def _send_and_wait(self, packet: bytes) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.6)
        self.addCleanup(sock.close)
        sock.sendto(packet, self.addr)
        try:
            sock.recvfrom(2048)
            return True
        except socket.timeout:
            return False

    def test_hello_without_a_key_gets_no_answer(self):
        self.assertFalse(self._send_and_wait(pack_packet(PacketType.HELLO, 0, 1, b"")))

    def test_hello_with_a_key_is_answered(self):
        hello = pack_packet(PacketType.HELLO, 0, 1, os.urandom(32) + os.urandom(16))
        # a random 32-byte string is not always a valid X25519 key, so only check it is not ignored silently
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        self.addCleanup(sock.close)
        client = CcpClient(*self.addr, receive_timeout=2.0)
        self.addCleanup(client.shutdown)
        self.assertNotEqual(client.connect(), 0)
        self.assertTrue(client.ping())                       # encrypted PING -> PONG


class _LossyProxy:
    """UDP proxy that drops each datagram (both directions) with probability `loss`."""

    def __init__(self, server_addr, loss: float, seed: int):
        self.server_addr, self.loss, self.rnd = server_addr, loss, random.Random(seed)
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.address = self.front.getsockname()
        self.upstream: dict = {}
        self.closed = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.closed:
            try:
                data, addr = self.front.recvfrom(65535)
            except OSError:
                return
            if addr not in self.upstream:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                self.upstream[addr] = sock
                threading.Thread(target=self._back, args=(addr, sock), daemon=True).start()
            if self.rnd.random() >= self.loss:
                self.upstream[addr].sendto(data, self.server_addr)

    def _back(self, addr, sock):
        while not self.closed:
            try:
                data, _ = sock.recvfrom(65535)
            except OSError:
                return
            if self.rnd.random() >= self.loss:
                self.front.sendto(data, addr)

    def close(self):
        self.closed = True
        self.front.close()
        for sock in self.upstream.values():
            sock.close()


class LossyNetworkTest(unittest.TestCase):
    """Two users log in, chat and exchange a file while the network loses datagrams."""

    FILE_BYTES = 120_000
    MESSAGES = 20

    def run_scenario(self, loss: float, seed: int, long_message: bool = False):
        users = UserStore()
        for name in ("alice", "bob"):
            users.add_user(name, "123456")
        server = CcpServer("127.0.0.1", 0, users)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        proxy = _LossyProxy(server.address, loss, seed)
        work = tempfile.mkdtemp()
        clients = []

        def cleanup():
            for c in clients:
                try:
                    c.connection.shutdown()
                except Exception:
                    pass
            proxy.close()
            server.shutdown()
            shutil.rmtree(work, ignore_errors=True)
        self.addCleanup(cleanup)

        def login(name):
            c = Client(CcpClient(*proxy.address, receive_timeout=2.0), download_dir=os.path.join(work, name))
            c.login(name, "123456")
            clients.append(c)
            return c

        alice, bob = login("alice"), login("bob")
        time.sleep(1.0)

        texts = ["msg %02d" % i for i in range(self.MESSAGES)]
        if long_message:
            texts.append("L" * 3000)                          # needs several DATA segments
        for text in texts:
            alice.send_private(["bob"], text)
            time.sleep(0.02)
        got, end = [], time.time() + 20
        while time.time() < end and len(got) < len(texts):
            try:
                m = bob.receive(timeout=0.3)
            except TimeoutError:
                continue
            if m["type"] == "MSG_DELIVER":
                got.append(m["payload"]["text"])
        self.assertEqual(got, texts, "all messages, in order, once each")

        data = os.urandom(self.FILE_BYTES)
        path = os.path.join(work, "f.bin")
        with open(path, "wb") as f:
            f.write(data)
        transfer = alice.send_file(path, "bob")
        end = time.time() + 40
        while time.time() < end and transfer.record.state.value not in ("completed", "failed", "rejected", "cancelled"):
            for t in bob.transfers():
                if isinstance(t, IncomingTransfer) and not t.responded:
                    bob.respond_file(t, True)
            time.sleep(0.1)
        self.assertEqual(transfer.record.state.value, "completed", transfer.record.error)
        received = os.path.join(work, "bob", "f.bin")
        with open(received, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), hashlib.sha256(data).hexdigest())

    def test_no_loss_including_a_message_longer_than_one_segment(self):
        self.run_scenario(0.0, 1, long_message=True)

    def test_5_percent_loss(self):
        self.run_scenario(0.05, 1)

    def test_5_percent_loss_other_seed(self):
        self.run_scenario(0.05, 7)

    def test_10_percent_loss(self):
        self.run_scenario(0.10, 7)


if __name__ == "__main__":
    unittest.main()

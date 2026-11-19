"""Many clients at once, chat that is not blocked by a file transfer, and clients that vanish mid-transfer."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.client.client import Client, IncomingTransfer  # noqa: E402
from src.client.network import CcpClient  # noqa: E402
from src.server import session_manager  # noqa: E402
from src.server.auth import UserStore  # noqa: E402
from src.server.server import CcpServer  # noqa: E402

try:
    from tests.test_reliability import _LossyProxy
except ImportError:                                     # run from inside the tests folder
    from test_reliability import _LossyProxy

FINAL = ("completed", "failed", "rejected", "cancelled")


class Network(unittest.TestCase):
    """A real server on localhost and helpers to log users in."""

    names: tuple[str, ...] = ("alice", "bob", "carol", "dave")

    def setUp(self):
        users = UserStore()
        for name in self.names:
            users.add_user(name, "123456")
        self.server = CcpServer("127.0.0.1", 0, users)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.work = tempfile.mkdtemp()
        self.clients: list[Client] = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for c in self.clients:
            try:
                c.connection.shutdown()
            except Exception:
                pass
        self.server.shutdown()
        shutil.rmtree(self.work, ignore_errors=True)

    def login(self, name: str, address=None) -> Client:
        address = address or self.server.address
        client = Client(CcpClient(*address, receive_timeout=2.0), download_dir=os.path.join(self.work, name))
        client.login(name, "123456")
        self.clients.append(client)
        return client

    def collect(self, client: Client, count: int, timeout: float) -> list[str]:
        texts, end = [], time.time() + timeout
        while time.time() < end and len(texts) < count:
            try:
                m = client.receive(timeout=0.3)
            except TimeoutError:
                continue
            if m["type"] == "MSG_DELIVER":
                texts.append(m["payload"]["text"])
        return texts

    def make_file(self, size: int) -> str:
        path = os.path.join(self.work, "big.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(size))
        return path


class ManyClientsTest(Network):
    COUNT = 20
    names = tuple("user%02d" % i for i in range(COUNT))

    def test_twenty_clients_log_in_together_and_all_hear_every_broadcast(self):
        with ThreadPoolExecutor(max_workers=self.COUNT) as pool:
            clients = list(pool.map(self.login, self.names))
        self.assertEqual(len(clients), self.COUNT)
        self.assertEqual(len(self.server._sessions.authenticated_sessions()), self.COUNT)
        self.assertEqual(len(clients[0].request_users()), self.COUNT)

        time.sleep(0.5)
        for index, client in enumerate(clients):                # every user speaks once
            client.send_broadcast("hello from %02d" % index)
        for index, client in enumerate(clients):
            heard = self.collect(client, self.COUNT - 1, timeout=20)
            expected = {"hello from %02d" % i for i in range(self.COUNT) if i != index}
            self.assertEqual(set(heard), expected, "user %02d missed a broadcast" % index)

        with ThreadPoolExecutor(max_workers=self.COUNT) as pool:   # and leave together
            list(pool.map(lambda c: c.logout(), clients))
        deadline = time.time() + 5
        while time.time() < deadline and self.server._sessions.authenticated_sessions():
            time.sleep(0.1)
        self.assertEqual(self.server._sessions.authenticated_sessions(), [])


class ChatNotBlockedByFileTest(Network):
    def test_chat_keeps_flowing_while_a_big_file_crosses_a_lossy_network(self):
        proxy = _LossyProxy(self.server.address, 0.05, 3)
        self.addCleanup(proxy.close)
        alice, bob = self.login("alice", proxy.address), self.login("bob", proxy.address)
        time.sleep(0.5)

        transfer = alice.send_file(self.make_file(1_500_000), "bob")
        sent_at: dict[str, float] = {}
        arrived_at: dict[str, float] = {}
        order: list[str] = []
        number, end = 0, time.time() + 90
        while time.time() < end and transfer.record.state.value not in FINAL:
            for t in bob.transfers():
                if isinstance(t, IncomingTransfer) and not t.responded:
                    bob.respond_file(t, True)
            if transfer.record.state.value == "transferring" and time.time() - sent_at.get("last", 0) >= 0.2:
                text = "chat %03d" % number
                number += 1
                sent_at[text] = sent_at["last"] = time.time()
                alice.send_private(["bob"], text)
            try:
                m = bob.receive(timeout=0.05)
                if m["type"] == "MSG_DELIVER":
                    arrived_at[m["payload"]["text"]] = time.time()
                    order.append(m["payload"]["text"])
            except TimeoutError:
                pass
        finished = time.time()
        self.assertEqual(transfer.record.state.value, "completed", transfer.record.error)
        sent_at.pop("last", None)
        self.assertGreaterEqual(len(sent_at), 5, "the transfer was too short to prove anything")

        while len(arrived_at) < len(sent_at) and time.time() < finished + 10:   # stragglers
            try:
                m = bob.receive(timeout=0.2)
                if m["type"] == "MSG_DELIVER":
                    arrived_at[m["payload"]["text"]] = time.time()
                    order.append(m["payload"]["text"])
            except TimeoutError:
                pass
        self.assertEqual(order, sorted(sent_at), "every chat message, in order")
        slowest = max(arrived_at[t] - sent_at[t] for t in sent_at)
        self.assertLess(slowest, 5.0, "a chat message waited %.1f s behind the file" % slowest)
        during = [t for t in sent_at if arrived_at[t] < finished]
        self.assertGreaterEqual(len(during), len(sent_at) - 3, "chat should arrive while the file is still moving")


class VanishingClientTest(Network):
    """The server must survive, and the other side must hear that the transfer is over."""

    FILE_BYTES = 6_000_000

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(session_manager, "HEARTBEAT_TIMEOUT", 6.0)   # do not wait 15 s for a dead client
        patcher.start()
        self.addCleanup(patcher.stop)

    def start_transfer(self):
        alice, bob = self.login("alice"), self.login("bob")
        time.sleep(0.3)
        transfer = alice.send_file(self.make_file(self.FILE_BYTES), "bob")
        incoming = None
        end = time.time() + 10
        while time.time() < end:
            for t in bob.transfers():
                if isinstance(t, IncomingTransfer) and not t.responded:
                    bob.respond_file(t, True)
                    incoming = t
            if incoming is not None and incoming.receiver is not None and incoming.receiver.bytes_received > 0:
                break
            time.sleep(0.01)
        self.assertIsNotNone(incoming)
        self.assertGreater(incoming.receiver.bytes_received, 0, "the file must be on its way")
        self.assertNotIn(transfer.record.state.value, FINAL, "the file finished before the test could interrupt it")
        return alice, bob, transfer, incoming

    @staticmethod
    def crash(client: Client) -> None:
        """Vanish like a killed process: no CLOSE, no LOGOUT, the socket just goes away."""
        connection = client.connection
        connection._stop_receive.set()
        connection._socket.close()

    def wait_final(self, transfer, timeout: float) -> str:
        end = time.time() + timeout
        while time.time() < end and transfer.record.state.value not in FINAL:
            time.sleep(0.1)
        return transfer.record.state.value

    def still_serves(self):
        carol, dave = self.login("carol"), self.login("dave")
        time.sleep(0.3)
        carol.send_private(["dave"], "still alive")
        self.assertEqual(self.collect(dave, 1, 5), ["still alive"])

    def test_receiver_crashes_during_the_transfer(self):
        alice, bob, transfer, _ = self.start_transfer()
        self.crash(bob)
        state = self.wait_final(transfer, 20)
        self.assertIn(state, ("failed", "cancelled"), "sender must not wait for ever")
        self.still_serves()
        self.assertNotIn("bob", [s.username for s in self.server._sessions.authenticated_sessions()])

    def test_receiver_quits_politely_during_the_transfer(self):
        alice, bob, transfer, _ = self.start_transfer()
        bob.connection.shutdown()                            # CLOSE without LOGOUT
        self.assertIn(self.wait_final(transfer, 10), ("failed", "cancelled"))
        self.still_serves()

    def test_sender_crashes_and_the_receiver_keeps_no_half_file(self):
        alice, bob, transfer, incoming = self.start_transfer()
        self.crash(alice)
        end = time.time() + 20
        while time.time() < end and incoming.record.state.value not in FINAL:
            time.sleep(0.1)
        self.assertIn(incoming.record.state.value, ("failed", "cancelled"))
        download = os.path.join(self.work, "bob")
        leftovers = [f for _, _, files in os.walk(download) for f in files]
        self.assertEqual(leftovers, [], "a half-received file must be deleted")
        self.still_serves()


if __name__ == "__main__":
    unittest.main()

"""Tests for the Phase 2 message layer of src/server/server.py (protocol-spec sections 8, 9, 10, 16).

Run from the repository root:

    python -m unittest tests.test_server_auth_msg -v

The network is replaced by lists (RecordingServer), so no UDP socket traffic, stream layer or
encryption is needed: the tests feed complete JSON frames into _dispatch_control_json and read
what the server would have sent.
"""
import json
import logging
import os
import secrets
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.server.auth import RegisterResult, UserStore, make_record, verify_password  # noqa: E402
from src.server.server import CcpServer, PacketType, pack_packet  # noqa: E402
from src.server.session_manager import MAX_AUTH_FAILURES, CloseReason, SessionState  # noqa: E402

PASSWORDS = {name: secrets.token_urlsafe(12) for name in ("alice", "bob", "carol")}
WRONG = "wrong-password-0"


def frame(msg_type, payload=None, *, req_id="req-1", version=1) -> bytes:
    message = {"type": msg_type, "payload": {} if payload is None else payload,
               "id": req_id, "version": version}
    return json.dumps(message).encode("utf-8")


class RecordingServer(CcpServer):
    """CcpServer whose outgoing traffic is recorded instead of sent."""

    def __init__(self, users):
        super().__init__("127.0.0.1", 0, users=users)
        self.messages = []     # (connection_id, stream_id, decoded JSON message)
        self.packets = []      # (connection_id, PacketType, payload): CLOSE, PING, HELLO_ACK ...
        self.order = []        # ("msg" | "pkt", connection_id, label) in sending order
        self.fail_for = set()  # connection_ids whose delivery raises

    def _send_frame(self, session, stream_id, frame_bytes):
        if session.connection_id in self.fail_for:
            raise RuntimeError("simulated delivery failure")
        (length,) = struct.unpack("!I", frame_bytes[:4])
        assert length == len(frame_bytes) - 4, "bad length prefix"
        message = json.loads(frame_bytes[4:])
        self.messages.append((session.connection_id, stream_id, message))
        self.order.append(("msg", session.connection_id, message["type"]))

    def _send(self, session, packet_type, payload=b""):
        self.packets.append((session.connection_id, packet_type, payload))
        self.order.append(("pkt", session.connection_id, packet_type.name))


class TestAuthModule(unittest.TestCase):
    def test_hash_and_verify_password(self) -> None:
        record = make_record("alice", "secret-pass")
        self.assertTrue(verify_password("secret-pass", record))
        self.assertFalse(verify_password("wrong-pass", record))

    def test_user_store_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "users.json"
            store = UserStore(path)
            store.seed_demo_users("123456")
            self.assertTrue(store.verify_credentials("alice", "123456"))
            self.assertEqual(
                store.register_user("minhquoc", "my_pass_99"),
                RegisterResult.OK,
            )
            self.assertEqual(
                store.register_user("minhquoc", "duplicate"),
                RegisterResult.USERNAME_TAKEN,
            )

            reloaded = UserStore(path)
            self.assertTrue(reloaded.user_exists("minhquoc"))
            self.assertTrue(reloaded.verify_credentials("minhquoc", "my_pass_99"))
            self.assertFalse(reloaded.verify_credentials("minhquoc", "bad_pass"))


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.users = UserStore()
        for name, password in PASSWORDS.items():
            cls.users.add_user(name, password)

    def setUp(self):
        self.server = RecordingServer(self.users)
        self.addCleanup(self.server._sock.close)
        self._port = 40000

    # ---- helpers ----
    def connect(self):
        self._port += 1
        return self.server._sessions.get_or_create_session(
            ("10.0.0.1", self._port), bytes(32), secrets.token_bytes(16)).session

    def send(self, session, msg_type, payload=None, **kwargs):
        self.server._dispatch_control_json(session, frame(msg_type, payload, **kwargs))

    def login(self, name):
        session = self.connect()
        self.send(session, "AUTH", {"username": name, "password": PASSWORDS[name]})
        self.assertIs(session.state, SessionState.AUTHENTICATED)
        return session

    def inbox(self, session, msg_type=None):
        return [m for cid, _, m in self.server.messages
                if cid == session.connection_id and (msg_type is None or m["type"] == msg_type)]

    def closes(self, session):
        return [p for cid, t, p in self.server.packets
                if cid == session.connection_id and t is PacketType.CLOSE]

    def clear(self):
        self.server.messages.clear()
        self.server.packets.clear()
        self.server.order.clear()

    def assertError(self, session, code, related_type, req_id="req-1"):
        errors = self.inbox(session, "ERROR")
        self.assertEqual(len(errors), 1, errors)
        self.assertEqual(errors[0]["payload"]["code"], code)
        self.assertEqual(errors[0]["payload"]["related_type"], related_type)
        self.assertEqual(errors[0]["id"], req_id)      # direct replies reuse the request id


class TestEnvelope(ServerTestCase):
    def test_broken_frames_are_discarded_without_reply(self):
        s = self.connect()
        for raw in (b"not json", b"[]", b'"text"', b"null", b'{"payload": {}}', b'{"type": 5}',
                    b"\xff\xfe\x00", b"[" * 5000, b"x" * 70_000):
            self.server._dispatch_control_json(s, raw)
        self.assertEqual(self.server.messages, [])

    def test_unsupported_version(self):
        s = self.connect()
        self.send(s, "AUTH", {}, version=2)
        self.assertError(s, "UNSUPPORTED_VERSION", "AUTH")

    def test_everything_but_auth_is_rejected_before_login(self):      # rule 2
        for msg_type in ("MSG", "LOGOUT", "USER_LIST_REQ", "FILE_OFFER", "NOPE"):
            with self.subTest(msg_type=msg_type):
                self.clear()
                s = self.connect()
                self.send(s, msg_type, {"target": "*", "text": "hi"})
                self.assertError(s, "NOT_AUTHENTICATED", msg_type)
                self.assertIs(s.state, SessionState.ESTABLISHED)

    def test_missing_id_or_bad_payload(self):
        s = self.login("alice")
        self.clear()
        self.server._dispatch_control_json(s, json.dumps(
            {"type": "MSG", "payload": [], "id": "r9", "version": 1}))
        self.assertError(s, "INVALID_PAYLOAD", "MSG", req_id="r9")
        self.clear()
        self.server._dispatch_control_json(s, json.dumps(
            {"type": "MSG", "payload": {}, "version": 1}))
        errors = self.inbox(s, "ERROR")
        self.assertEqual(errors[0]["payload"]["code"], "INVALID_PAYLOAD")
        self.assertTrue(errors[0]["id"].startswith("srv-"))     # no usable request id

    def test_unknown_type_after_login(self):
        s = self.login("alice")
        self.clear()
        self.send(s, "TELEPORT")
        self.assertError(s, "UNKNOWN_MESSAGE_TYPE", "TELEPORT")

    def test_handler_crash_becomes_internal_error(self):
        s = self.login("alice")
        self.clear()
        with mock.patch.object(self.server._sessions, "online_users", side_effect=RuntimeError):
            with self.assertLogs("ccp.server", level="ERROR"):
                self.send(s, "USER_LIST_REQ")
        self.assertError(s, "INTERNAL_ERROR", "USER_LIST_REQ")


class TestAuth(ServerTestCase):
    def test_wrong_password_keeps_the_connection(self):
        s = self.connect()
        self.send(s, "AUTH", {"username": "alice", "password": WRONG})
        ack = self.inbox(s, "AUTH_ACK")[0]
        self.assertEqual(ack["payload"], {"success": False, "username": None,
                                          "error": "AUTH_FAILED"})
        self.assertEqual(ack["id"], "req-1")
        self.assertIs(s.state, SessionState.ESTABLISHED)
        self.assertEqual(s.failed_auth_count, 1)
        self.send(s, "AUTH", {"username": "alice", "password": PASSWORDS["alice"]})  # may retry
        self.assertIs(s.state, SessionState.AUTHENTICATED)

    def test_unknown_user_looks_like_a_wrong_password(self):
        a, b = self.connect(), self.connect()
        self.send(a, "AUTH", {"username": "alice", "password": WRONG})
        self.send(b, "AUTH", {"username": "nobody", "password": WRONG})
        self.assertEqual(self.inbox(a, "AUTH_ACK")[0]["payload"],
                         self.inbox(b, "AUTH_ACK")[0]["payload"])

    def test_username_star_can_never_log_in(self):
        s = self.connect()
        self.send(s, "AUTH", {"username": "*", "password": WRONG})
        self.assertEqual(self.inbox(s, "AUTH_ACK")[0]["payload"]["error"], "AUTH_FAILED")

    def test_five_failures_close_the_connection(self):          # rule 5
        s = self.connect()
        for _ in range(MAX_AUTH_FAILURES - 1):
            self.send(s, "AUTH", {"username": "alice", "password": WRONG})
        self.assertEqual(self.closes(s), [])
        self.assertIsNotNone(self.server._sessions.lookup(s.connection_id, s.address))
        self.send(s, "AUTH", {"username": "alice", "password": WRONG})
        acks = self.inbox(s, "AUTH_ACK")
        self.assertEqual(len(acks), MAX_AUTH_FAILURES)           # the 5th failure is still answered
        self.assertTrue(all(a["payload"]["error"] == "AUTH_FAILED" for a in acks))
        self.assertEqual(self.closes(s), [bytes([CloseReason.PROTOCOL_ERROR])])
        self.assertIsNone(self.server._sessions.lookup(s.connection_id, s.address))
        kinds = [label for _, cid, label in self.server.order if cid == s.connection_id]
        self.assertEqual(kinds[-2:], ["AUTH_ACK", "CLOSE"])

    def test_malformed_auth_is_not_counted_as_a_failed_login(self):
        s = self.connect()
        for payload in ({}, {"username": 5, "password": "x"}, {"username": "alice"},
                        {"username": "alice", "password": None}):
            self.clear()
            self.send(s, "AUTH", payload)
            self.assertError(s, "INVALID_PAYLOAD", "AUTH")
        self.assertEqual(s.failed_auth_count, 0)

    def test_success_sends_ack_then_user_list_then_presence_to_others(self):   # rule 8
        bob = self.login("bob")
        stranger = self.connect()                                 # connected but not logged in
        self.clear()
        alice = self.connect()
        self.send(alice, "AUTH", {"username": "alice", "password": PASSWORDS["alice"]})
        got = self.inbox(alice)
        self.assertEqual([m["type"] for m in got], ["AUTH_ACK", "USER_LIST"])
        self.assertEqual(got[0]["payload"], {"success": True, "username": "alice", "error": None})
        self.assertEqual(got[0]["id"], "req-1")
        users = {u["username"]: u for u in got[1]["payload"]["users"]}
        self.assertEqual(set(users), {"alice", "bob"})
        self.assertEqual(users["alice"], {"username": "alice", "ip": "10.0.0.1",
                                          "port": alice.address[1], "status": "online"})
        presence = self.inbox(bob, "PRESENCE")
        self.assertEqual([m["payload"] for m in presence],
                         [{"username": "alice", "status": "online"}])
        self.assertTrue(presence[0]["id"].startswith("srv-"))     # events get their own ids
        self.assertEqual(self.inbox(stranger), [])               # not authenticated: no events
        self.assertEqual(self.inbox(alice, "PRESENCE"), [])      # nobody announces you to yourself

    def test_second_login_gets_already_logged_in_only_with_the_right_password(self):  # rule 4
        self.login("alice")
        other = self.connect()
        self.send(other, "AUTH", {"username": "alice", "password": WRONG})
        self.assertEqual(self.inbox(other, "AUTH_ACK")[-1]["payload"]["error"], "AUTH_FAILED")
        self.send(other, "AUTH", {"username": "alice", "password": PASSWORDS["alice"]})
        self.assertEqual(self.inbox(other, "AUTH_ACK")[-1]["payload"],
                         {"success": False, "username": None, "error": "ALREADY_LOGGED_IN"})
        self.assertIs(other.state, SessionState.ESTABLISHED)
        self.assertEqual(other.failed_auth_count, 1)             # only the wrong password counted

    def test_authenticated_connection_cannot_auth_again(self):   # rule 6
        s = self.login("alice")
        self.clear()
        with mock.patch.object(self.users, "verify_credentials") as verify:
            self.send(s, "AUTH", {"username": "bob", "password": PASSWORDS["bob"]})
        verify.assert_not_called()                               # no PBKDF2 work, no counter change
        self.assertError(s, "ALREADY_AUTHENTICATED", "AUTH")
        self.assertEqual(s.username, "alice")

    def test_password_never_reaches_the_log(self):               # rule 11
        class ListHandler(logging.Handler):
            def __init__(self):
                super().__init__(logging.DEBUG)
                self.lines = []

            def emit(self, record):
                self.lines.append(self.format(record))

        handler, root = ListHandler(), logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(lambda: (root.removeHandler(handler), root.setLevel(old_level)))
        secret = "Sup3r-Secret-PW"
        s = self.connect()
        for _ in range(MAX_AUTH_FAILURES):                       # ends with a logged session close
            self.send(s, "AUTH", {"username": "alice", "password": secret})
        other = self.connect()
        self.send(other, "AUTH", {"username": "alice", "password": PASSWORDS["alice"]})
        self.send(other, "AUTH", {"username": "alice", "password": 12345})
        self.assertTrue(handler.lines)
        joined = "\n".join(handler.lines)
        self.assertNotIn(secret, joined)
        self.assertNotIn(PASSWORDS["alice"], joined)


class TestLogoutAndPresence(ServerTestCase):
    def test_logout_flow(self):                                  # section 16
        alice, bob = self.login("alice"), self.login("bob")
        self.clear()
        self.send(alice, "LOGOUT", req_id="out-1")
        ack = self.inbox(alice, "LOGOUT_ACK")
        self.assertEqual(ack[0]["payload"], {"success": True})
        self.assertEqual(ack[0]["id"], "out-1")
        self.assertEqual(self.closes(alice), [bytes([CloseReason.NORMAL])])
        labels = [label for _, cid, label in self.server.order if cid == alice.connection_id]
        self.assertEqual(labels, ["LOGOUT_ACK", "CLOSE"])
        self.assertEqual([m["payload"] for m in self.inbox(bob, "PRESENCE")],
                         [{"username": "alice", "status": "offline"}])
        self.assertIsNone(self.server._sessions.get_by_username("alice"))
        self.login("alice")                                      # the name is free again

    def test_heartbeat_timeout_of_a_logged_in_user_announces_offline(self):
        alice, bob = self.login("alice"), self.login("bob")
        self.clear()
        alice.last_recv = time.monotonic() - 16
        self.server._sweep_once()
        self.assertEqual(self.closes(alice), [bytes([CloseReason.TIMEOUT])])
        self.assertEqual([m["payload"] for m in self.inbox(bob, "PRESENCE")],
                         [{"username": "alice", "status": "offline"}])
        self.assertEqual(self.closes(bob), [])

    def test_missing_auth_deadline_closes_silently(self):        # 10 s rule, nobody to announce
        bob = self.login("bob")
        s = self.connect()
        self.clear()
        s.created_at = time.monotonic() - 11
        self.server._sweep_once()
        self.assertEqual(self.closes(s), [bytes([CloseReason.TIMEOUT])])
        self.assertEqual(self.inbox(bob, "PRESENCE"), [])

    def test_losing_connection_cannot_release_the_username(self):    # rule 10
        alice, bob = self.login("alice"), self.login("bob")
        loser = self.connect()
        self.send(loser, "AUTH", {"username": "alice", "password": PASSWORDS["alice"]})
        self.assertEqual(self.inbox(loser, "AUTH_ACK")[-1]["payload"]["error"], "ALREADY_LOGGED_IN")
        self.clear()
        self.server._close_session(loser, CloseReason.TIMEOUT, "test")
        self.assertIs(self.server._sessions.get_by_username("alice"), alice)
        self.assertEqual(self.inbox(bob, "PRESENCE"), [])        # nothing really went offline
        self.send(bob, "USER_LIST_REQ")
        names = {u["username"] for u in self.inbox(bob, "USER_LIST")[-1]["payload"]["users"]}
        self.assertEqual(names, {"alice", "bob"})

    def test_presence_is_sent_once_even_if_cleanup_runs_twice(self):  # rule 9
        alice, bob = self.login("alice"), self.login("bob")
        self.clear()
        self.server._close_session(alice, CloseReason.TIMEOUT, "first")
        self.server._close_session(alice, CloseReason.TIMEOUT, "second")
        self.assertEqual(len(self.inbox(bob, "PRESENCE")), 1)
        self.assertEqual(len(self.closes(alice)), 1)

    def test_client_restart_announces_offline_for_the_old_session(self):
        alice, bob = self.login("alice"), self.login("bob")
        self.clear()
        hello = pack_packet(PacketType.HELLO, 0, 1, b"")         # same (ip, port), different nonce
        self.server._handle_datagram(hello, alice.address)
        self.assertIs(alice.state, SessionState.CLOSED)
        self.assertEqual([m["payload"] for m in self.inbox(bob, "PRESENCE")],
                         [{"username": "alice", "status": "offline"}])

    def test_online_is_never_announced_after_the_session_is_gone(self):
        bob = self.login("bob")
        s = self.connect()
        self.send(s, "AUTH", {"username": "alice", "password": PASSWORDS["alice"]})
        self.server._close_session(s, CloseReason.TIMEOUT, "race")
        self.clear()
        self.server._announce_online(s)                          # late "online" for a closed session
        self.assertEqual(self.inbox(bob, "PRESENCE"), [])


class TestMessages(ServerTestCase):
    def test_private_message_is_delivered_to_the_target_only(self):
        alice, bob, carol = self.login("alice"), self.login("bob"), self.login("carol")
        self.clear()
        self.send(alice, "MSG", {"target": "bob", "text": "Xin chào Bob"}, req_id="m-1")
        delivered = self.inbox(bob, "MSG_DELIVER")
        self.assertEqual(len(delivered), 1)
        payload = delivered[0]["payload"]
        self.assertEqual((payload["sender"], payload["target"], payload["text"]),
                         ("alice", "bob", "Xin chào Bob"))
        self.assertRegex(payload["timestamp"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(delivered[0]["id"].startswith("srv-"))
        self.assertEqual([stream for cid, stream, m in self.server.messages
                          if m["type"] == "MSG_DELIVER"], [1])   # chat travels on stream 1
        self.assertEqual(self.inbox(alice), [])                  # no echo, no error
        self.assertEqual(self.inbox(carol), [])

    def test_sender_cannot_be_spoofed(self):
        alice, bob = self.login("alice"), self.login("bob")
        self.clear()
        self.send(alice, "MSG", {"target": "bob", "text": "hi", "sender": "carol"})
        self.assertEqual(self.inbox(bob, "MSG_DELIVER")[0]["payload"]["sender"], "alice")

    def test_offline_and_unknown_targets_get_different_errors(self):
        alice, bob = self.login("alice"), self.login("bob")
        self.clear()
        self.send(alice, "MSG", {"target": "carol", "text": "hi"})     # exists, not online
        self.assertError(alice, "USER_OFFLINE", "MSG")
        self.clear()
        self.send(alice, "MSG", {"target": "ghost", "text": "hi"})
        self.assertError(alice, "USER_NOT_FOUND", "MSG")
        self.assertEqual(self.inbox(bob), [])                    # nothing queued or forwarded

    def test_user_who_logged_out_is_offline_not_unknown(self):
        alice, bob = self.login("alice"), self.login("bob")
        self.send(bob, "LOGOUT")
        self.clear()
        self.send(alice, "MSG", {"target": "bob", "text": "are you there?"})
        self.assertError(alice, "USER_OFFLINE", "MSG")

    def test_broadcast_reaches_every_other_logged_in_user(self):
        alice, bob, carol = self.login("alice"), self.login("bob"), self.login("carol")
        stranger = self.connect()
        self.clear()
        self.send(alice, "MSG", {"target": "*", "text": "hello all"})
        for peer in (bob, carol):
            msgs = self.inbox(peer, "MSG_DELIVER")
            self.assertEqual(len(msgs), 1)
            self.assertEqual(msgs[0]["payload"]["target"], "*")
            self.assertEqual(msgs[0]["payload"]["sender"], "alice")
        self.assertEqual(self.inbox(alice), [])                  # sender is not echoed
        self.assertEqual(self.inbox(stranger), [])               # not authenticated

    def test_broadcast_with_no_other_user_is_not_an_error(self):
        alice = self.login("alice")
        self.clear()
        self.send(alice, "MSG", {"target": "*", "text": "anyone?"})
        self.assertEqual(self.server.messages, [])

    def test_one_failing_recipient_does_not_block_the_others(self):   # section 10
        alice, bob, carol = self.login("alice"), self.login("bob"), self.login("carol")
        self.clear()
        self.server.fail_for.add(bob.connection_id)
        with self.assertLogs("ccp.server", level="ERROR"):
            self.send(alice, "MSG", {"target": "*", "text": "still delivered"})
        self.assertEqual(len(self.inbox(carol, "MSG_DELIVER")), 1)
        self.assertEqual(self.inbox(alice), [])                  # the sender sees no error

    def test_invalid_msg_payloads(self):
        alice = self.login("alice")
        too_long = "x" * 4097
        bad_payloads = [{}, {"target": "bob"}, {"text": "hi"}, {"target": "bob", "text": ""},
                        {"target": "bob", "text": "   "}, {"target": "", "text": "hi"},
                        {"target": 5, "text": "hi"}, {"target": "bob", "text": 5},
                        {"target": "bob", "text": too_long}, {"target": "bob", "text": "\ud800"}]
        for payload in bad_payloads:
            with self.subTest(payload=str(payload)[:40]):
                self.clear()
                self.send(alice, "MSG", payload)
                self.assertError(alice, "INVALID_PAYLOAD", "MSG")

    def test_user_list_request(self):
        alice, bob = self.login("alice"), self.login("bob")
        self.clear()
        self.send(alice, "USER_LIST_REQ", req_id="ul-1")
        reply = self.inbox(alice, "USER_LIST")
        self.assertEqual(reply[0]["id"], "ul-1")
        users = reply[0]["payload"]["users"]
        self.assertEqual(sorted(u["username"] for u in users), ["alice", "bob"])
        self.assertTrue(all(u["status"] == "online" for u in users))


if __name__ == "__main__":
    unittest.main()

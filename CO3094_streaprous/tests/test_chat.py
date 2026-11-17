import unittest

from apps.chat import ChatService


class ChatServiceTests(unittest.TestCase):
    def setUp(self):
        self.chat = ChatService()
        self.chat.register_peer("peer-a", "Alice", "192.0.2.1", 9001)
        self.chat.register_peer("peer-b", "Bob", "192.0.2.2", 9002)
        self.chat.join_channel("peer-a", "general")
        self.chat.join_channel("peer-b", "general")

    def test_tracker_lists_registered_peers(self):
        peers = self.chat.list_peers()
        self.assertEqual({peer["peerId"] for peer in peers}, {"peer-a", "peer-b"})
        self.assertEqual(
            (peers[0]["ip"], peers[0]["port"]),
            ("192.0.2.1", 9001),
        )

    def test_broadcast_queues_event_for_channel_members(self):
        result = self.chat.send_message("peer-a", "general", "Hello")
        events = self.chat.poll_events("peer-b")
        self.assertEqual(result["message"]["text"], "Hello")
        self.assertEqual(result["queued"], 1)
        self.assertEqual(events[0]["type"], "message")
        self.assertEqual(events[0]["message"]["peerId"], "peer-a")
        self.assertEqual(self.chat.poll_events("peer-a"), [])

    def test_private_message_is_queued_only_for_recipient(self):
        result = self.chat.send_private_message("peer-a", "peer-b", "Private")
        self.assertEqual(result["to"], "peer-b")
        self.assertEqual(self.chat.poll_events("peer-a"), [])
        self.assertEqual(self.chat.poll_events("peer-b")[0]["type"], "private")

    def test_channel_membership_is_required_to_read_or_broadcast(self):
        channel = self.chat.create_channel("peer-a", "Study group")
        with self.assertRaisesRegex(ValueError, "join the channel"):
            self.chat.list_messages("peer-b", channel["id"])
        with self.assertRaisesRegex(ValueError, "join the channel"):
            self.chat.send_message("peer-b", channel["id"], "Hello")

    def test_messages_enforce_utf8_size_limit(self):
        with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
            self.chat.send_message("peer-a", "general", "é" * 301)

    def test_registration_rejects_non_integer_ports(self):
        with self.assertRaisesRegex(ValueError, "port must be an integer"):
            self.chat.register_peer("peer-c", "Charlie", "192.0.2.3", 9000.5)

    def test_private_message_requires_registered_recipient(self):
        with self.assertRaisesRegex(ValueError, "recipient must be registered"):
            self.chat.send_private_message("peer-a", "missing", "Private")

    def test_poll_drains_each_queued_event_once(self):
        self.chat.send_message("peer-a", "general", "Once")
        self.assertEqual(len(self.chat.poll_events("peer-b")), 1)
        self.assertEqual(self.chat.poll_events("peer-b"), [])


if __name__ == "__main__":
    unittest.main()

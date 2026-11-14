import threading
import time
import uuid


class ChatService:
    """Track peers, channel membership, history, and queued chat events."""

    PEER_TIMEOUT = 60
    MAX_MESSAGE_BYTES = 600

    def __init__(self):
        self._lock = threading.RLock()
        self._peers = {}
        self._channels = {
            "general": {
                "id": "general",
                "name": "General",
                "members": set(),
            }
        }
        self._messages = {"general": []}
        self._events = {}

    @staticmethod
    def _required_text(value, label, maximum):
        if not isinstance(value, str):
            raise ValueError("{} must be text".format(label))
        value = value.strip()
        if not value or len(value) > maximum:
            raise ValueError("{} must contain 1 to {} characters".format(label, maximum))
        return value

    @classmethod
    def _message_text(cls, value):
        text = cls._required_text(value, "message", cls.MAX_MESSAGE_BYTES)
        if len(text.encode("utf-8")) > cls.MAX_MESSAGE_BYTES:
            raise ValueError(
                "message exceeds {} UTF-8 bytes".format(cls.MAX_MESSAGE_BYTES)
            )
        return text

    def _remove_expired_peers(self):
        now = time.time()
        expired = [
            peer_id for peer_id, peer in self._peers.items()
            if now - peer["lastSeen"] > self.PEER_TIMEOUT
        ]
        for peer_id in expired:
            del self._peers[peer_id]
            self._events.pop(peer_id, None)

    def register_peer(self, peer_id, username, ip, port):
        peer_id = self._required_text(peer_id, "peerId", 80)
        username = self._required_text(username, "username", 40)
        ip = self._required_text(ip, "ip", 255)
        if isinstance(port, bool) or (
            isinstance(port, float) and not port.is_integer()
        ):
            raise ValueError("port must be an integer")
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError("port must be an integer")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        with self._lock:
            self._remove_expired_peers()
            peer = {
                "peerId": peer_id,
                "username": username,
                "ip": ip,
                "port": port,
                "lastSeen": time.time(),
            }
            self._peers[peer_id] = peer
            self._events.setdefault(peer_id, [])
            return dict(peer)

    def list_peers(self):
        with self._lock:
            self._remove_expired_peers()
            return [
                {key: value for key, value in peer.items() if key != "lastSeen"}
                for peer in self._peers.values()
            ]

    def unregister_peer(self, peer_id):
        peer_id = self._required_text(peer_id, "peerId", 80)
        with self._lock:
            self._peers.pop(peer_id, None)
            self._events.pop(peer_id, None)
        return {"peerId": peer_id}

    def list_channels(self, peer_id):
        peer_id = self._required_text(peer_id, "peerId", 80)
        with self._lock:
            return [
                {
                    "id": channel["id"],
                    "name": channel["name"],
                    "joined": peer_id in channel["members"],
                }
                for channel in self._channels.values()
            ]

    def create_channel(self, peer_id, name):
        peer_id = self._required_text(peer_id, "peerId", 80)
        name = self._required_text(name, "channel name", 50)
        with self._lock:
            self._remove_expired_peers()
            if peer_id not in self._peers:
                raise ValueError("peer must be registered before creating channels")
            channel_id = uuid.uuid4().hex
            channel = {
                "id": channel_id,
                "name": name,
                "members": {peer_id},
            }
            self._channels[channel_id] = channel
            self._messages[channel_id] = []
            return {"id": channel_id, "name": name, "joined": True}

    def join_channel(self, peer_id, channel_id):
        peer_id = self._required_text(peer_id, "peerId", 80)
        channel_id = self._required_text(channel_id, "channelId", 80)
        with self._lock:
            self._remove_expired_peers()
            if peer_id not in self._peers:
                raise ValueError("peer must be registered before joining channels")
            channel = self._channels.get(channel_id)
            if channel is None:
                raise ValueError("channel does not exist")
            channel["members"].add(peer_id)
            return {"id": channel["id"], "name": channel["name"], "joined": True}

    def list_messages(self, peer_id, channel_id):
        peer_id = self._required_text(peer_id, "peerId", 80)
        channel_id = self._required_text(channel_id, "channelId", 80)
        with self._lock:
            channel = self._channels.get(channel_id)
            if channel is None:
                raise ValueError("channel does not exist")
            if peer_id not in channel["members"]:
                raise ValueError("join the channel before viewing its messages")
            return list(self._messages[channel_id])

    def poll_events(self, peer_id):
        peer_id = self._required_text(peer_id, "peerId", 80)
        with self._lock:
            self._remove_expired_peers()
            peer = self._peers.get(peer_id)
            if peer is None:
                raise ValueError("peer is not active")
            peer["lastSeen"] = time.time()
            events = self._events.setdefault(peer_id, [])
            self._events[peer_id] = []
            return events

    def send_message(self, peer_id, channel_id, text):
        peer_id = self._required_text(peer_id, "peerId", 80)
        channel_id = self._required_text(channel_id, "channelId", 80)
        text = self._message_text(text)

        with self._lock:
            self._remove_expired_peers()
            peer = self._peers.get(peer_id)
            channel = self._channels.get(channel_id)
            if peer is None:
                raise ValueError("peer must be registered before sending messages")
            if channel is None or peer_id not in channel["members"]:
                raise ValueError("join the channel before sending messages")
            message = {
                "id": uuid.uuid4().hex,
                "channelId": channel_id,
                "peerId": peer_id,
                "username": peer["username"],
                "text": text,
                "timestamp": time.time(),
            }
            self._messages[channel_id].append(message)
            peer["lastSeen"] = time.time()

            recipients = [
                member_id for member_id in channel["members"]
                if member_id != peer_id and member_id in self._peers
            ]
            event = {"type": "message", "message": dict(message)}
            for recipient_id in recipients:
                self._events.setdefault(recipient_id, []).append(event)

        return {"message": dict(message), "queued": len(recipients)}

    def send_private_message(self, sender_id, target_id, text):
        sender_id = self._required_text(sender_id, "peerId", 80)
        target_id = self._required_text(target_id, "to", 80)
        text = self._message_text(text)

        with self._lock:
            self._remove_expired_peers()
            sender = self._peers.get(sender_id)
            if sender is None:
                raise ValueError("peer must register before sending messages")
            if target_id not in self._peers:
                raise ValueError("recipient must be registered")
            message = {
                "id": uuid.uuid4().hex,
                "peerId": sender_id,
                "username": sender["username"],
                "text": text,
                "timestamp": time.time(),
            }
            sender["lastSeen"] = time.time()
            self._events.setdefault(target_id, []).append({
                "type": "private",
                "message": message,
            })
        return {"message": message, "to": target_id}

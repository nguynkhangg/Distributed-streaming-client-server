"""Python client for the StreapRous REST chat API."""

import argparse
import http.client
import json
import threading


class ChatClient:
    def __init__(
        self,
        server_host,
        server_port,
        peer_id,
        username,
        advertised_ip,
        advertised_port,
    ):
        self.server_host = server_host
        self.server_port = int(server_port)
        self.peer_id = peer_id
        self.username = username
        self.advertised_ip = advertised_ip
        self.advertised_port = int(advertised_port)
        self._stop = threading.Event()
        self._poll_thread = None

    def request(self, method, path, data=None, headers=None):
        body = None if data is None else json.dumps(data)
        connection = http.client.HTTPConnection(
            self.server_host,
            self.server_port,
            timeout=10,
        )
        try:
            connection.request(
                method,
                path,
                body=body,
                headers=headers or {},
            )
            response = connection.getresponse()
            payload = response.read()
            result = json.loads(payload.decode("utf-8"))
            if response.status < 200 or response.status >= 300 or "error" in result:
                raise RuntimeError(result.get("error", response.reason))
            return result
        finally:
            connection.close()

    def register(self):
        return self.request(
            "POST",
            "/api/peers/register",
            {
                "peerId": self.peer_id,
                "username": self.username,
                "ip": self.advertised_ip,
                "port": self.advertised_port,
            },
        )

    def unregister(self):
        self.stop_polling()
        return self.request(
            "POST",
            "/api/peers/unregister",
            {"peerId": self.peer_id},
        )

    def start_polling(self, on_event=None, interval=6):
        if self._poll_thread is not None and self._poll_thread.is_alive():
            raise RuntimeError("chat polling is already running")
        self._stop.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            args=(on_event, interval),
            daemon=True,
        )
        self._poll_thread.start()

    def _poll_loop(self, on_event, interval):
        while not self._stop.is_set():
            try:
                result = self.request(
                    "POST",
                    "/api/messages/poll",
                    {"peerId": self.peer_id},
                )
                for event in result["events"]:
                    if on_event is None:
                        print(json.dumps(event, ensure_ascii=False))
                    else:
                        on_event(event)
            except (OSError, RuntimeError, ValueError) as error:
                if not self._stop.is_set():
                    print("[ChatClient] Message polling failed: {}".format(error))
            self._stop.wait(interval)

    def stop_polling(self):
        self._stop.set()
        if self._poll_thread is not None:
            self._poll_thread.join(timeout=10)
            self._poll_thread = None

    def list_peers(self):
        return self.request("GET", "/api/peers")

    def list_channels(self):
        return self.request(
            "GET",
            "/api/channels",
            headers={"X-Peer-ID": self.peer_id},
        )

    def create_channel(self, name):
        return self.request(
            "POST",
            "/api/channels/create",
            {"peerId": self.peer_id, "name": name},
        )

    def join_channel(self, channel_id):
        return self.request(
            "POST",
            "/api/channels/join",
            {"peerId": self.peer_id, "channelId": channel_id},
        )

    def list_messages(self, channel_id):
        return self.request(
            "GET",
            "/api/messages",
            headers={
                "X-Peer-ID": self.peer_id,
                "X-Channel-ID": channel_id,
            },
        )

    def send_message(self, channel_id, text):
        return self.request(
            "POST",
            "/api/messages",
            {"peerId": self.peer_id, "channelId": channel_id, "text": text},
        )

    def send_private_message(self, target_id, text):
        return self.request(
            "POST",
            "/api/messages/direct",
            {"peerId": self.peer_id, "to": target_id, "text": text},
        )


def main():
    parser = argparse.ArgumentParser(description="StreapRous Python chat client")
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=2026)
    parser.add_argument("--peer-id", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--advertised-ip", required=True)
    parser.add_argument("--advertised-port", type=int, default=2027)
    parser.add_argument("--poll-interval", type=int, default=6)
    args = parser.parse_args()

    client = ChatClient(
        args.server_host,
        args.server_port,
        args.peer_id,
        args.username,
        args.advertised_ip,
        args.advertised_port,
    )
    registered = False
    try:
        client.register()
        registered = True
        client.join_channel("general")
        client.start_polling(interval=args.poll_interval)
        print("Joined #general. Type /quit to exit.")
        while True:
            text = input("> ").strip()
            if text == "/quit":
                break
            if text:
                client.send_message("general", text)
    except KeyboardInterrupt:
        print("\nClosing chat.")
    finally:
        if registered:
            client.unregister()


if __name__ == "__main__":
    main()

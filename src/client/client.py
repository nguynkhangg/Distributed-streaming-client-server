"""Interactive broadcast and private-messaging CCP client."""

from __future__ import annotations

import argparse
import getpass
import sys
import threading

from .messaging import MessagingClient
from .network import CcpClient
from ..common.exceptions import (
    AuthenticationError,
    HandshakeTimeoutError,
    MalformedPacketError,
)


def _display_incoming(client: MessagingClient, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            message = client.receive(timeout=0.25)
        except TimeoutError:
            continue
        except (AuthenticationError, ConnectionError):
            return

        message_type = message["type"]
        payload = message["payload"]
        if message_type == "MSG_DELIVER":
            print(
                f"\n[{payload.get('sender')} -> {payload.get('target')}] "
                f"{payload.get('text')}"
            )
        elif message_type == "PRESENCE":
            print(
                f"\n[Presence] {payload.get('username')} "
                f"{payload.get('status')}"
            )
        elif message_type == "ERROR":
            print(
                f"\n[Server error: {payload.get('code')}] "
                f"{payload.get('message')}"
            )
        elif message_type == "USER_LIST":
            usernames = ", ".join(
                user.get("username", "?") for user in payload.get("users", [])
            )
            print(f"\n[Online users] {usernames}")
        else:
            print(f"\n[{message_type}] {payload}")
        print("> ", end="", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCP UDP messaging client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--username")
    parser.add_argument(
        "--hello-attempts",
        type=int,
        default=3,
        help="number of HELLO attempts before giving up",
    )
    args = parser.parse_args(argv)

    username = args.username or input("Username: ").strip()
    password = getpass.getpass("Password: ")
    connection = CcpClient(
        args.host, args.port, hello_attempts=args.hello_attempts
    )
    client = MessagingClient(connection)
    stop_display = threading.Event()
    display_thread: threading.Thread | None = None

    try:
        client.login(username, password)
    except (HandshakeTimeoutError, AuthenticationError, TimeoutError, OSError) as exc:
        print(f"Could not log in: {exc}", file=sys.stderr)
        connection.shutdown()
        return 1

    print(f"Logged in as {client.username}.")
    print("Commands: /broadcast <message>, /private <user[,user...]> <message>,")
    print("          /users, /quit")
    display_thread = threading.Thread(
        target=_display_incoming,
        args=(client, stop_display),
        name="ccp-client-display",
        daemon=True,
    )
    display_thread.start()

    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            command, _, arguments = line.partition(" ")
            if command == "/quit":
                break
            if command == "/users":
                users = client.request_users()
                print("[Online users] " + ", ".join(
                    user.get("username", "?") for user in users
                ))
                continue
            if command == "/broadcast":
                if not arguments.strip():
                    print("Usage: /broadcast <message>")
                    continue
                try:
                    client.send_broadcast(arguments)
                except (ValueError, MalformedPacketError) as exc:
                    print(f"Could not send message: {exc}")
                continue
            if command == "/private":
                targets, separator, text = arguments.partition(" ")
                if not separator or not targets.strip() or not text.strip():
                    print("Usage: /private <user[,user...]> <message>")
                    continue
                recipients = [target.strip() for target in targets.split(",")]
                try:
                    client.send_private(recipients, text)
                except (ValueError, MalformedPacketError) as exc:
                    print(f"Could not send message: {exc}")
                continue
            print("Unknown command. Use /broadcast, /private, /users, or /quit.")
    except (KeyboardInterrupt, EOFError):
        pass
    except (ConnectionError, OSError, TimeoutError) as exc:
        print(f"Messaging connection ended: {exc}", file=sys.stderr)
    finally:
        stop_display.set()
        if display_thread is not None:
            display_thread.join(timeout=1)
        try:
            client.logout()
        except (ConnectionError, OSError, TimeoutError) as exc:
            print(f"Logout was not confirmed: {exc}", file=sys.stderr)
            connection.shutdown()
        print("Disconnected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

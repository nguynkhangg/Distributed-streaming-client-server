"""Command-line entry point of the CCP client: chat and file transfer.

Run from the repository root:
    python -m src.client.run_client_cli --host <server-ip> --port 9000
"""

from __future__ import annotations

import argparse
import getpass
import sys
import threading

from ..common.constants import DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT
from ..common.exceptions import (
    AuthenticationError,
    HandshakeTimeoutError,
    MalformedPacketError,
)
from ..file_transfer.models import TransferState
from .client import Client, IncomingTransfer, OutgoingTransfer
from .network import CcpClient

PROMPT = "> "
HELP = """Commands:
  /broadcast <message>               send a message to everyone
  /private <user[,user...]> <msg>    send a private message
  /users                             list online users
  /file <user> <path>                send a file to a user
  /accept <number>                   accept a file offered (number from /transfers)
  /reject <number>                   reject a file offered (number from /transfers)
  /transfers                         show file transfers and their progress
  /cancel <number>                   cancel a file transfer in progress (number from /transfers)
  /help                              show this help
  /quit                              log out and exit"""


def _print_async(text: str) -> None:
    print(f"\n{text}")
    print(PROMPT, end="", flush=True)


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def _describe_transfer(
    client: Client, transfer: OutgoingTransfer | IncomingTransfer
) -> str:
    metadata = transfer.record.metadata
    size = metadata.size_bytes
    done = client.transfer_progress(transfer)
    percent = 100.0 if size == 0 else done * 100 / size
    if isinstance(transfer, IncomingTransfer):
        direction = f"<- {metadata.sender}"
    else:
        direction = f"-> {metadata.target}"
    text = (
        f"{metadata.filename} {direction} [{transfer.record.state.value}] "
        f"{_format_size(done)}/{_format_size(size)} ({percent:.0f}%)"
    )
    if transfer.record.error:
        text += f" - {transfer.record.error}"
    if isinstance(transfer, IncomingTransfer) and transfer.saved_path is not None:
        text += f" - saved to {transfer.saved_path}"
    return text


def _on_transfer_event(
    client: Client, transfer: OutgoingTransfer | IncomingTransfer
) -> None:
    text = f"[File] {_describe_transfer(client, transfer)}"
    if (
        isinstance(transfer, IncomingTransfer)
        and transfer.record.state is TransferState.OFFERED
        and not transfer.responded
    ):
        number = client.transfers().index(transfer) + 1
        text += f"\n       Use /accept {number} or /reject {number}."
    _print_async(text)


def _display_incoming(client: Client, stop: threading.Event) -> None:
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
            text = (
                f"[{payload.get('sender')} -> {payload.get('target')}] "
                f"{payload.get('text')}"
            )
        elif message_type == "PRESENCE":
            text = f"[Presence] {payload.get('username')} {payload.get('status')}"
        elif message_type == "ERROR":
            text = f"[Server error: {payload.get('code')}] {payload.get('message')}"
        elif message_type == "USER_LIST":
            usernames = ", ".join(
                user.get("username", "?") for user in payload.get("users", [])
            )
            text = f"[Online users] {usernames}"
        else:
            text = f"[{message_type}] {payload}"
        _print_async(text)


def _handle_file(client: Client, arguments: str) -> None:
    target, _, path = arguments.strip().partition(" ")
    path = path.strip().strip("\"'")
    if not target or not path:
        print("Usage: /file <user> <path>")
        return
    try:
        transfer = client.send_file(path, target)
    except (ValueError, OSError, MalformedPacketError) as exc:
        print(f"Could not send file: {exc}")
        return
    metadata = transfer.record.metadata
    print(
        f"Offered {metadata.filename} ({_format_size(metadata.size_bytes)}) to "
        f"{target}; waiting for the receiver. Use /transfers to follow progress."
    )


def _handle_transfers(client: Client) -> None:
    transfers = client.transfers()
    if not transfers:
        print("No file transfers.")
    for number, transfer in enumerate(transfers, start=1):
        print(f"  {number}. {_describe_transfer(client, transfer)}")


def _pick_transfer(client: Client, arguments: str, usage: str):
    transfers = client.transfers()
    try:
        number = int(arguments.strip())
        if not 1 <= number <= len(transfers):
            raise ValueError
    except ValueError:
        print(f"Usage: {usage} (see /transfers)")
        return None
    return transfers[number - 1]


def _handle_cancel(client: Client, arguments: str) -> None:
    transfer = _pick_transfer(client, arguments, "/cancel <number>")
    if transfer is None:
        return
    try:
        if not client.cancel_file(transfer):
            print("That transfer has already finished.")
    except (ValueError, MalformedPacketError) as exc:
        print(f"Could not cancel: {exc}")


def _handle_respond(client: Client, arguments: str, accepted: bool) -> None:
    command = "/accept" if accepted else "/reject"
    transfer = _pick_transfer(client, arguments, f"{command} <number>")
    if transfer is None:
        return
    try:
        client.respond_file(transfer, accepted)
    except (ValueError, ConnectionError, OSError, MalformedPacketError) as exc:
        print(f"Could not answer the offer: {exc}")
        return
    print("Accepted; waiting for the transfer to start." if accepted else "Rejected.")


def _run_commands(client: Client) -> None:
    while True:
        line = input(PROMPT).strip()
        if not line:
            continue
        command, _, arguments = line.partition(" ")
        if command == "/quit":
            return
        if command == "/help":
            print(HELP)
        elif command == "/users":
            try:
                users = client.request_users()
            except (RuntimeError, ValueError, TimeoutError) as exc:
                print(f"Could not list users: {exc}")
                continue
            print("[Online users] " + ", ".join(
                user.get("username", "?") for user in users
            ))
        elif command == "/broadcast":
            if not arguments.strip():
                print("Usage: /broadcast <message>")
                continue
            try:
                client.send_broadcast(arguments)
            except (ValueError, MalformedPacketError) as exc:
                print(f"Could not send message: {exc}")
        elif command == "/private":
            targets, separator, text = arguments.partition(" ")
            if not separator or not targets.strip() or not text.strip():
                print("Usage: /private <user[,user...]> <message>")
                continue
            recipients = [target.strip() for target in targets.split(",")]
            try:
                client.send_private(recipients, text)
            except (ValueError, MalformedPacketError) as exc:
                print(f"Could not send message: {exc}")
        elif command == "/file":
            _handle_file(client, arguments)
        elif command == "/transfers":
            _handle_transfers(client)
        elif command == "/cancel":
            _handle_cancel(client, arguments)
        elif command in ("/accept", "/reject"):
            _handle_respond(client, arguments, command == "/accept")
        else:
            print("Unknown command. Type /help for the list of commands.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCP UDP chat and file-transfer client")
    parser.add_argument("--host", default=DEFAULT_SERVER_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT)
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
    client = Client(connection)
    client.transfer_listener = lambda transfer: _on_transfer_event(client, transfer)
    stop_display = threading.Event()

    try:
        client.login(username, password)
    except (HandshakeTimeoutError, AuthenticationError, TimeoutError, OSError) as exc:
        print(f"Could not log in: {exc}", file=sys.stderr)
        connection.shutdown()
        return 1

    print(f"Logged in as {client.username}.")
    print(HELP)
    display_thread = threading.Thread(
        target=_display_incoming,
        args=(client, stop_display),
        name="ccp-client-display",
        daemon=True,
    )
    display_thread.start()

    try:
        _run_commands(client)
    except (KeyboardInterrupt, EOFError):
        pass
    except (ConnectionError, OSError, TimeoutError) as exc:
        print(f"Connection ended: {exc}", file=sys.stderr)
    finally:
        stop_display.set()
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

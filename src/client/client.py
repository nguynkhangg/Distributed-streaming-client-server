"""Minimal interactive CCP client."""

from __future__ import annotations

import argparse
import sys

from .network import CcpClient, ConnectionState, HandshakeTimeoutError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCP UDP client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument(
        "--hello-attempts",
        type=int,
        default=3,
        help="number of HELLO attempts before giving up",
    )
    args = parser.parse_args(argv)

    client = CcpClient(args.host, args.port, hello_attempts=args.hello_attempts)
    try:
        connection_id = client.connect()
    except HandshakeTimeoutError as exc:
        print(exc, file=sys.stderr)
        client.shutdown()
        return 1

    print(f"Connected to {args.host}:{args.port} (connection_id={connection_id:#010x})")
    print("Type PING to check the connection, or QUIT to close it.")
    try:
        for line in sys.stdin:
            command = line.strip()
            if not command:
                continue
            if command.upper() == "QUIT":
                break
            if command.upper() == "PING":
                print("PONG" if client.ping() else "PING timed out")
                continue
            print("Commands: PING or QUIT")
    except KeyboardInterrupt:
        pass
    finally:
        client.shutdown()
        print("Disconnected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
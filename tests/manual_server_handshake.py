"""Manual Phase 1 check for src/server/server.py. Start the server first:

    python -m src.server.server --log-level DEBUG        # terminal 1
    python tests/manual_server_handshake.py              # terminal 2

Packets are built here with struct directly (not imported from server.py), so this
script also checks the server against the wire format in protocol-spec section 4.
"""
import argparse
import itertools
import os
import socket
import struct
import time

HEADER = struct.Struct("!HBBBBIIH")
MAGIC, VERSION = 0xA5C3, 1
HELLO, HELLO_ACK, PING, PONG, CLOSE = 0x01, 0x02, 0x05, 0x06, 0x07


def build(packet_type, connection_id, packet_number, payload=b""):
    return HEADER.pack(MAGIC, VERSION, packet_type, 0, 0, connection_id,
                       packet_number, len(payload)) + payload


def parse(data):
    magic, version, packet_type, _, _, connection_id, _, length = \
        HEADER.unpack(data[:HEADER.size])
    assert magic == MAGIC and version == VERSION, "bad magic/version in reply"
    assert length == len(data) - HEADER.size, "payload_length mismatch in reply"
    return packet_type, connection_id, data[HEADER.size:]


def expect(sock, wanted, wait=2.0):
    """Return (connection_id, payload) of the next `wanted` packet; server PINGs are skipped."""
    sock.settimeout(wait)
    while True:
        packet_type, connection_id, payload = parse(sock.recvfrom(2048)[0])
        if packet_type == wanted:
            return connection_id, payload
        assert packet_type == PING, f"expected type {wanted:#04x}, got {packet_type:#04x}"


def expect_silence(sock, wait=1.0):
    sock.settimeout(wait)
    try:
        sock.recvfrom(2048)
    except socket.timeout:
        return
    raise AssertionError("server answered a packet it should have dropped")


def wait_for_timeout_close(sock):
    """Stay silent after HELLO; the server must send CLOSE(reason=1) after ~10 s."""
    start = time.monotonic()
    sock.settimeout(15)
    while True:
        packet_type, _, payload = parse(sock.recvfrom(2048)[0])
        if packet_type == CLOSE:
            break
    assert payload == b"\x01", f"CLOSE reason should be 1 (timeout), got {payload!r}"
    print(f"CLOSE(reason=1) received after {time.monotonic() - start:.1f}s (expected ~10s)")


def main():
    parser = argparse.ArgumentParser(description="Manual handshake test client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--empty-hello", action="store_true",
                        help="dev mode: HELLO with a 0-byte payload")
    parser.add_argument("--check-timeout", action="store_true",
                        help="send HELLO, then stay silent and wait for CLOSE(timeout)")
    args = parser.parse_args()
    server = (args.host, args.port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    numbers = itertools.count(1)
    hello = b"" if args.empty_hello else os.urandom(32 + 16)

    def send(packet_type, connection_id, payload=b"", via=sock):
        via.sendto(build(packet_type, connection_id, next(numbers), payload), server)

    send(HELLO, 0, hello)
    conn_id, payload = expect(sock, HELLO_ACK)
    assert conn_id != 0 and len(payload) == 48, "bad HELLO_ACK (need 32B key + 16B nonce)"
    print(f"1. HELLO -> HELLO_ACK ok (connection_id={conn_id:#010x})")

    if args.check_timeout:
        wait_for_timeout_close(sock)
        return

    send(HELLO, 0, hello)                          # pretend the first HELLO_ACK was lost
    again, _ = expect(sock, HELLO_ACK)
    assert again == conn_id, "retransmitted HELLO created a second session"
    print("2. HELLO retransmission -> same connection_id ok")

    send(PING, conn_id)
    expect(sock, PONG)
    print("3. PING -> PONG ok")

    other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send(PING, conn_id, via=other)                 # right connection_id, wrong (ip, port)
    expect_silence(other)
    print("4. PING from another port with the same connection_id dropped ok")

    send(CLOSE, conn_id, b"\x00")
    time.sleep(0.2)
    send(PING, conn_id)
    expect_silence(sock)
    print("5. CLOSE removed the session; later PING dropped ok")
    print("ALL PASS")


if __name__ == "__main__":
    main()

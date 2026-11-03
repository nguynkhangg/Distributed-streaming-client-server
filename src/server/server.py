"""CCP server over UDP: receive loop, handshake, heartbeat (protocol-spec sections 4, 6, 7, 16).

Phase 1 scope: HELLO/HELLO_ACK, PING/PONG, CLOSE and timeout sweeping.
DATA and ACK handlers are placeholders for Phase 2 (stream layer, AUTH).
"""
from __future__ import annotations

import argparse
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass
from enum import IntEnum

try:
    from .session_manager import (KEY_SIZE, NONCE_SIZE, Address, ClientSession,
                                  CloseReason, RemoveResult, SessionLimitError,
                                  SessionManager)
except ImportError:  # run directly as a script: python src/server/server.py
    from session_manager import (KEY_SIZE, NONCE_SIZE, Address, ClientSession,
                                 CloseReason, RemoveResult, SessionLimitError,
                                 SessionManager)

from ..security.concurrency import shutdown_workers, submit_datagram
from ..security.encryption import (DIR_C2S,DIR_S2C,GCM_TAG_SIZE,
                                   CryptoError,derive_keys,derive_session_keys,
                                   open as gcm_open,seal,x25519_shared_secret)

log = logging.getLogger("ccp.server")

# ---- TEMP wire-format helpers: delete and import from src/common/protocol.py once merged ----
MAGIC = 0xA5C3
VERSION = 1
HEADER_FORMAT = "!HBBBBIIH"                      # big-endian, no padding
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)     # 16
MAX_DATAGRAM = 1200
MAX_PAYLOAD = MAX_DATAGRAM - HEADER_SIZE         # 1184

FLAG_FIN = 0x01
FLAG_ENC = 0x02


class PacketType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    DATA = 0x03
    ACK = 0x04
    PING = 0x05
    PONG = 0x06
    CLOSE = 0x07


class PacketError(ValueError):
    """Datagram violates the CCP packet format and must be dropped."""


@dataclass(frozen=True)
class PacketHeader:
    packet_type: PacketType
    connection_id: int
    packet_number: int
    payload_length: int
    flags: int = 0
    version: int = VERSION
    magic: int = MAGIC
    reserved: int = 0


def pack_packet(packet_type: PacketType, connection_id: int, packet_number: int,
                payload: bytes = b"", flags: int = 0) -> bytes:
    """Build header + payload into one datagram."""
    if len(payload) > MAX_PAYLOAD:
        raise PacketError(f"payload too large: {len(payload)}")
    header = struct.pack(HEADER_FORMAT, MAGIC, VERSION, int(packet_type), flags,
                         0, connection_id, packet_number, len(payload))
    return header + payload


def unpack_packet(data: bytes) -> tuple[PacketHeader, bytes]:
    """Validate a raw datagram and return (header, payload). Raise PacketError to drop."""
    if len(data) < HEADER_SIZE:
        raise PacketError("datagram shorter than header")
    if len(data) > MAX_DATAGRAM:
        raise PacketError("datagram exceeds max size")

    magic, version, raw_type, flags, reserved, conn_id, pkt_num, payload_len = \
        struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])

    if magic != MAGIC:
        raise PacketError("bad magic")
    if version != VERSION:
        raise PacketError("unsupported version")
    try:
        packet_type = PacketType(raw_type)
    except ValueError:
        raise PacketError("unknown packet type") from None
    if payload_len != len(data) - HEADER_SIZE:
        raise PacketError("payload_length mismatch")

    header = PacketHeader(packet_type, conn_id, pkt_num, payload_len,
                          flags, version, magic, reserved)
    return header, data[HEADER_SIZE:]
# ---- end TEMP ----

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9000
RECV_BUFFER = 65535       # larger than MAX_DATAGRAM so oversize datagrams are seen, not truncated
SOCKET_TIMEOUT = 1.0      # lets the loop notice shutdown and Ctrl+C
SWEEP_INTERVAL = 1.0


class CcpServer:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
        self._sessions = SessionManager()
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.bind((host, port))
        except OSError:
            self._sock.close()
            raise
        self._sock.settimeout(SOCKET_TIMEOUT)
        self._handlers = {
            PacketType.DATA: self._on_data,
            PacketType.ACK: self._on_ack,
            PacketType.PING: self._on_ping,
            PacketType.PONG: self._on_pong,
            PacketType.CLOSE: self._on_close,
        }
        log.info("listening on udp://%s:%d", *self.address)

    @property
    def address(self) -> Address:
        return self._sock.getsockname()[:2]

    # ---- main loops ---------------------------------------------------

    def serve_forever(self) -> None:
        threading.Thread(target=self._sweep_loop, name="sweeper", daemon=True).start()
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(RECV_BUFFER)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue   # Windows: ICMP "port unreachable" from an earlier sendto, not a fault here
            except OSError as exc:
                if self._stop.is_set():
                    break  # socket closed by shutdown()
                log.error("recvfrom failed: %s", exc)
                time.sleep(0.1)
                continue
            # Bounded pool so one slow client does not block recv (CSR concurrency)
            submit_datagram(self._handle_datagram_safe, data, addr)

    def _handle_datagram_safe(self, data: bytes, addr: Address) -> None:
        try:
            self._handle_datagram(data, addr)
        except Exception:  # section 16: one bad client must never stop the server
            log.exception("error while handling datagram from %s", addr)

    def shutdown(self) -> None:
        """Stop the loops, send CLOSE(server shutdown) to every client, release the socket."""
        self._stop.set()
        for result in self._sessions.remove_all():
            self._send_close(result.session, CloseReason.SERVER_SHUTDOWN)
        shutdown_workers(wait=False)
        self._sock.close()

    def _sweep_loop(self) -> None:
        while not self._stop.wait(SWEEP_INTERVAL):
            try:
                self._sweep_once()
            except Exception:
                log.exception("sweeper error")

    def _sweep_once(self) -> None:
        now = time.monotonic()
        for session in self._sessions.find_expired(now):
            # remove_session is the single arbiter: only one thread gets a result per session
            result = self._sessions.remove_session(session.connection_id)
            if result is None:
                continue
            self._send_close(session, CloseReason.TIMEOUT)
            self._handle_removed(result, "timeout")
        for session in self._sessions.find_idle(now):
            self._send(session, PacketType.PING)    # section 6: idle endpoint pings after 5 s

    # ---- datagram dispatch -------------------------------------------

    def _handle_datagram(self, data: bytes, addr: Address) -> None:
        try:
            header, payload = unpack_packet(data)
        except PacketError as exc:
            log.debug("drop datagram from %s: %s", addr, exc)    # section 16: drop silently
            return
        if header.packet_type is PacketType.HELLO:
            self._on_hello(header, payload, addr)
            return
        session = self._sessions.lookup(header.connection_id, addr)
        if session is None:
            log.debug("drop %s from %s: unknown connection_id/address",
                      header.packet_type.name, addr)
            return
        if header.flags & FLAG_ENC:
            if session.key_c2s is None:
                log.debug("drop %s from %s: ENC before keys ready",
                          header.packet_type.name, addr)
                return
            try:
                payload = gcm_open(
                    session.key_c2s,
                    header.packet_number,
                    data[:HEADER_SIZE],
                    payload,
                    direction=DIR_C2S,
                )
            except CryptoError:
                log.debug("drop %s from %s: GCM auth failed",
                          header.packet_type.name, addr)
                return
        handler = self._handlers.get(header.packet_type)
        if handler is None:
            log.debug("drop %s from %s: not valid client-to-server",
                      header.packet_type.name, addr)
            return
        session.touch()    # only after the packet passed every check (and decryption, later)
        handler(session, payload)

    def _on_hello(self, header: PacketHeader, payload: bytes, addr: Address) -> None:
        if header.connection_id != 0:
            log.debug("drop HELLO from %s: connection_id must be 0", addr)
            return
        if not payload:                    # dev mode (section 12): placeholder key and nonce
            client_key, client_nonce = bytes(KEY_SIZE), bytes(NONCE_SIZE)
        elif len(payload) == KEY_SIZE + NONCE_SIZE:
            client_key, client_nonce = payload[:KEY_SIZE], payload[KEY_SIZE:]
        else:
            log.debug("drop HELLO from %s: payload must be 0 or %d bytes",
                      addr, KEY_SIZE + NONCE_SIZE)
            return
        try:
            result = self._sessions.get_or_create_session(addr, client_key, client_nonce)
        except SessionLimitError:
            log.warning("session table full, drop HELLO from %s", addr)
            return
        if result.replaced is not None:
            self._handle_removed(result.replaced, "client restarted")
        session = result.session
        if result.is_new:
            # Real X25519 when client sent a non-zero public key; else compat fallback
            if (
                session.server_private_key is not None
                and session.client_public_key != bytes(KEY_SIZE)
            ):
                shared = x25519_shared_secret(
                    session.server_private_key, session.client_public_key
                )
                session.key_c2s, session.key_s2c = derive_session_keys(
                    shared, session.client_nonce, session.server_nonce
                )
            else:
                session.key_c2s, session.key_s2c = derive_keys(
                    session.client_public_key,
                    session.server_public_key,
                    session.client_nonce,
                    session.server_nonce,
                )
            log.info("new session %08x for %s:%d", session.connection_id, *addr)
        else:
            log.debug("HELLO retransmission from %s: resend HELLO_ACK", addr)
        self._send(session, PacketType.HELLO_ACK,
                   session.server_public_key + session.server_nonce)

    def _on_ping(self, session: ClientSession, payload: bytes) -> None:
        self._send(session, PacketType.PONG)

    def _on_pong(self, session: ClientSession, payload: bytes) -> None:
        pass    # touch() in the dispatcher already refreshed last_recv

    def _on_close(self, session: ClientSession, payload: bytes) -> None:
        result = self._sessions.remove_session(session.connection_id)
        if result is not None:
            self._handle_removed(result, "client CLOSE")

    def _on_data(self, session: ClientSession, payload: bytes) -> None:
        log.debug("DATA from %s (%d bytes): stream layer not implemented yet",
                  session.address, len(payload))

    def _on_ack(self, session: ClientSession, payload: bytes) -> None:
        log.debug("ACK from %s: reliability layer not implemented yet", session.address)

    # ---- helpers ------------------------------------------------------

    def _handle_removed(self, result: RemoveResult, why: str) -> None:
        session = result.session
        log.info("session %08x (%s:%d) closed: %s", session.connection_id, *session.address, why)
        # Phase 2: if result.went_offline -> broadcast PRESENCE offline and cancel transfers.

    def _send(self, session: ClientSession, packet_type: PacketType,
              payload: bytes = b"") -> None:
        pn = session.allocate_packet_number()
        # HELLO/HELLO_ACK stay plaintext; everything else uses ENC once keys exist
        use_enc = (
            session.key_s2c is not None
            and packet_type not in (PacketType.HELLO, PacketType.HELLO_ACK)
        )
        if use_enc:
            sealed_len = len(payload) + GCM_TAG_SIZE
            header16 = struct.pack(HEADER_FORMAT,MAGIC,VERSION,
                                   int(packet_type),FLAG_ENC,0,
                                   session.connection_id,pn,sealed_len)
            body = seal(session.key_s2c, pn, header16, payload, direction=DIR_S2C)
            raw = header16 + body
        else:
            raw = pack_packet(packet_type,session.connection_id,pn,payload,0)
        try:
            self._sock.sendto(raw, session.address)
        except OSError as exc:
            log.warning("send %s to %s failed: %s", packet_type.name, session.address, exc)

    def _send_close(self, session: ClientSession, reason: CloseReason) -> None:
        self._send(session, PacketType.CLOSE, bytes([reason]))    # CLOSE is never retransmitted


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CCP collaboration server (UDP)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        server = CcpServer(args.host, args.port)
    except OSError as exc:
        log.error("cannot bind %s:%d: %s", args.host, args.port, exc)
        return 1
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

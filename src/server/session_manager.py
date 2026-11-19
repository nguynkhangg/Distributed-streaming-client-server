"""Session table for the CCP server (protocol-spec sections 6, 7, 9 and 15).

One UDP socket serves every client, so there is no accept() to separate
peers. A session is found by connection_id and is only valid when the
datagram also comes from the recorded (ip, port).

All deadlines use time.monotonic(): it never jumps when the wall clock is
adjusted (NTP, manual change), so timeouts cannot fire early or never fire.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, IntEnum

try:
    from ..file_transfer.reliability import AckTracker
    from .stream_layer import SendBuffer, StreamReceiver
except ImportError:
    from src.file_transfer.reliability import AckTracker
    from stream_layer import SendBuffer, StreamReceiver

Address = tuple[str, int]

AUTH_DEADLINE = 10.0          # seconds after handshake to send AUTH (section 7)
HEARTBEAT_TIMEOUT = 15.0      # silence before a peer is considered dead (section 6)
PING_INTERVAL = 5.0           # idle time before the server sends PING (section 6)
MAX_AUTH_FAILURES = 5         # failed AUTH attempts before CLOSE (section 9, rule 5)
MAX_PACKET_NUMBER = 0xFFFFFFFF
NONCE_SIZE = 16
KEY_SIZE = 32
DEFAULT_MAX_SESSIONS = 1024


class SessionState(Enum):
    ESTABLISHED = "established"        # handshake done, not authenticated
    AUTHENTICATED = "authenticated"
    CLOSED = "closed"


class CloseReason(IntEnum):
    """One-byte reason code of the CLOSE packet (section 4)."""
    NORMAL = 0
    TIMEOUT = 1
    PROTOCOL_ERROR = 2
    SERVER_SHUTDOWN = 3


class BindResult(Enum):
    OK = "ok"
    ALREADY_LOGGED_IN = "already_logged_in"        # username owned by another connection
    ALREADY_AUTHENTICATED = "already_authenticated"  # this connection already logged in
    INVALID_STATE = "invalid_state"                # closed or unknown session


class SessionLimitError(RuntimeError):
    """Session table is full; the HELLO should be dropped."""


class PacketNumberExhausted(RuntimeError):
    """4-byte packet number space is used up; the connection must be closed.

    A packet number must never repeat because it is part of the AES-GCM nonce.
    """


@dataclass(eq=False)
class ClientSession:
    connection_id: int
    address: Address
    client_public_key: bytes
    client_nonce: bytes
    server_public_key: bytes
    server_nonce: bytes
    server_private_key: bytes | None = None  # X25519; needed for ECDH
    state: SessionState = SessionState.ESTABLISHED
    username: str | None = None
    failed_auth_count: int = 0
    next_packet_number: int = 0
    # Filled after HELLO (derive_session_keys or derive_keys fallback)
    key_c2s: bytes | None = None
    key_s2c: bytes | None = None
    use_encryption: bool = False
    wire_mode: str = "packet"
    # Packet numbers received from this client: used to ACK DATA and drop resent duplicates.
    ack_tracker: AckTracker = field(default_factory=AckTracker, repr=False)
    # Client -> server control/chat streams (by stream id): ordering, duplicates, framing.
    recv_streams: dict[int, StreamReceiver] = field(default_factory=dict, repr=False)
    # Server -> client control/chat frames waiting for an ACK, and their next offsets.
    send_buf: SendBuffer = field(default_factory=SendBuffer, repr=False)
    # Datagrams of one client are handled one at a time (the worker pool is shared).
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    # Taken while a frame gets its offset and packet number, so both stay in the same order.
    send_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    created_at: float = field(default_factory=time.monotonic)
    last_recv: float = field(default_factory=time.monotonic)
    last_send: float = field(default_factory=time.monotonic)
    _pn_lock: threading.Lock = field(
        init=False, repr=False, default_factory=threading.Lock)

    def allocate_packet_number(self) -> int:
        """Return the next server-to-client packet number (never reused)."""
        with self._pn_lock:
            if self.next_packet_number > MAX_PACKET_NUMBER:
                raise PacketNumberExhausted(self.connection_id)
            number = self.next_packet_number
            self.next_packet_number += 1
        self.last_send = time.monotonic()
        return number

    def touch(self) -> None:
        """Record activity. Call only after the packet passed validation/decryption."""
        self.last_recv = time.monotonic()


@dataclass(frozen=True)
class RemoveResult:
    session: ClientSession
    went_offline: bool     # True only if this removal released the username


@dataclass(frozen=True)
class HelloResult:
    session: ClientSession
    is_new: bool                       # False: HELLO retransmission, resend same HELLO_ACK
    replaced: RemoveResult | None = None   # old session of a restarted client at same address


class SessionManager:
    def __init__(self, max_sessions: int = DEFAULT_MAX_SESSIONS,
                 server_key_factory: Callable[[], bytes] | None = None) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[int, ClientSession] = {}
        self._by_address: dict[Address, int] = {}
        self._by_username: dict[str, int] = {}
        self._max_sessions = max_sessions
        # Called once per new session to get the server X25519 public key.
        self._server_key_factory = server_key_factory

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    # ---- handshake ----------------------------------------------------

    def get_or_create_session(self, address: Address, client_public_key: bytes,
                              client_nonce: bytes) -> HelloResult:
        """Handle HELLO. Same (address, client_nonce) maps to the same session."""
        if len(client_public_key) != KEY_SIZE or len(client_nonce) != NONCE_SIZE:
            raise ValueError("invalid HELLO payload sizes")
        with self._lock:
            existing_id = self._by_address.get(address)
            replaced = None
            if existing_id is not None:
                existing = self._by_id[existing_id]
                if existing.client_nonce == client_nonce:
                    return HelloResult(existing, is_new=False)   # lost HELLO_ACK
                replaced = self._remove_locked(existing_id)      # client restarted
            elif len(self._by_id) >= self._max_sessions:
                raise SessionLimitError("too many sessions")

            connection_id = self._new_connection_id_locked()
            if self._server_key_factory is not None:
                server_public = self._server_key_factory()
                server_private = None
            else:
                from ..security.encryption import generate_x25519_keypair

                server_private, server_public = generate_x25519_keypair()
            session = ClientSession(
                connection_id=connection_id,
                address=address,
                client_public_key=client_public_key,
                client_nonce=client_nonce,
                server_public_key=server_public,
                server_nonce=secrets.token_bytes(NONCE_SIZE),
                server_private_key=server_private,
            )
            self._by_id[connection_id] = session
            self._by_address[address] = connection_id
            return HelloResult(session, is_new=True, replaced=replaced)

    def _new_connection_id_locked(self) -> int:
        # Unpredictable and non-zero (0 is reserved for HELLO).
        while True:
            candidate = secrets.randbits(32)
            if candidate != 0 and candidate not in self._by_id:
                return candidate

    # ---- lookup -------------------------------------------------------

    def lookup(self, connection_id: int, address: Address) -> ClientSession | None:
        """Return the session only if both connection_id and source address match."""
        with self._lock:
            session = self._by_id.get(connection_id)
        if session is None or session.address != address:
            return None
        return session

    def get_by_username(self, username: str) -> ClientSession | None:
        with self._lock:
            connection_id = self._by_username.get(username)
            return self._by_id.get(connection_id) if connection_id is not None else None

    def all_sessions(self) -> list[ClientSession]:
        with self._lock:
            return list(self._by_id.values())

    def authenticated_sessions(self) -> list[ClientSession]:
        with self._lock:
            return [self._by_id[cid] for cid in self._by_username.values()]

    def online_users(self) -> list[dict]:
        """Payload entries for USER_LIST."""
        return [{"username": s.username, "ip": s.address[0],
                 "port": s.address[1], "status": "online"}
                for s in self.authenticated_sessions()]

    # ---- authentication state ----------------------------------------

    def bind_username(self, session: ClientSession, username: str) -> BindResult:
        """Atomically claim a username (check and set under one lock)."""
        with self._lock:
            if session.state is SessionState.AUTHENTICATED:
                return BindResult.ALREADY_AUTHENTICATED
            if (session.state is not SessionState.ESTABLISHED
                    or self._by_id.get(session.connection_id) is not session):
                return BindResult.INVALID_STATE
            if username in self._by_username:
                return BindResult.ALREADY_LOGGED_IN
            self._by_username[username] = session.connection_id
            session.username = username
            session.state = SessionState.AUTHENTICATED
            session.failed_auth_count = 0
            return BindResult.OK

    def record_auth_failure(self, session: ClientSession) -> int:
        """Return the failure count; caller closes at MAX_AUTH_FAILURES."""
        with self._lock:
            session.failed_auth_count += 1
            return session.failed_auth_count

    # ---- removal and timeouts ----------------------------------------

    def remove_session(self, connection_id: int) -> RemoveResult | None:
        """Idempotent. None means it was already removed: emit no second PRESENCE."""
        with self._lock:
            return self._remove_locked(connection_id)

    def remove_all(self) -> list[RemoveResult]:
        """Graceful shutdown: empty the table and return what was removed."""
        with self._lock:
            return [r for cid in list(self._by_id)
                    if (r := self._remove_locked(cid)) is not None]

    def _remove_locked(self, connection_id: int) -> RemoveResult | None:
        session = self._by_id.pop(connection_id, None)
        if session is None:
            return None
        if self._by_address.get(session.address) == connection_id:
            del self._by_address[session.address]
        # Rule 10 (section 9): release the username only if this connection owns it.
        went_offline = False
        if (session.username is not None
                and self._by_username.get(session.username) == connection_id):
            del self._by_username[session.username]
            went_offline = True
        session.state = SessionState.CLOSED
        return RemoveResult(session, went_offline)

    def find_expired(self, now: float | None = None) -> list[ClientSession]:
        """Sessions past the auth deadline or the heartbeat timeout."""
        now = time.monotonic() if now is None else now
        with self._lock:
            return [s for s in self._by_id.values()
                    if now - s.last_recv > HEARTBEAT_TIMEOUT
                    or (s.state is SessionState.ESTABLISHED
                        and now - s.created_at > AUTH_DEADLINE)]

    def find_idle(self, now: float | None = None) -> list[ClientSession]:
        """Sessions the server has not sent anything to for PING_INTERVAL."""
        now = time.monotonic() if now is None else now
        with self._lock:
            return [s for s in self._by_id.values()
                    if now - s.last_send > PING_INTERVAL]

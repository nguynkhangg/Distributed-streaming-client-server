"""Session table for the CCP server (protocol-spec §6, §7, §9, §15).

One UDP socket serves every client: sessions are keyed by connection_id and
validated against the recorded (ip, port). Deadlines use time.monotonic().
"""
from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum

from ..security.encryption import CryptoError, derive_keys, new_keypair

Address = tuple[str, int]

AUTH_DEADLINE = 10.0
HEARTBEAT_TIMEOUT = 15.0
PING_INTERVAL = 5.0
MAX_AUTH_FAILURES = 5
MAX_PACKET_NUMBER = 0xFFFFFFFF
NONCE_SIZE = 16
KEY_SIZE = 32
DEFAULT_MAX_SESSIONS = 1024


class SessionState(Enum):
    ESTABLISHED = "established"
    AUTHENTICATED = "authenticated"
    CLOSED = "closed"


class CloseReason(IntEnum):
    NORMAL = 0
    TIMEOUT = 1
    PROTOCOL_ERROR = 2
    SERVER_SHUTDOWN = 3


class BindResult(Enum):
    OK = "ok"
    ALREADY_LOGGED_IN = "already_logged_in"
    ALREADY_AUTHENTICATED = "already_authenticated"
    INVALID_STATE = "invalid_state"


class SessionLimitError(RuntimeError):
    pass


class PacketNumberExhausted(RuntimeError):
    pass


@dataclass(eq=False)
class ClientSession:
    connection_id: int
    address: Address
    client_public_key: bytes
    client_nonce: bytes
    server_public_key: bytes
    server_nonce: bytes
    state: SessionState = SessionState.ESTABLISHED
    username: str | None = None
    failed_auth_count: int = 0
    next_packet_number: int = 0
    key_c2s: bytes | None = None
    key_s2c: bytes | None = None
    stream_offsets: dict[int, int] = field(default_factory=dict)
    pending: deque = field(default_factory=deque)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _drain_active: bool = field(default=False, repr=False, init=False)
    created_at: float = field(default_factory=time.monotonic)
    last_recv: float = field(default_factory=time.monotonic)
    last_send: float = field(default_factory=time.monotonic)
    _pn_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def allocate_packet_number(self) -> int:
        with self._pn_lock:
            if self.next_packet_number > MAX_PACKET_NUMBER:
                raise PacketNumberExhausted(self.connection_id)
            number = self.next_packet_number
            self.next_packet_number += 1
        self.last_send = time.monotonic()
        return number

    def touch(self) -> None:
        self.last_recv = time.monotonic()

    def clear_keys(self) -> None:
        self.key_c2s = None
        self.key_s2c = None

    @property
    def closed(self) -> bool:
        return self.state is SessionState.CLOSED


@dataclass(frozen=True)
class RemoveResult:
    session: ClientSession
    went_offline: bool


@dataclass(frozen=True)
class HelloResult:
    session: ClientSession
    is_new: bool
    replaced: RemoveResult | None = None


class SessionManager:
    def __init__(self, max_sessions: int = DEFAULT_MAX_SESSIONS) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[int, ClientSession] = {}
        self._by_address: dict[Address, int] = {}
        self._by_username: dict[str, int] = {}
        self._max_sessions = max_sessions

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    def get_or_create_session(
        self, address: Address, client_public_key: bytes, client_nonce: bytes
    ) -> HelloResult:
        """HELLO → same (address, nonce) reuses session; keys derived before publish."""
        if len(client_public_key) != KEY_SIZE or len(client_nonce) != NONCE_SIZE:
            raise ValueError("invalid HELLO payload sizes")

        private, public = new_keypair()
        server_nonce = secrets.token_bytes(NONCE_SIZE)
        try:
            key_c2s, key_s2c = derive_keys(
                private, client_public_key, client_nonce, server_nonce
            )
        except CryptoError:
            raise

        with self._lock:
            existing_id = self._by_address.get(address)
            replaced = None
            if existing_id is not None:
                existing = self._by_id[existing_id]
                if existing.client_nonce == client_nonce:
                    return HelloResult(existing, is_new=False)
                replaced = self._remove_locked(existing_id)
            elif len(self._by_id) >= self._max_sessions:
                raise SessionLimitError("too many sessions")

            connection_id = self._new_connection_id_locked()
            session = ClientSession(
                connection_id=connection_id,
                address=address,
                client_public_key=client_public_key,
                client_nonce=client_nonce,
                server_public_key=public,
                server_nonce=server_nonce,
                key_c2s=key_c2s,
                key_s2c=key_s2c,
            )
            self._by_id[connection_id] = session
            self._by_address[address] = connection_id
            return HelloResult(session, is_new=True, replaced=replaced)

    def _new_connection_id_locked(self) -> int:
        while True:
            candidate = secrets.randbits(32)
            if candidate != 0 and candidate not in self._by_id:
                return candidate

    def lookup(self, connection_id: int, address: Address) -> ClientSession | None:
        with self._lock:
            session = self._by_id.get(connection_id)
        if session is None or session.address != address:
            return None
        return session

    def get_by_username(self, username: str) -> ClientSession | None:
        with self._lock:
            cid = self._by_username.get(username)
            return self._by_id.get(cid) if cid is not None else None

    def all_sessions(self) -> list[ClientSession]:
        with self._lock:
            return list(self._by_id.values())

    def authenticated_sessions(self) -> list[ClientSession]:
        with self._lock:
            return [self._by_id[cid] for cid in self._by_username.values()]

    def online_users(self) -> list[dict]:
        return [
            {
                "username": s.username,
                "ip": s.address[0],
                "port": s.address[1],
                "status": "online",
            }
            for s in self.authenticated_sessions()
        ]

    def bind_username(self, session: ClientSession, username: str) -> BindResult:
        with self._lock:
            if session.state is SessionState.AUTHENTICATED:
                return BindResult.ALREADY_AUTHENTICATED
            if (
                session.state is not SessionState.ESTABLISHED
                or self._by_id.get(session.connection_id) is not session
            ):
                return BindResult.INVALID_STATE
            if username in self._by_username:
                return BindResult.ALREADY_LOGGED_IN
            self._by_username[username] = session.connection_id
            session.username = username
            session.state = SessionState.AUTHENTICATED
            session.failed_auth_count = 0
            return BindResult.OK

    def record_auth_failure(self, session: ClientSession) -> int:
        with self._lock:
            session.failed_auth_count += 1
            return session.failed_auth_count

    def remove_session(self, connection_id: int) -> RemoveResult | None:
        with self._lock:
            return self._remove_locked(connection_id)

    def remove_all(self) -> list[RemoveResult]:
        with self._lock:
            return [
                r
                for cid in list(self._by_id)
                if (r := self._remove_locked(cid)) is not None
            ]

    def _remove_locked(self, connection_id: int) -> RemoveResult | None:
        session = self._by_id.pop(connection_id, None)
        if session is None:
            return None
        if self._by_address.get(session.address) == connection_id:
            del self._by_address[session.address]
        went_offline = False
        if (
            session.username is not None
            and self._by_username.get(session.username) == connection_id
        ):
            del self._by_username[session.username]
            went_offline = True
        session.state = SessionState.CLOSED
        session.clear_keys()
        return RemoveResult(session, went_offline)

    def find_expired(self, now: float | None = None) -> list[ClientSession]:
        now = time.monotonic() if now is None else now
        with self._lock:
            return [
                s
                for s in self._by_id.values()
                if now - s.last_recv > HEARTBEAT_TIMEOUT
                or (
                    s.state is SessionState.ESTABLISHED
                    and now - s.created_at > AUTH_DEADLINE
                )
            ]

    def find_idle(self, now: float | None = None) -> list[ClientSession]:
        now = time.monotonic() if now is None else now
        with self._lock:
            return [
                s for s in self._by_id.values() if now - s.last_send > PING_INTERVAL
            ]

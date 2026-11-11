"""User credential management and PBKDF2-HMAC-SHA256 authentication for CCP server."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

log = logging.getLogger("ccp.auth")

PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16
DIGEST_SIZE = 32
USERS_FILE_VERSION = 1

# Allow 2..32 lowercase alphanumeric/underscore characters (e.g. "an", "quoc", "khang").
# Broadcast symbol "*" is automatically excluded by this pattern.
USERNAME_PATTERN = re.compile(r"[a-z0-9_]{2,32}")
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 128

DEMO_USERNAMES = ("alice", "bob", "carol", "dave", "quoc", "khang", "nhat", "tri", "an")
DEFAULT_DEMO_PASSWORD = os.environ.get("CCP_DEMO_PASSWORD", "123456")


class UsersFileError(ValueError):
    """Raised when the JSON user database cannot be parsed or validated."""


class InvalidUsernameError(ValueError):
    """Raised when a username violates format constraints."""


class InvalidPasswordError(ValueError):
    """Raised when a password violates length or encoding constraints."""


class UserExistsError(ValueError):
    """Raised when registering a username that is already present."""


class RegisterResult(Enum):
    OK = "ok"
    INVALID_USERNAME = "invalid_username"
    INVALID_PASSWORD = "invalid_password"
    USERNAME_TAKEN = "username_taken"


@dataclass(frozen=True)
class UserRecord:
    username: str
    salt_hex: str
    hash_hex: str
    iterations: int = PBKDF2_ITERATIONS

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def hash_password(
    password: str,
    salt: bytes | None = None,
    iterations: int = PBKDF2_ITERATIONS,
) -> tuple[bytes, bytes]:
    """Derive a 32-byte key from password using PBKDF2-HMAC-SHA256."""
    raw_salt = secrets.token_bytes(SALT_SIZE) if salt is None else salt
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        raw_salt,
        iterations,
    )
    return raw_salt, derived


def make_record(
    username: str,
    password: str,
    iterations: int = PBKDF2_ITERATIONS,
) -> UserRecord:
    salt, digest = hash_password(password, iterations=iterations)
    return UserRecord(
        username=username,
        salt_hex=salt.hex(),
        hash_hex=digest.hex(),
        iterations=iterations,
    )


def verify_password(password: str, record: UserRecord) -> bool:
    """Verify password against stored UserRecord in constant time."""
    try:
        salt_bytes = bytes.fromhex(record.salt_hex)
        expected_bytes = bytes.fromhex(record.hash_hex)
        _, candidate_bytes = hash_password(password, salt_bytes, record.iterations)
    except (UnicodeEncodeError, ValueError):
        return False
    return hmac.compare_digest(candidate_bytes, expected_bytes)


def is_valid_username(username: object) -> bool:
    if not isinstance(username, str):
        return False
    return USERNAME_PATTERN.fullmatch(username) is not None


def is_valid_password(password: object) -> bool:
    if not isinstance(password, str):
        return False
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return False
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _validate_record(record: UserRecord) -> None:
    if not is_valid_username(record.username):
        raise ValueError(f"invalid username {record.username!r}")
    if type(record.iterations) is not int or record.iterations <= 0:
        raise ValueError("iterations must be a positive integer")
    salt = bytes.fromhex(record.salt_hex)
    digest = bytes.fromhex(record.hash_hex)
    if len(salt) != SALT_SIZE or len(digest) != DIGEST_SIZE:
        raise ValueError("unexpected salt or digest length")


class UserStore:
    """Thread-safe user store backed by salted PBKDF2 hashes and optional JSON storage."""

    def __init__(
        self,
        path: str | os.PathLike | None = None,
        seed_defaults: bool = False,
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._users: dict[str, UserRecord] = {}
        self._fallback_record = make_record("fallback_user", secrets.token_urlsafe(16))

        if self._path is not None and self._path.exists():
            self._users = self._read_file(self._path)
            log.info("loaded %d user account(s) from %s", len(self._users), self._path)
        elif seed_defaults:
            self.seed_demo_users(DEFAULT_DEMO_PASSWORD)

    def user_exists(self, username: str) -> bool:
        with self._lock:
            return username in self._users

    def usernames(self) -> list[str]:
        with self._lock:
            return sorted(self._users.keys())

    def verify_credentials(self, username: str, password: str) -> bool:
        if not isinstance(username, str) or not isinstance(password, str):
            return False
        if len(password) > MAX_PASSWORD_LENGTH:
            return False
        with self._lock:
            record = self._users.get(username)
        if record is None:
            # Run dummy PBKDF2 check so unknown usernames take comparable time
            verify_password(password, self._fallback_record)
            return False
        return verify_password(password, record)

    def add_user(self, username: str, password: str) -> UserRecord:
        if not is_valid_username(username):
            raise InvalidUsernameError(f"invalid username: {username!r}")
        if not is_valid_password(password):
            raise InvalidPasswordError(
                f"password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}"
            )
        record = make_record(username, password)
        with self._lock:
            if username in self._users:
                raise UserExistsError(f"user {username!r} already exists")
            self._users[username] = record
        return record

    def register_user(self, username: str, password: str) -> RegisterResult:
        try:
            self.add_user(username, password)
        except InvalidUsernameError:
            return RegisterResult.INVALID_USERNAME
        except InvalidPasswordError:
            return RegisterResult.INVALID_PASSWORD
        except UserExistsError:
            return RegisterResult.USERNAME_TAKEN
        self.save()
        return RegisterResult.OK

    def seed_demo_users(self, password: str = DEFAULT_DEMO_PASSWORD) -> list[str]:
        created: list[str] = []
        for uname in DEMO_USERNAMES:
            try:
                self.add_user(uname, password)
                created.append(uname)
            except UserExistsError:
                continue
        if created:
            self.save()
        return created

    def save(self) -> None:
        if self._path is None:
            return
        with self._lock:
            payload = {
                "version": USERS_FILE_VERSION,
                "users": [rec.to_dict() for rec in self._users.values()],
            }
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, indent=2)
            os.replace(tmp_path, self._path)

    @staticmethod
    def _read_file(path: Path) -> dict[str, UserRecord]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("root JSON value must be an object")

            users_Entry = raw.get("users")
            loaded: dict[str, UserRecord] = {}

            # Support both list-of-records format (version 1) and dict format
            if isinstance(users_Entry, list):
                if raw.get("version") != USERS_FILE_VERSION:
                    raise ValueError("unsupported users file version")
                for item in users_Entry:
                    rec = UserRecord(
                        username=item["username"],
                        salt_hex=item["salt_hex"],
                        hash_hex=item["hash_hex"],
                        iterations=int(item.get("iterations", PBKDF2_ITERATIONS)),
                    )
                    _validate_record(rec)
                    if rec.username in loaded:
                        raise ValueError(f"duplicate username {rec.username!r}")
                    loaded[rec.username] = rec
            elif isinstance(users_Entry, dict):
                for uname, item in users_Entry.items():
                    rec = UserRecord(
                        username=uname,
                        salt_hex=item.get("salt_hex") or item["salt"],
                        hash_hex=item.get("hash_hex") or item["hash"],
                        iterations=int(item.get("iterations", PBKDF2_ITERATIONS)),
                    )
                    _validate_record(rec)
                    loaded[rec.username] = rec
            else:
                raise ValueError("missing 'users' collection")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise UsersFileError(f"invalid users file {path}: {exc}") from exc
        return loaded

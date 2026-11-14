"""Resilience helpers: network error classes + active transfer registry (CSR)."""
from __future__ import annotations

import errno
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NetworkErrorClass(str, Enum):
    TIMEOUT = "timeout"
    RESET = "reset"
    UNREACHABLE = "unreachable"
    CLOSED = "closed"
    OTHER = "other"


def classify_network_error(exc: BaseException) -> NetworkErrorClass:
    """Map OSError / socket errors into a coarse class for UI / logging."""
    if isinstance(exc, TimeoutError):
        return NetworkErrorClass.TIMEOUT
    if isinstance(exc, ConnectionResetError):
        return NetworkErrorClass.RESET
    if isinstance(exc, BrokenPipeError):
        return NetworkErrorClass.CLOSED
    if isinstance(exc, ConnectionRefusedError):
        return NetworkErrorClass.UNREACHABLE
    if isinstance(exc, OSError):
        en = getattr(exc, "errno", None)
        if en in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
            return NetworkErrorClass.TIMEOUT
        if en in (errno.ECONNRESET, errno.ECONNABORTED):
            return NetworkErrorClass.RESET
        if en in (errno.EPIPE, errno.ENOTCONN):
            return NetworkErrorClass.CLOSED
        if en in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ECONNREFUSED):
            return NetworkErrorClass.UNREACHABLE
    return NetworkErrorClass.OTHER


@dataclass
class TransferRecord:
    transfer_id: str
    connection_id: int
    peer: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class ActiveTransferRegistry:
    """Track in-flight transfers so disconnect can cancel them cleanly."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, TransferRecord] = {}
        self._by_conn: dict[int, set[str]] = {}

    def register(
        self,
        transfer_id: str,
        connection_id: int,
        *,
        peer: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            old = self._by_id.get(transfer_id)
            if old is not None and old.connection_id != connection_id:
                ids = self._by_conn.get(old.connection_id)
                if ids is not None:
                    ids.discard(transfer_id)
                    if not ids:
                        del self._by_conn[old.connection_id]
            rec = TransferRecord(
                transfer_id=transfer_id,
                connection_id=connection_id,
                peer=peer,
                meta=dict(meta or {}),
            )
            self._by_id[transfer_id] = rec
            self._by_conn.setdefault(connection_id, set()).add(transfer_id)

    def get(self, transfer_id: str) -> TransferRecord | None:
        with self._lock:
            return self._by_id.get(transfer_id)

    def cancel(self, transfer_id: str) -> TransferRecord | None:
        with self._lock:
            rec = self._by_id.pop(transfer_id, None)
            if rec is None:
                return None
            ids = self._by_conn.get(rec.connection_id)
            if ids is not None:
                ids.discard(transfer_id)
                if not ids:
                    del self._by_conn[rec.connection_id]
            return rec

    def cancel_for_connection(self, connection_id: int) -> list[TransferRecord]:
        with self._lock:
            ids = list(self._by_conn.pop(connection_id, set()))
            out: list[TransferRecord] = []
            for tid in ids:
                rec = self._by_id.pop(tid, None)
                if rec is not None:
                    out.append(rec)
            return out

    def cancel_all(self) -> list[TransferRecord]:
        with self._lock:
            out = list(self._by_id.values())
            self._by_id.clear()
            self._by_conn.clear()
            return out

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

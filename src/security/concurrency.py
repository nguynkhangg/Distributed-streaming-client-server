"""Shared worker pool for datagram handling (CSR concurrency)."""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Callable, Iterator

log = logging.getLogger("ccp.concurrency")

_POOL: ThreadPoolExecutor | None = None
_MAX_WORKERS = 16
_MAX_PENDING = 256
_pending = 0
_pending_lock = threading.Lock()
_session_locks: dict[object, threading.Lock] = {}
_session_locks_guard = threading.Lock()


def _pool() -> ThreadPoolExecutor:
    global _POOL
    if _POOL is None:
        _POOL = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="ccp-dg")
    return _POOL


@contextmanager
def session_lock(key: object) -> Iterator[None]:
    """Serialize work for one session (or address); other keys stay concurrent."""
    with _session_locks_guard:
        lock = _session_locks.setdefault(key, threading.Lock())
    with lock:
        yield


def submit_datagram(handler: Callable[..., None], data: bytes, addr: tuple) -> bool:
    """Queue handler(data, addr). Returns False if pending queue is full (drop)."""
    global _pending
    with _pending_lock:
        if _pending >= _MAX_PENDING:
            log.warning("datagram queue full (%d); dropping packet from %s", _MAX_PENDING, addr)
            return False
        _pending += 1

    def _run(data: bytes, addr: tuple) -> None:
        global _pending
        try:
            handler(data, addr)
        finally:
            with _pending_lock:
                _pending -= 1

    _pool().submit(_run, data, addr)
    return True


def pending_count() -> int:
    with _pending_lock:
        return _pending


def shutdown_workers(wait: bool = False) -> None:
    """Optional cleanup on process/server shutdown."""
    global _POOL, _pending
    if _POOL is not None:
        _POOL.shutdown(wait=wait, cancel_futures=True)
        _POOL = None
    with _pending_lock:
        _pending = 0

"""Small shared worker pool for datagram handling (server or client)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable

_POOL: ThreadPoolExecutor | None = None
_MAX_WORKERS = 16


def _pool() -> ThreadPoolExecutor:
    global _POOL
    if _POOL is None:
        _POOL = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="ccp-dg")
    return _POOL


def submit_datagram(handler: Callable[..., None], data: bytes, addr: tuple) -> None:
    """Run handler(data, addr) on the shared bounded thread pool."""
    _pool().submit(handler, data, addr)


def shutdown_workers(wait: bool = False) -> None:
    """Optional cleanup on process/server shutdown."""
    global _POOL
    if _POOL is not None:
        _POOL.shutdown(wait=wait, cancel_futures=True)
        _POOL = None

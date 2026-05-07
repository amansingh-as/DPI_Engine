"""
thread_safe_queue.py - A bounded, thread-safe queue used between pipeline stages.
Equivalent to thread_safe_queue.h in the C++ multi-threaded version.

Python's queue.Queue already provides blocking put/get with an optional maxsize,
so this module is a thin, typed wrapper that mirrors the C++ API.
"""

from __future__ import annotations
import queue
from typing import Generic, Optional, TypeVar

T = TypeVar("T")

_SENTINEL = object()   # signals "no more items" (EOF) to consumers


class TSQueue(Generic[T]):
    """
    Thread-safe bounded FIFO queue.

    Producers call put(item).
    Consumers call get() which blocks until an item is available.
    When the producer is done, call close() to unblock all waiting consumers.
    """

    def __init__(self, maxsize: int = 0):
        """
        maxsize=0  → unbounded (mirrors std::queue default in C++ version).
        maxsize>0  → bounded; put() blocks when full.
        """
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._closed = False

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    def put(self, item: T, timeout: Optional[float] = None) -> None:
        """Add item to the queue.  Blocks if the queue is full."""
        self._q.put(item, timeout=timeout)

    def close(self) -> None:
        """
        Signal EOF to one waiting consumer.  Call once per consumer thread
        so every thread wakes up and exits cleanly.
        """
        self._closed = True
        self._q.put(_SENTINEL)  # type: ignore

    def close_all(self, n_consumers: int) -> None:
        """Send n_consumers sentinel values so every consumer thread exits."""
        self._closed = True
        for _ in range(n_consumers):
            self._q.put(_SENTINEL)  # type: ignore

    # ------------------------------------------------------------------
    # Consumer API
    # ------------------------------------------------------------------

    def get(self, timeout: Optional[float] = None) -> Optional[T]:
        """
        Remove and return the next item.
        Returns None when the queue has been closed and drained.
        Blocks until an item or the close sentinel arrives.
        """
        item = self._q.get(timeout=timeout)
        if item is _SENTINEL:
            # Put the sentinel back so other consumers also wake up
            self._q.put(_SENTINEL)  # type: ignore
            return None
        return item  # type: ignore

    def get_nowait(self) -> Optional[T]:
        """Non-blocking get; returns None if empty."""
        try:
            item = self._q.get_nowait()
            if item is _SENTINEL:
                self._q.put(_SENTINEL)  # type: ignore
                return None
            return item  # type: ignore
        except queue.Empty:
            return None

    # ------------------------------------------------------------------
    # Info
    # ------------------------------------------------------------------

    def size(self) -> int:
        return self._q.qsize()

    def is_closed(self) -> bool:
        return self._closed

    def __len__(self) -> int:
        return self.size()

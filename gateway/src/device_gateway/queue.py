"""Bounded in-process queue with explicit backpressure.

The gateway must never grow without limit when the device or control plane is
slower than the pull rate. Admission raises :class:`BackpressureError` so the
worker can report a bounded rejection instead of silently dropping work.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any


class BackpressureError(RuntimeError):
    pass


class BoundedQueue:
    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._items: deque[dict[str, Any]] = deque()
        self._lock = threading.Lock()
        self._available = threading.Condition(self._lock)
        self._closed = False

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def put(self, item: dict[str, Any]) -> None:
        with self._lock:
            if self._closed:
                raise BackpressureError("queue closed")
            if len(self._items) >= self.capacity:
                raise BackpressureError("queue full")
            self._items.append(item)
            self._available.notify()

    def get_nowait(self) -> dict[str, Any] | None:
        with self._lock:
            return self._items.popleft() if self._items else None

    def drain(self) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._items)
            self._items.clear()
            return items

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._available.notify_all()

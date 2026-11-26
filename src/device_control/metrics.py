"""Process-local counters for operational visibility.

These are deliberately simple and label-free: no tenant ids, subjects or
credentials become metric labels, which keeps cardinality and privacy under
control. Export them through `/v1/metrics` (admin) or scrape from the process.
"""

from __future__ import annotations

import threading
from collections import Counter
from typing import Iterable

_LOCK = threading.Lock()
_COUNTERS: Counter[str] = Counter()


def increment(name: str, amount: int = 1) -> None:
    with _LOCK:
        _COUNTERS[name] += amount


def snapshot() -> dict[str, int]:
    with _LOCK:
        return dict(sorted(_COUNTERS.items()))


def reset(names: Iterable[str] | None = None) -> None:
    with _LOCK:
        if names is None:
            _COUNTERS.clear()
        else:
            for name in names:
                _COUNTERS.pop(name, None)

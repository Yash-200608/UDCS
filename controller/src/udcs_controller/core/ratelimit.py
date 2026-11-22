"""In-memory sliding-window rate limiter.

Limitation (documented in docs/security/threat-model.md): state is per process.
Running several controller workers multiplies the effective limit.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 100_000,
    ) -> None:
        if limit < 1 or window_seconds <= 0:
            raise ValueError("limit must be >= 1 and window_seconds > 0")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self._max_keys:
                    self._evict_stale(now)
                hits = self._hits[key] = deque()
            while hits and hits[0] <= now - self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self._window
        for key in [k for k, q in self._hits.items() if not q or q[-1] <= cutoff]:
            del self._hits[key]
        if len(self._hits) >= self._max_keys:
            # Memory safety wins over precision under a key-flooding attack.
            self._hits.clear()

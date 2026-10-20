"""Every cap for the AI assist, in one place.

The rate limiter is an in-memory sliding window, so it is per process: with several
replicas the effective limit is multiplied. That is acceptable for an opt-in,
bring-your-own-key feature; the provider's own limits remain the hard stop.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

INTAKE_DRAFT_MAX_INPUT_CHARS = 20_000
EXPLAIN_MAX_INPUT_CHARS = 16_000
EXPLAIN_MAX_PROPERTY_CHARS = 1_000
MAX_OUTPUT_TOKENS = 2_000
REQUEST_TIMEOUT_S = 60.0
RATE_LIMIT_CALLS = 20
RATE_LIMIT_WINDOW_S = 600.0
EXCERPT_MAX_CHARS = 200


class RateLimited(Exception):
    def __init__(self, retry_after_s: float) -> None:
        super().__init__("Too many AI requests; try again later.")
        self.retry_after_s = retry_after_s


class RateLimiter:
    def __init__(
        self,
        calls: int = RATE_LIMIT_CALLS,
        window_s: float = RATE_LIMIT_WINDOW_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._calls = calls
        self._window = window_s
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, user_id: str) -> None:
        """Records one call for the user, or raises `RateLimited`."""
        now = self._clock()
        with self._lock:
            hits = self._hits[user_id]
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= self._calls:
                raise RateLimited(self._window - (now - hits[0]))
            hits.append(now)

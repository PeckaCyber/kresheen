"""In-process cache for `build_threats_out`.

Threats are derived, never stored, so every caller regenerated them from scratch. That is fine for one model,
but the list pages (`/api/groups`, `/api/dashboard`, trend snapshots) regenerate them for *every* application on
every request: with about 100 applications those calls took minutes. This keeps the invariant (nothing derived
is persisted) and only memoises the result in this process, so a restart or a stale entry can never leave wrong
data in the database.

Correctness rests on invalidation:
- Every non-GET request bumps a version: `/api/applications/{id}/...` bumps that application's, anything else
  bumps the global one (see `AuditMiddleware`). An entry is served only while both versions are unchanged
  since it was computed.
- The versions are read *before* computing, so a result computed while a write lands is stored under the old
  stamp and is never served.
- A TTL (`KRESHEEN_THREATS_CACHE_TTL` seconds, default 60, 0 turns the cache off) bounds staleness for
  writes that do not go through HTTP (the CLI) or that another worker process made.
Memory is bounded by entry count and by total threats held (oldest entries go first).
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")

_MAX_ENTRIES = 2000  # entries are cheap; memory is bounded by the weight below
_MAX_TOTAL_WEIGHT = 100_000  # threats held across all entries (a few GB would otherwise be possible)


def ttl_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get("KRESHEEN_THREATS_CACHE_TTL", "60")))
    except ValueError:
        return 60.0


class VersionedCache(Generic[T]):
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._global = 0
        self._apps: dict[str, int] = {}
        self._entries: OrderedDict[tuple, tuple[T, tuple[int, int], float, int]] = OrderedDict()
        self._weight = 0
        self._flights: dict[tuple, threading.Lock] = {}

    def stamp(self, app_id: str) -> tuple[int, int]:
        with self._lock:
            return self._global, self._apps.get(app_id, 0)

    def get(self, key: tuple, app_id: str) -> T | None:
        ttl = ttl_seconds()
        if ttl <= 0:
            return None
        with self._lock:
            hit = self._entries.get(key)
            if hit is None:
                return None
            value, stamp, at, _weight = hit
            if stamp != (self._global, self._apps.get(app_id, 0)) or self._clock() - at > ttl:
                self._drop(key)
                return None
            self._entries.move_to_end(key)
            return value

    def put(self, key: tuple, value: T, stamp: tuple[int, int], weight: int) -> None:
        if ttl_seconds() <= 0:
            return
        with self._lock:
            self._drop(key)
            self._entries[key] = (value, stamp, self._clock(), weight)
            self._weight += weight
            while self._entries and (len(self._entries) > _MAX_ENTRIES or self._weight > _MAX_TOTAL_WEIGHT):
                self._drop(next(iter(self._entries)))

    def _drop(self, key: tuple) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._weight -= entry[3]

    def get_or_compute(self, key: tuple, app_id: str, compute: Callable[[], T], weight: Callable[[T], int]) -> T:
        """Cached value, or compute it once: concurrent callers for the same key wait for one computation instead of
        each doing the work (a cold list page used to start one full regeneration per visitor)."""
        value = self.get(key, app_id)
        if value is not None:
            return value
        with self._flight_lock(key):
            value = self.get(key, app_id)  # another caller may have finished while we waited
            if value is not None:
                return value
            stamp = self.stamp(app_id)  # read before computing: a write during the work leaves this stale
            value = compute()
            self.put(key, value, stamp, weight(value))
            return value

    def _flight_lock(self, key: tuple) -> threading.Lock:
        with self._lock:
            lock = self._flights.get(key)
            if lock is None:
                if len(self._flights) > 1024:  # bounded: locks of finished computations are simply forgotten
                    self._flights.clear()
                lock = self._flights[key] = threading.Lock()
            return lock

    def invalidate_app(self, app_id: str) -> None:
        with self._lock:
            self._apps[app_id] = self._apps.get(app_id, 0) + 1

    def invalidate_all(self) -> None:
        with self._lock:
            self._global += 1


def cache_for(repo: object) -> VersionedCache:
    """One cache per repository object, so separate databases never share entries."""
    cache = getattr(repo, "_threats_cache", None)
    if cache is None:
        cache = VersionedCache()
        try:
            repo._threats_cache = cache  # type: ignore[attr-defined]
        except AttributeError:
            return cache
    return cache  # type: ignore[no-any-return]

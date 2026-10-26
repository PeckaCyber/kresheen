"""Failed-login throttle: a lockout per account, and progressive delays per (client address, account) and per
client address.

In memory and per process on purpose (single-process deployment, no new infrastructure). A restart
clears it, and with several workers each keeps its own count, so the effective limit is the per-process
limit times the worker count. The check runs before any password hashing, so a blocked request costs
almost nothing. Counting unknown emails exactly like known ones keeps the response from revealing which
accounts exist.

Limits (env, all optional):
- `KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT` (10): failures in the window, from any address, that lock the account.
- `KRESHEEN_LOGIN_FREE_FAILURES` (3): failures per (address, account) pair before delays start.
- `KRESHEEN_LOGIN_DELAY_BASE_SECONDS` (1) and `KRESHEEN_LOGIN_DELAY_MAX_SECONDS` (300): each failure past the free
  ones doubles the wait before that pair may try again, up to the cap.
- `KRESHEEN_LOGIN_MAX_FAILURES_PER_IP` (50): failures from one address (all accounts) before that address is slowed
  (same doubling from the base). `KRESHEEN_LOGIN_IP_DELAY_MAX_SECONDS` (30) caps that delay, so a spray across many
  accounts is slowed but everyone else behind the same proxy waits at most that long, never a lockout.
- `KRESHEEN_LOGIN_WINDOW_SECONDS` (900): how long failures are remembered.
Tradeoff: someone can deliberately lock a known account out for the window by failing its logins;
that is preferred over unlimited guessing, and the account resumes by itself afterwards.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from collections.abc import Callable

_MAX_TRACKED_KEYS = 10_000


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


class LoginThrottle:
    def __init__(
        self,
        *,
        max_per_account: int | None = None,
        max_per_ip: int | None = None,
        window_seconds: int | None = None,
        free_failures: int | None = None,
        delay_base: int | None = None,
        delay_max: int | None = None,
        ip_delay_max: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_per_account = max_per_account or _env_int("KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT", 10)
        self.max_per_ip = max_per_ip or _env_int("KRESHEEN_LOGIN_MAX_FAILURES_PER_IP", 50)
        self.window = window_seconds or _env_int("KRESHEEN_LOGIN_WINDOW_SECONDS", 900)
        self.free_failures = free_failures or _env_int("KRESHEEN_LOGIN_FREE_FAILURES", 3)
        self.delay_base = delay_base or _env_int("KRESHEEN_LOGIN_DELAY_BASE_SECONDS", 1)
        self.delay_max = delay_max or _env_int("KRESHEEN_LOGIN_DELAY_MAX_SECONDS", 300)
        self.ip_delay_max = ip_delay_max or _env_int("KRESHEEN_LOGIN_IP_DELAY_MAX_SECONDS", 30)
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = {}
        self._last_block_logged: dict[str, float] = {}

    @staticmethod
    def _keys(email: str, ip: str | None) -> tuple[str, str | None, str | None]:
        acct = f"acct:{email.strip().casefold()[:200]}"
        return acct, (f"ip:{ip}" if ip else None), (f"pair:{ip}|{acct}" if ip else None)

    def _delay(self, failures: int, free: int, cap: int) -> int:
        """Wait after the `failures`-th failure: nothing within the free ones, then base, 2*base, 4*base, ..."""
        over = failures - free
        if over <= 0:
            return 0
        return min(cap, self.delay_base * 2 ** min(over - 1, 30))

    def _live(self, key: str, now: float) -> deque[float]:
        q = self._failures.get(key)
        if q is None:
            return deque()
        while q and now - q[0] >= self.window:
            q.popleft()
        if not q:
            del self._failures[key]
        return q

    def retry_after(self, email: str, ip: str | None) -> int | None:
        """Seconds until another attempt is allowed, or None if the attempt may proceed."""
        acct, ipk, pair = self._keys(email, ip)
        now = self._clock()
        with self._lock:
            waits = []
            q = self._live(acct, now)
            if len(q) >= self.max_per_account:
                waits.append(self.window - (now - q[0]))
            for key, free, cap in (
                (pair, self.free_failures, self.delay_max),
                (ipk, self.max_per_ip, self.ip_delay_max),
            ):
                if key is None:
                    continue
                q = self._live(key, now)
                delay = self._delay(len(q), free, cap)
                if delay and q:
                    waits.append(q[-1] + delay - now)
            wait = max(waits, default=0)
            return int(wait) + 1 if wait > 0 else None

    def note_block(self, email: str, ip: str | None, *, every_seconds: int = 60) -> bool:
        """True at most once per `every_seconds` per account, so lockouts can be audited without a flood of
        throttled requests filling the audit log with one row each."""
        key = self._keys(email, None)[0]
        now = self._clock()
        with self._lock:
            if len(self._last_block_logged) >= _MAX_TRACKED_KEYS:
                self._last_block_logged.clear()
            if now - self._last_block_logged.get(key, -1e9) < every_seconds:
                return False
            self._last_block_logged[key] = now
            return True

    def record_failure(self, email: str, ip: str | None) -> None:
        acct, ipk, pair = self._keys(email, ip)
        now = self._clock()
        with self._lock:
            if len(self._failures) >= _MAX_TRACKED_KEYS:  # bound memory under a spray of distinct emails
                for key in list(self._failures):
                    self._live(key, now)
                if len(self._failures) >= _MAX_TRACKED_KEYS:
                    for key in list(self._failures)[: _MAX_TRACKED_KEYS // 10]:
                        del self._failures[key]
            self._failures.setdefault(acct, deque()).append(now)
            for extra in (ipk, pair):
                if extra is not None:
                    self._failures.setdefault(extra, deque()).append(now)

    def record_success(self, email: str, ip: str | None = None) -> None:
        acct, _, pair = self._keys(email, ip)
        with self._lock:
            self._failures.pop(acct, None)
            if pair is not None:
                self._failures.pop(pair, None)

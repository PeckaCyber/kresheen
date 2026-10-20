"""Password hashing, session lifecycle, and FastAPI auth/CSRF dependencies
for the dashboard's JSON API. Sessions are kept server-side rather than as
JWTs so they can be revoked, passwords use argon2, and CSRF is a header
token the SPA echoes back. Sessions are tied to a `User` account.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import threading
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from fastapi import Depends, HTTPException, Request

from kresheen.dashboard.deps import get_repo
from kresheen.models.auth import ApiToken, Session
from kresheen.models.user import User
from kresheen.storage.repository import Repository

SESSION_COOKIE_NAME = "kresheen_session"
# A session ends at the absolute limit (`KRESHEEN_SESSION_MAX_HOURS`, default 12) or after this long without an
# authenticated request (`KRESHEEN_SESSION_IDLE_MINUTES`, default 60), whichever comes first.
DEFAULT_SESSION_MAX_HOURS = 12
DEFAULT_SESSION_IDLE_MINUTES = 60
# Last-seen is written at most this often per session, so a busy page does not write on every request.
LAST_SEEN_WRITE_INTERVAL = timedelta(minutes=1)


def _env_positive_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def session_lifetime() -> timedelta:
    return timedelta(hours=_env_positive_int("KRESHEEN_SESSION_MAX_HOURS", DEFAULT_SESSION_MAX_HOURS))


def session_idle_timeout() -> timedelta:
    return timedelta(minutes=_env_positive_int("KRESHEEN_SESSION_IDLE_MINUTES", DEFAULT_SESSION_IDLE_MINUTES))


def cookie_secure(request: Request) -> bool:
    """Whether to set the `Secure` flag on a cookie.

    `KRESHEEN_COOKIE_SECURE`: `always`, `never`, or `auto` (default) which follows the request scheme as the app
    sees it. Behind a TLS-terminating proxy the app only sees `http` unless it trusts the proxy's forwarded headers
    (`KRESHEEN_FORWARDED_ALLOW_IPS`), so set `always` or that variable there; the docs say so.
    """
    mode = os.environ.get("KRESHEEN_COOKIE_SECURE", "auto").strip().lower()
    if mode in ("always", "true", "1"):
        return True
    if mode in ("never", "false", "0"):
        return False
    return request.url.scheme == "https"
CSRF_HEADER_NAME = "X-CSRF-Token"
_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

API_TOKEN_PREFIX = "pck_"
_hasher = PasswordHasher()

# Each argon2 hash holds about 64 MiB (x parallelism) while it runs. Unbounded, a burst of
# concurrent logins is an unauthenticated memory-exhaustion attack (60 parallel attempts
# OOM-killed a 2 GB container), so only a few run at once and the rest wait briefly or get 503.
# `KRESHEEN_MAX_CONCURRENT_HASHES` (default 2).
_HASH_WAIT_SECONDS = 5.0


def _hash_slot_count() -> int:
    try:
        return max(1, int(os.environ.get("KRESHEEN_MAX_CONCURRENT_HASHES", "2")))
    except ValueError:
        return 2


_hash_slots = threading.BoundedSemaphore(_hash_slot_count())

# Waiting for a slot occupies one of the server's worker threads, and a burst of logins used to fill them all,
# starving every other request for the duration (the 200-user spike: 40 s of stall). So only a few may wait; the rest
# are turned away at once with 503 + Retry-After. `KRESHEEN_MAX_QUEUED_HASHES` (default 12).
_hash_waiting = 0
_hash_waiting_lock = threading.Lock()


def _max_queued_hashes() -> int:
    try:
        return max(0, int(os.environ.get("KRESHEEN_MAX_QUEUED_HASHES", "12")))
    except ValueError:
        return 12


def _busy() -> HTTPException:
    return HTTPException(status_code=503, detail="The server is busy; try again shortly", headers={"Retry-After": "2"})


def _acquire_hash_slot() -> None:
    global _hash_waiting
    if _hash_slots.acquire(blocking=False):
        return
    with _hash_waiting_lock:
        if _hash_waiting >= _max_queued_hashes():
            raise _busy()
        _hash_waiting += 1
    try:
        if not _hash_slots.acquire(timeout=_HASH_WAIT_SECONDS):
            raise _busy()
    finally:
        with _hash_waiting_lock:
            _hash_waiting -= 1


# `kresheen create-user` and the owner-only "add user" API route never take
# a caller-supplied password (they generate a random one-time value), so
# neither enforces a length/complexity rule today. Self-serve change-password
# is the first place a person types their own new password, so it gets a
# floor here.
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    _acquire_hash_slot()
    try:
        return _hasher.hash(password)
    finally:
        _hash_slots.release()


def verify_password(password: str, password_hash: str) -> bool:
    _acquire_hash_slot()
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHash):
        return False
    finally:
        _hash_slots.release()


_dummy_hash: str | None = None


def verify_against_dummy(password: str) -> None:
    """Spend the same work as a real check when the account does not exist (or is inactive), so the
    response time does not reveal which emails are registered."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _dummy_hash)


def generate_session(user_id: str) -> Session:
    now = datetime.now(UTC)
    return Session(
        id=secrets.token_urlsafe(32),
        user_id=user_id,
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        expires_at=now + session_lifetime(),
        last_seen_at=now,
    )


def hash_api_token(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_api_token_secret() -> str:
    return API_TOKEN_PREFIX + secrets.token_urlsafe(32)


# An API token acts as its owner but may only call what `kresheen ci` needs: list models, start and read runs
# and read their results. Everything else (users, audit log, connectors, groups, token management, writes to
# models) needs a browser session, so a leaked CI token cannot read the audit log or reconfigure integrations.
API_TOKEN_ROUTES: tuple[tuple[frozenset[str], re.Pattern[str]], ...] = (
    (frozenset({"GET"}), re.compile(r"^/api/applications$")),
    (frozenset({"GET"}), re.compile(r"^/api/applications/[^/]+$")),
    (frozenset({"GET", "POST"}), re.compile(r"^/api/applications/[^/]+/runs$")),
    (frozenset({"GET"}), re.compile(r"^/api/applications/[^/]+/runs/[^/]+(/.*)?$")),
)


def _api_token_may_call(method: str, path: str) -> bool:
    return any(method in methods and pattern.match(path) for methods, pattern in API_TOKEN_ROUTES)


def _session_from_bearer(request: Request, repo: Repository) -> Session | None:
    header = request.headers.get("Authorization", "")
    scheme, _, secret = header.partition(" ")
    if scheme.lower() != "bearer" or not secret.startswith(API_TOKEN_PREFIX):
        return None
    token: ApiToken | None = repo.get_api_token_by_hash(hash_api_token(secret.strip()))
    if token is None:
        return None
    if token.expires_at is not None and token.expires_at <= datetime.now(UTC):
        return None
    if not _api_token_may_call(request.method, request.url.path):
        raise HTTPException(status_code=403, detail="This API token cannot call that route")
    token.last_used_at = datetime.now(UTC)
    repo.save_api_token(token)
    request.state.via_api_token = True
    request.state.audit_user_id = token.user_id
    now = datetime.now(UTC)
    # A synthetic, never-persisted Session so every route that depends on
    # `get_current_session`/`get_current_user` works unchanged. No CSRF token:
    # `require_csrf` skips bearer-authenticated requests (a cross-site request
    # cannot attach an Authorization header the way it can ride a cookie).
    return Session(id=f"token:{token.id}", user_id=token.user_id, csrf_token="", created_at=now, expires_at=now)


def get_current_session(request: Request, repo: Repository = Depends(get_repo)) -> Session:
    """Every `/api/*` route (other than login) depends on this. Raises 401
    rather than redirecting -- the SPA, not the server, owns navigation.
    Accepts a browser session cookie or an `Authorization: Bearer pck_...`
    API token (see `models/auth.py::ApiToken`); the cookie wins if both are
    present."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id is None:
        bearer_session = _session_from_bearer(request, repo)
        if bearer_session is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return bearer_session
    session = repo.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    now = datetime.now(UTC)
    last_seen = session.last_seen_at or session.created_at
    if now - last_seen >= session_idle_timeout():
        repo.delete_session(session_id)
        raise HTTPException(status_code=401, detail="Signed out after a period of inactivity")
    if now - last_seen >= LAST_SEEN_WRITE_INTERVAL:
        repo.touch_session(session_id, now)
    request.state.audit_user_id = session.user_id
    return session


def require_cookie_session(request: Request, _session: Session = Depends(get_current_session)) -> None:
    """For credential-management routes: an API token must not be able to
    mint or revoke API tokens (a leaked token would otherwise be able to
    entrench itself)."""
    if getattr(request.state, "via_api_token", False):
        raise HTTPException(status_code=403, detail="Not available to API tokens")


def get_current_user(
    session: Session = Depends(get_current_session), repo: Repository = Depends(get_repo)
) -> User:
    """Depend on this instead of `get_current_session` when a route needs
    the actual account (e.g. to check `role`, or to attribute an
    Application's `owner_user_id`) rather than just proving a valid
    session exists."""
    user = repo.get_user(session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_owner(user: User = Depends(get_current_user)) -> None:
    """Add as an extra dependency on administrative routes (user
    management, Settings' credentials, Constructs' code templates,
    Connector credentials) -- see models/user.py's docstring for why
    Application visibility itself is *not* gated by role."""
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Owner role required")


def require_csrf(request: Request, session: Session = Depends(get_current_session)) -> None:
    """Add as an extra dependency on every mutating `/api/*` route. Not
    needed on login itself -- there's no session yet to hijack at that
    point in the flow."""
    if request.method in _SAFE_METHODS or getattr(request.state, "via_api_token", False):
        return
    header_token = request.headers.get(CSRF_HEADER_NAME)
    if not header_token or not secrets.compare_digest(header_token, session.csrf_token):
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")

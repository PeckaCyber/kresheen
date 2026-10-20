"""Dashboard authentication: server-side sessions tied to a `User`.

Sessions are stored server-side (not a stateless JWT) so they're revocable
on logout or password rotation. Sessions belong to real multi-user `User`
accounts.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class Session(BaseModel):
    """`id` is the session token itself -- high-entropy, used directly as
    both the lookup key and the cookie value. Could be hashed at rest like
    the password is, same as any other bearer-token-in-a-database tradeoff;
    not done in v1, consistent with how this codebase flags lower-urgency
    hardening items rather than blocking on them."""

    id: str
    user_id: str
    csrf_token: str
    created_at: datetime
    expires_at: datetime
    # Last authenticated request (written at most once a minute); None on sessions created before the idle timeout
    # existed, which then count from `created_at`.
    last_seen_at: datetime | None = None
    # Established via OIDC (so logout can also end the IdP session).
    sso: bool = False


class ApiToken(BaseModel):
    """A long-lived bearer credential for non-browser clients (the
    `kresheen ci` command, scripts). Acts as its owning `User`, so it
    carries that user's role, but only for the CI route allowlist in `dashboard/auth.py::API_TOKEN_ROUTES`.

    Only a SHA-256 of the secret is stored: the secret is high-entropy and
    random, so a fast hash is sufficient (unlike a password), and a database
    leak does not yield usable credentials. The plaintext is shown exactly
    once, at creation. `prefix` is the first characters of the secret, kept
    so a user can tell tokens apart in a list."""

    id: str
    user_id: str
    name: str
    token_hash: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    # Optional expiry. None means the token never expires.
    expires_at: datetime | None = None

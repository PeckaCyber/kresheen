"""Audit trail for the dashboard API (models/audit.py).

`AuditMiddleware` records every state-changing `/api/*` request made by an
authenticated caller, from the outside, so a route added later is audited
without anyone remembering to. Auth routes write their own explicit events
(`record_event`) because the caller is not authenticated yet at login.

Failure policy: a failure to write an audit row is logged and swallowed
rather than failing the user's request (fail-open). That favours availability
for a self-hosted single-team tool; revisit if a deployment needs the
stricter "no audit row, no action" guarantee.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime, timedelta

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from kresheen.dashboard.security_log import (
    SECURITY_ACTIONS,
    SECURITY_PREFIXES,
    is_security_action,
)
from kresheen.engine.threats.cache import cache_for
from kresheen.models.audit import AuditEvent, new_audit_id
from kresheen.plugins import get_registry
from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)

_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def record_event(
    repo: Repository,
    *,
    action: str,
    user_id: str | None = None,
    user_email: str | None = None,
    subject: dict[str, str] | None = None,
    status_code: int | None = None,
    via: str = "session",
    client_ip: str | None = None,
) -> None:
    try:
        now = datetime.now(UTC)
        security = is_security_action(action)
        _notify_sinks(now, action, user_email, client_ip, status_code, via, subject or {}, security)
        repo.add_audit_event(
            AuditEvent(
                id=new_audit_id(),
                at=now,
                user_id=user_id,
                user_email=user_email,
                action=action,
                subject=subject or {},
                status_code=status_code,
                via="api_token" if via == "api_token" else "session",
                client_ip=client_ip,
            )
        )
        if action == FAILED_LOGIN_ACTION:
            repo.trim_audit_events_for_action(FAILED_LOGIN_ACTION, min(max_failed_logins(), max_entries()))
        # Two pools: routine writes are capped at max_entries(), security events at max_security_entries(),
        # so a member flooding harmless writes cannot evict the trail of a login attack or a token change.
        repo.trim_audit_events(max_entries(), security=False, names=SECURITY_ACTIONS, prefixes=SECURITY_PREFIXES)
        repo.trim_audit_events(
            max_security_entries(), security=True, names=SECURITY_ACTIONS, prefixes=SECURITY_PREFIXES
        )
    except Exception:
        logger.exception("Could not write audit event %s", action)


def _notify_sinks(at, action, user, ip, status, via, detail, security) -> None:
    event = {
        "at": at.isoformat(),
        "action": action,
        "user": user,
        "ip": ip,
        "status": status,
        "via": "api_token" if via == "api_token" else "session",
        "detail": dict(detail),
        "security": security,
    }
    for sink in get_registry().audit_sinks():
        try:
            sink(dict(event))
        except Exception:
            logger.exception("Audit sink failed for %s", action)


_PRUNE_INTERVAL_SECONDS = 24 * 3600


def retention_days() -> int | None:
    """`KRESHEEN_AUDIT_RETENTION_DAYS`: unset/0/invalid = keep forever."""
    try:
        days = int(os.environ.get("KRESHEEN_AUDIT_RETENTION_DAYS", "0"))
    except ValueError:
        return None
    return days if days > 0 else None


DEFAULT_MAX_ENTRIES = 2000
# Failed sign-ins are unauthenticated and unbounded, so they get their own, smaller cap: a flood of them
# must not be able to evict the rest of the history. `KRESHEEN_AUDIT_MAX_FAILED_LOGINS` (default 500).
FAILED_LOGIN_ACTION = "auth.login_failed"
DEFAULT_MAX_FAILED_LOGINS = 500


def max_failed_logins() -> int:
    """The local log's cap; a plugin can raise it (`Plugin.audit_limits`)."""
    return get_registry().audit_limit("max_failed_logins") or DEFAULT_MAX_FAILED_LOGINS


DEFAULT_MAX_SECURITY_ENTRIES = 10000


def max_security_entries() -> int:
    """The local log's cap; a plugin can raise it (`Plugin.audit_limits`)."""
    return get_registry().audit_limit("max_security_entries") or DEFAULT_MAX_SECURITY_ENTRIES


def max_entries() -> int:
    """The local log's cap; a plugin can raise it (`Plugin.audit_limits`)."""
    return get_registry().audit_limit("max_entries") or DEFAULT_MAX_ENTRIES


def prune_audit_log(repo: Repository, days: int) -> int:
    return repo.prune_audit_events(datetime.now(UTC) - timedelta(days=days))


def prune_if_due(app_state: object, repo: Repository) -> None:
    """Amortised retention: at most once a day from the request path, so a
    long-running server needs no scheduler. Never raises."""
    days = retention_days()
    last = getattr(app_state, "audit_last_prune", 0.0)
    if days is None or time.monotonic() - last < _PRUNE_INTERVAL_SECONDS and last:
        return
    app_state.audit_last_prune = time.monotonic()  # type: ignore[attr-defined]
    try:
        removed = prune_audit_log(repo, days)
        if removed:
            logger.info("Pruned %d audit events older than %d days", removed, days)
    except Exception:
        logger.exception("Audit retention prune failed")


# Top-level API areas whose writes never feed threat generation. Anything not listed (threat knowledge-base
# rules, settings, constructs, and anything new) invalidates everything, which is the safe default.
_WRITES_THAT_CANNOT_CHANGE_THREATS = frozenset(
    {"auth", "users", "groups", "tokens", "audit-log", "agent-config", "settings", "applications"}
)


def _invalidate_threat_cache(request: Request) -> None:
    """A write may change derived threats (statuses, properties, components, data sources, KB rules...):
    drop the cached results for that application, or everything for a write outside `/api/applications/{id}`.
    Done for failed writes too; being too eager only costs a recompute."""
    cache = cache_for(request.app.state.repo)
    parts = request.url.path.split("/")  # ['', 'api', 'applications', '<id>', ...]
    if len(parts) > 3 and parts[2] == "applications" and parts[3] and parts[3] != "sample":
        cache.invalidate_app(parts[3])
    elif len(parts) > 2 and (
        parts[2] in _WRITES_THAT_CANNOT_CHANGE_THREATS or parts[2] in get_registry().threat_neutral_api_areas()
    ):
        return  # e.g. creating a group or a token must not throw away every cached summary
    else:
        cache.invalidate_all()


_EXPORT_SUFFIXES = (
    "/report.html",
    "/report.docx",
    "/report.pdf",
    "/findings.sarif",
    "/threatdragon.json",
    "/threats.csv",
    "/action-plan.csv",
    "/findings.csv",
    "/dfd.svg",
    "/compliance/export",
)


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        prune_if_due(request.app.state, request.app.state.repo)
        if request.method not in _SAFE_METHODS and request.url.path.startswith("/api/"):
            _invalidate_threat_cache(request)
        user_id = getattr(request.state, "audit_user_id", None)
        if user_id is None or not request.url.path.startswith("/api/"):
            return response
        route = request.scope.get("route")
        template = getattr(route, "path", request.url.path)
        if request.method in _SAFE_METHODS:
            # Report and data exports are GETs but move data out of the system, so they are audited too.
            if request.method != "GET" or response.status_code != 200 or not template.endswith(_EXPORT_SUFFIXES):
                return response
            action = "report.export"
        else:
            action = f"{request.method} {template}"
        repo: Repository = request.app.state.repo
        user = repo.get_user(user_id)
        record_event(
            repo,
            action=action,
            user_id=user_id,
            user_email=user.email if user else None,
            subject={k: str(v) for k, v in request.path_params.items()},
            status_code=response.status_code,
            via="api_token" if getattr(request.state, "via_api_token", False) else "session",
            client_ip=request.client.host if request.client else None,
        )
        return response

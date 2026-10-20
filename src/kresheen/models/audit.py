"""AuditEvent: an append-only record of who changed what, and when.

Written for every state-changing `/api/*` request by `dashboard/audit.py`'s
middleware (so a new route cannot forget to be audited), plus explicit events
for login, failed login and logout. Request bodies are never recorded: they
carry credentials (connector tokens, passwords, API-token names).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


def new_audit_id() -> str:
    return f"AUD-{uuid.uuid4().hex[:12]}"


class AuditEvent(BaseModel):
    id: str
    at: datetime
    # None for a failed login by an unknown email.
    user_id: str | None = None
    user_email: str | None = None
    # e.g. "POST /api/applications/{application_id}/runs" or "auth.login".
    action: str
    # Concrete URL path params (application_id, run_id, ...): the "what".
    subject: dict[str, str] = Field(default_factory=dict)
    status_code: int | None = None
    via: Literal["session", "api_token"] = "session"
    client_ip: str | None = None

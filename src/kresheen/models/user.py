"""User accounts for the dashboard.

Every user in a deployment sees every Application by default -- a shared
workspace, matching this codebase's existing single-business-per-deployment
scope.
`role` gates administrative surfaces (user management, Settings'
credentials, Constructs' code templates, Connector credentials) only, not
Application visibility. Revisit if a deployment ever needs per-Application
ACLs across unrelated client engagements -- not needed until then.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


def normalize_email(email: str) -> str:
    """How an address is stored and matched: trimmed and lower-cased, so
    "Bob@Example.com" and "bob@example.com" are one account."""
    return email.strip().lower()


def new_user_id() -> str:
    return f"USER-{uuid.uuid4().hex[:16]}"


class User(BaseModel):
    id: str
    email: str
    password_hash: str
    role: Literal["owner", "member"] = "member"
    is_active: bool = True
    # "sso": created by OIDC/SCIM provisioning, so the IdP is authoritative for
    # its role (group mapping may demote it). "password": created by
    # `create-user`, never auto-demoted -- the owner break-glass account.
    auth_source: Literal["password", "sso"] = "password"
    created_at: datetime

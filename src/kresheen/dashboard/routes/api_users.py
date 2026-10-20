"""JSON API for user accounts (owner-only): list who has access, add a
password account, and change a user's role or active status. Self-service
password rotation for the *current* user lives in `api_auth.py`
(`POST /api/auth/change-password`) since it needs the caller's current
password, not an owner override.

Accounts are otherwise still bootstrapped via `kresheen create-user`
(first account, or a break-glass path if the dashboard is unreachable) --
this router reuses that command's id/hashing helpers exactly, it does not
invent a new account-creation path.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kresheen.dashboard.auth import (
    get_current_session,
    get_current_user,
    hash_password,
    require_cookie_session,
    require_csrf,
    require_owner,
)
from kresheen.dashboard.deps import get_repo
from kresheen.models.user import User, new_user_id, normalize_email
from kresheen.storage.repository import Repository

router = APIRouter(
    prefix="/api/users",
    tags=["users"],
    dependencies=[Depends(get_current_session), Depends(require_owner)],
)

# Length of the server-generated one-time password, same as
# `kresheen create-user --password` when none is given (`cli/main.py`).
_GENERATED_PASSWORD_BYTES = 18


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    auth_source: str
    is_active: bool
    created_at: datetime


class CreatedUserOut(UserOut):
    # Shown once, from the create call only -- never returned by list/patch.
    one_time_password: str


def _out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role=user.role,
        auth_source=user.auth_source,
        is_active=user.is_active,
        created_at=user.created_at,
    )


@router.get("", response_model=list[UserOut])
def list_users(repo: Repository = Depends(get_repo)) -> list[UserOut]:
    return [_out(u) for u in repo.list_users()]


class CreateUserRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    role: Literal["owner", "member"] = "member"


@router.post(
    "",
    response_model=CreatedUserOut,
    dependencies=[Depends(require_csrf), Depends(require_cookie_session)],
)
def create_user(body: CreateUserRequest, repo: Repository = Depends(get_repo)) -> CreatedUserOut:
    """Adds a password account with a random one-time password, returned
    exactly once in this response (never persisted or logged in plaintext,
    never re-derivable -- only its argon2 hash is stored). Mirrors
    `kresheen create-user`'s id generation and hashing exactly; this is
    not a second hashing scheme."""
    email = normalize_email(body.email)
    if repo.get_user_by_email(email) is not None:
        raise HTTPException(status_code=409, detail="A user with that email already exists")
    password = secrets.token_urlsafe(_GENERATED_PASSWORD_BYTES)
    user = User(
        id=new_user_id(),
        email=email,
        password_hash=hash_password(password),
        role=body.role,
        created_at=datetime.now(UTC),
    )
    repo.save_user(user)
    return CreatedUserOut(**_out(user).model_dump(), one_time_password=password)


class UpdateUserRequest(BaseModel):
    role: Literal["owner", "member"] | None = None
    is_active: bool | None = None


def _other_active_owners(repo: Repository, exclude_id: str) -> int:
    return sum(1 for u in repo.list_users() if u.role == "owner" and u.is_active and u.id != exclude_id)


@router.patch(
    "/{user_id}",
    response_model=UserOut,
    dependencies=[Depends(require_csrf), Depends(require_cookie_session)],
)
def update_user(
    user_id: str,
    body: UpdateUserRequest,
    current_user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> UserOut:
    """Changes role and/or active status. Guards against locking the
    deployment out of administration: an owner cannot deactivate their own
    account, and the last active owner can neither be demoted nor
    deactivated (whichever change would leave zero active owners is
    refused, computed from the *other* users so both changes in a single
    request are checked against the same snapshot)."""
    target = repo.get_user(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Unknown user")

    deactivating = body.is_active is False and target.is_active
    demoting = body.role is not None and body.role != "owner" and target.role == "owner"

    if deactivating and target.id == current_user.id:
        raise HTTPException(status_code=422, detail="You cannot deactivate your own account")
    if (
        (deactivating or demoting)
        and target.is_active
        and target.role == "owner"
        and _other_active_owners(repo, exclude_id=target.id) == 0
    ):
        raise HTTPException(status_code=422, detail="Cannot demote or deactivate the last active owner")

    updates: dict[str, object] = {}
    if body.role is not None:
        updates["role"] = body.role
    if body.is_active is not None:
        updates["is_active"] = body.is_active
    if updates:
        target = target.model_copy(update=updates)
        repo.save_user(target)
        if deactivating:
            # Belt-and-suspenders: `is_active` already blocks the account's
            # next request (`get_current_user`), this ends sessions already
            # open right now instead of at their next call.
            repo.delete_sessions_for_user(target.id)

    return _out(target)

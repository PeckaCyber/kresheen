"""API tokens for non-browser clients (`kresheen ci`, scripts).

A token acts as the user who created it. Only a cookie session can create,
list or revoke tokens (`require_cookie_session`): a leaked token must not be
able to mint more of itself. The plaintext secret is returned exactly once,
from the create call.

Expiry contract for `POST /api/tokens` (`expires_in_days`): omitted means 90 days; an integer from 1 to 730 means that
many days; an explicit JSON `null` means the token never expires. Never-expiring is therefore always a deliberate
request, not what you get by leaving the field out.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kresheen.dashboard.auth import (
    generate_api_token_secret,
    get_current_user,
    hash_api_token,
    require_cookie_session,
    require_csrf,
)
from kresheen.dashboard.deps import get_repo
from kresheen.models.auth import ApiToken
from kresheen.models.user import User
from kresheen.storage.repository import Repository

router = APIRouter(prefix="/api/tokens", tags=["tokens"], dependencies=[Depends(require_cookie_session)])

_PREFIX_DISPLAY_LEN = 8
DEFAULT_TOKEN_DAYS = 90


class TokenOut(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    expires_at: datetime | None = None


class CreateTokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    # Omitted: DEFAULT_TOKEN_DAYS. Explicit null: never expires. Otherwise it stops working after this many days.
    expires_in_days: int | None = Field(default=DEFAULT_TOKEN_DAYS, ge=1, le=730)


class CreatedTokenOut(TokenOut):
    # Shown once. Never returned by the list endpoint.
    secret: str


def _out(token: ApiToken) -> TokenOut:
    return TokenOut(
        id=token.id,
        name=token.name,
        prefix=token.prefix,
        created_at=token.created_at,
        last_used_at=token.last_used_at,
        expires_at=token.expires_at,
    )


@router.get("", response_model=list[TokenOut])
def list_tokens(user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)) -> list[TokenOut]:
    return [_out(t) for t in repo.list_api_tokens_for_user(user.id)]


@router.post("", response_model=CreatedTokenOut, dependencies=[Depends(require_csrf)])
def create_token(
    body: CreateTokenRequest, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> CreatedTokenOut:
    secret = generate_api_token_secret()
    token = ApiToken(
        id=f"TOKEN-{uuid.uuid4().hex[:16]}",
        user_id=user.id,
        name=body.name.strip(),
        token_hash=hash_api_token(secret),
        prefix=secret[:_PREFIX_DISPLAY_LEN],
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    repo.save_api_token(token)
    return CreatedTokenOut(**_out(token).model_dump(), secret=secret)


@router.delete("/{token_id}", status_code=204, dependencies=[Depends(require_csrf)])
def revoke_token(
    token_id: str, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> None:
    owned = {t.id for t in repo.list_api_tokens_for_user(user.id)}
    if token_id not in owned:
        raise HTTPException(status_code=404, detail="Unknown token")
    repo.delete_api_token(token_id)

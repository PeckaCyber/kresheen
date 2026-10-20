"""Owner-only instance switch for the experimental AI assist.

Off by default. `KRESHEEN_AI_DISABLED` forces it off regardless of the stored setting (an operator guarantee), in which
case the switch cannot be changed and the PUT answers 409. Turning it off keeps users' stored keys.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from kresheen.dashboard.audit import record_event
from kresheen.dashboard.auth import (
    get_current_session,
    get_current_user,
    require_csrf,
    require_owner,
)
from kresheen.dashboard.deps import get_repo
from kresheen.engine.llm.settings import ai_status, set_ai_enabled
from kresheen.models.user import User
from kresheen.storage.repository import Repository

router = APIRouter(
    prefix="/api/settings/ai",
    tags=["settings"],
    dependencies=[Depends(get_current_session), Depends(require_owner)],
)


class AiSettingsOut(BaseModel):
    enabled: bool
    forced_off: bool


class SetAiSettingsRequest(BaseModel):
    enabled: bool


def _out(repo: Repository) -> AiSettingsOut:
    status = ai_status(repo)
    return AiSettingsOut(enabled=status.enabled, forced_off=status.forced_off)


@router.get("", response_model=AiSettingsOut)
def get_ai_settings(repo: Repository = Depends(get_repo)) -> AiSettingsOut:
    return _out(repo)


@router.put("", response_model=AiSettingsOut, dependencies=[Depends(require_csrf)])
def set_ai_settings(
    body: SetAiSettingsRequest,
    request: Request,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> AiSettingsOut:
    if ai_status(repo).forced_off:
        raise HTTPException(status_code=409, detail="AI assist is turned off by the server (KRESHEEN_AI_DISABLED).")
    set_ai_enabled(repo, body.enabled, user.id)
    record_event(
        repo,
        action="ai.instance_toggled",
        user_id=user.id,
        user_email=user.email,
        subject={"enabled": str(body.enabled).lower()},
        status_code=200,
        via="api_token" if getattr(request.state, "via_api_token", False) else "session",
        client_ip=request.client.host if request.client else None,
    )
    return _out(repo)

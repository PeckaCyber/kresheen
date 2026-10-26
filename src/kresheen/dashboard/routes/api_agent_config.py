"""JSON API for Settings' AI section: a user's own Anthropic API key + model choice for the experimental AI assist.

Always mounted, but every route answers 404 until the instance owner enables AI (and while `KRESHEEN_AI_DISABLED`
forces it off), so a default install exposes nothing. Each person has one config of their own (key, model, optional
Anthropic workspace ID); there is no shared or per-application key. Anthropic-only.

`default_model=None` ("rule-based only, no AI calls") is a first-class, permanent choice: threat modeling is fully
working without any key. The model list itself is never hardcoded: `POST /api/agent-config/models` asks
Anthropic's live model list (through the provider) for the *specific key* in play, so the dropdown always reflects what
that key can actually use.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, BeforeValidator, Field

from kresheen.dashboard.audit import record_event
from kresheen.dashboard.auth import get_current_session, get_current_user, require_csrf
from kresheen.dashboard.deps import get_llm_provider, get_repo
from kresheen.engine.llm.settings import ai_status
from kresheen.engine.llm.types import LlmProvider, ProviderError
from kresheen.models.agent_config import AgentConfig, new_agent_config_id
from kresheen.models.user import User
from kresheen.secrets.store import DbSecretStore, SecretKeyMissing
from kresheen.storage.repository import Repository


def require_ai_enabled(repo: Repository = Depends(get_repo)) -> None:
    """404 (not 403) while the instance switch is off or forced off: the feature does not exist, as far as a client
    can tell."""
    if not ai_status(repo).enabled:
        raise HTTPException(status_code=404, detail="Not found")


router = APIRouter(
    prefix="/api/agent-config",
    tags=["agent-config"],
    dependencies=[Depends(get_current_session), Depends(require_ai_enabled)],
)


def _blank_to_none(value: object) -> object:
    return value.strip() or None if isinstance(value, str) else value


# Sent to Anthropic as a request header, so only id characters are accepted (no spaces, no line breaks).
WorkspaceId = Annotated[
    Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,100}$")] | None, BeforeValidator(_blank_to_none)
]


class ModelOut(BaseModel):
    id: str
    display_name: str


class AgentConfigOut(BaseModel):
    default_model: str | None
    has_api_key: bool
    workspace_id: str | None = None


class SaveAgentConfigRequest(BaseModel):
    api_key: str | None = None  # raw key, write-only; omit to keep the existing one
    default_model: str | None = None
    workspace_id: WorkspaceId = None  # only for a key that is not tied to a workspace; omit or blank for none


class ListModelsRequest(BaseModel):
    api_key: str | None = None  # a not-yet-saved key to check; omit to use the user's saved key
    workspace_id: WorkspaceId = None


def _out(config: AgentConfig | None) -> AgentConfigOut:
    if config is None:
        return AgentConfigOut(default_model=None, has_api_key=False)
    return AgentConfigOut(
        default_model=config.default_model,
        has_api_key=bool(config.api_key_ref),
        workspace_id=config.workspace_id,
    )


def _list_models_for_key(provider: LlmProvider, api_key: str, workspace_id: str | None = None) -> list[ModelOut]:
    try:
        models = provider.list_models(api_key, workspace_id=workspace_id)
    except ProviderError as exc:
        if exc.kind == "auth":
            raise HTTPException(status_code=422, detail="Invalid API key.") from None
        if exc.kind in ("workspace", "workspace_invalid"):
            raise HTTPException(status_code=422, detail=exc.message) from None
        raise HTTPException(status_code=502, detail=exc.message) from None
    return [ModelOut(id=m.id, display_name=m.display_name) for m in models]


def _audit(request: Request, repo: Repository, user: User, action: str) -> None:
    record_event(
        repo,
        action=action,
        user_id=user.id,
        user_email=user.email,
        status_code=200,
        via="api_token" if getattr(request.state, "via_api_token", False) else "session",
        client_ip=request.client.host if request.client else None,
    )


@router.get("", response_model=AgentConfigOut)
def get_agent_config(user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)) -> AgentConfigOut:
    return _out(repo.get_agent_config("user", user.id))


@router.post("/models", response_model=list[ModelOut], dependencies=[Depends(require_csrf)])
def list_models(
    body: ListModelsRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
    provider: LlmProvider = Depends(get_llm_provider),
) -> list[ModelOut]:
    api_key = body.api_key
    if not api_key:
        existing = repo.get_agent_config("user", user.id)
        if existing and existing.api_key_ref:
            api_key = DbSecretStore(repo).get(existing.api_key_ref)
    if not api_key:
        return []
    return _list_models_for_key(provider, api_key, body.workspace_id)


@router.put("", response_model=AgentConfigOut, dependencies=[Depends(require_csrf)])
def save_agent_config(
    body: SaveAgentConfigRequest,
    request: Request,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
    provider: LlmProvider = Depends(get_llm_provider),
) -> AgentConfigOut:
    store: DbSecretStore | None = None
    if body.api_key:
        # Checked first so nothing leaves the server (no model-list call) for a key that cannot be stored anyway.
        try:
            store = DbSecretStore(repo)
        except SecretKeyMissing:
            raise HTTPException(
                status_code=400,
                detail="Cannot store an API key: the server has no KRESHEEN_SECRET_KEY set. Ask the administrator.",
            ) from None
    existing = repo.get_agent_config("user", user.id)
    api_key_ref = existing.api_key_ref if existing else None

    effective_key: str | None = body.api_key
    if effective_key is None and api_key_ref:
        effective_key = DbSecretStore(repo).get(api_key_ref)

    if body.default_model is not None:
        # A chosen model always needs a key to validate against -- "rule-based
        # only" is the only choice that's valid with no key at all.
        if not effective_key:
            raise HTTPException(status_code=422, detail="An API key is required to select a model.")
        available = {model.id for model in _list_models_for_key(provider, effective_key, body.workspace_id)}
        if body.default_model not in available:
            raise HTTPException(status_code=422, detail=f"Unknown model for this key: {body.default_model}")

    key_added = False
    if body.api_key and store is not None:
        previous_ref = api_key_ref
        api_key_ref = store.set(f"user:{user.id}", body.api_key)
        if previous_ref:
            store.delete(previous_ref)  # a replaced key must not linger encrypted in the table
        key_added = True

    now = datetime.now(UTC)
    config = AgentConfig(
        id=existing.id if existing else new_agent_config_id(),
        scope="user",
        scope_id=user.id,
        api_key_ref=api_key_ref,
        default_model=body.default_model,
        workspace_id=body.workspace_id,
        created_at=existing.created_at if existing else now,
        updated_at=now,
    )
    repo.save_agent_config(config)
    if key_added:
        _audit(request, repo, user, "ai.key_added")
    return _out(config)


@router.delete("/key", response_model=AgentConfigOut, dependencies=[Depends(require_csrf)])
def remove_api_key(
    request: Request, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> AgentConfigOut:
    """ "Remove my key": deletes the encrypted key and the model choice (a model is meaningless without a key). Needs no
    `KRESHEEN_SECRET_KEY`, since nothing is decrypted."""
    existing = repo.get_agent_config("user", user.id)
    if existing is None or not existing.api_key_ref:
        return _out(existing)
    repo.delete_secret_blob(existing.api_key_ref)
    config = existing.model_copy(update={"api_key_ref": None, "default_model": None, "updated_at": datetime.now(UTC)})
    repo.save_agent_config(config)
    _audit(request, repo, user, "ai.key_removed")
    return _out(config)

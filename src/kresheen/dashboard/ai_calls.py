"""Shared plumbing for the routes that call the experimental AI assist (intake draft, threat explain).

Every AI route depends on `require_ai_caller` and calls `run_ai_task`, so availability, the user's own key, the rate
limit, error mapping and auditing live in one place. The guardrails themselves are in `engine/llm/policy.py`.

AI is available to a user only when the instance switch is on, not forced off, and the user has stored a key and
picked a model. Otherwise the routes answer 404: as far as a client can tell, the feature does not exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from kresheen.dashboard.audit import record_event
from kresheen.dashboard.auth import get_current_user
from kresheen.dashboard.deps import get_llm_provider, get_repo
from kresheen.engine.llm.limits import RateLimited, RateLimiter
from kresheen.engine.llm.policy import (
    ContentTooLarge,
    InvalidModelOutput,
    LlmResult,
    LlmTask,
    run_llm_task,
)
from kresheen.engine.llm.settings import ai_status
from kresheen.engine.llm.types import LlmProvider, ProviderError
from kresheen.models.user import User
from kresheen.secrets.store import DbSecretStore
from kresheen.storage.repository import Repository

T = TypeVar("T", bound=BaseModel)


@dataclass(frozen=True)
class AiCaller:
    user: User
    api_key: str
    model: str
    provider: LlmProvider
    workspace_id: str | None = None


def require_ai_caller(
    repo: Repository = Depends(get_repo),
    user: User = Depends(get_current_user),
    provider: LlmProvider = Depends(get_llm_provider),
) -> AiCaller:
    if not ai_status(repo).enabled:
        raise HTTPException(status_code=404, detail="Not found")
    config = repo.get_agent_config("user", user.id)
    if config is None or not config.api_key_ref or not config.default_model:
        raise HTTPException(status_code=404, detail="Not found")
    api_key = DbSecretStore(repo).get(config.api_key_ref)  # SecretKeyMissing -> the app-wide 503 handler
    if not api_key:
        raise HTTPException(status_code=404, detail="Not found")
    return AiCaller(
        user=user, api_key=api_key, model=config.default_model, provider=provider, workspace_id=config.workspace_id
    )


def _rate_limiter(request: Request) -> RateLimiter:
    # Per app (and so per process), which keeps test apps independent of each other.
    limiter = getattr(request.app.state, "ai_rate_limiter", None)
    if limiter is None:
        limiter = RateLimiter()
        request.app.state.ai_rate_limiter = limiter
    return limiter  # type: ignore[no-any-return]


def _audit(
    request: Request, repo: Repository, user: User, action: str, subject: dict[str, str], status_code: int
) -> None:
    record_event(
        repo,
        action=action,
        user_id=user.id,
        user_email=user.email,
        subject=subject,
        status_code=status_code,
        via="api_token" if getattr(request.state, "via_api_token", False) else "session",
        client_ip=request.client.host if request.client else None,
    )


def run_ai_task(
    request: Request,
    repo: Repository,
    caller: AiCaller,
    task: LlmTask[T],
    content: str,
    scan_text: str | None = None,
) -> LlmResult[T]:
    """Rate limit, guarded call, audit. Raises HTTPException with a user-facing message on any failure.

    Audits one `ai.call` per attempt (task, model, token counts, outcome; never content or keys) and one
    `ai.injection_signal` security event per signal found in the content (or in `scan_text`, the full
    content, when `content` was shortened before sending).
    """
    subject = {"task": task.name, "model": caller.model}
    try:
        _rate_limiter(request).check(caller.user.id)
        result = run_llm_task(
            task,
            content,
            caller.provider,
            model=caller.model,
            api_key=caller.api_key,
            scan_text=scan_text,
            workspace_id=caller.workspace_id,
        )
    except RateLimited as exc:
        _audit(request, repo, caller.user, "ai.call", {**subject, "outcome": "rate_limited"}, 429)
        raise HTTPException(
            status_code=429,
            detail="Too many AI requests. Try again in a few minutes.",
            headers={"Retry-After": str(int(exc.retry_after_s) + 1)},
        ) from None
    except ContentTooLarge as exc:
        _audit(request, repo, caller.user, "ai.call", {**subject, "outcome": "too_large"}, 413)
        raise HTTPException(status_code=413, detail=str(exc)) from None
    except InvalidModelOutput:
        _audit(request, repo, caller.user, "ai.call", {**subject, "outcome": "invalid_output"}, 502)
        raise HTTPException(status_code=502, detail="The AI answer could not be used. Try again.") from None
    except ProviderError as exc:
        status = 429 if exc.kind == "rate_limit" else 502
        _audit(request, repo, caller.user, "ai.call", {**subject, "outcome": f"provider_{exc.kind}"}, status)
        raise HTTPException(status_code=status, detail=exc.message) from None
    _audit(
        request,
        repo,
        caller.user,
        "ai.call",
        {
            **subject,
            "outcome": "ok",
            "input_tokens": str(result.usage.input_tokens),
            "output_tokens": str(result.usage.output_tokens),
        },
        200,
    )
    for signal in result.signals:
        _audit(
            request,
            repo,
            caller.user,
            "ai.injection_signal",
            # No excerpt: the audit log never holds user text. The person who sent it sees the excerpt in the warning.
            {"task": task.name, "pattern": signal.pattern, "cwe": signal.cwe},
            200,
        )
    return result

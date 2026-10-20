"""Anthropic provider client and the test double.

`anthropic` is imported inside methods only, so an instance with AI switched off never loads the SDK and importing
this module costs nothing. The provider takes the decrypted user key per call and never stores it. Neither keys nor
prompt/response content are logged here, and `ProviderError` messages are fixed strings, so an SDK error body (which
can echo request details) never reaches a user or a log line.

`KRESHEEN_AI_BASE_URL` points the SDK at another server (an end-to-end stub). It is read from the environment only and
is deliberately not settable from the UI or the API.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from kresheen.engine.llm.limits import REQUEST_TIMEOUT_S
from kresheen.engine.llm.types import ModelInfo, ProviderError, ProviderErrorKind, Usage

BASE_URL_ENV = "KRESHEEN_AI_BASE_URL"

_MESSAGES: dict[str, str] = {
    "auth": "Anthropic rejected the API key. Check that it is correct and still active.",
    "rate_limit": "Anthropic is rate limiting this key. Try again in a minute.",
    "overloaded": "Anthropic is overloaded right now. Try again shortly.",
    "timeout": "The request to Anthropic timed out. Try again.",
    "bad_request": "Anthropic could not process this request.",
    "workspace": (
        "This API key is not tied to a workspace, so Anthropic needs a workspace ID with every request. "
        "Enter the workspace ID below, or create the key inside a workspace in the Anthropic Console."
    ),
    "workspace_invalid": (
        "Anthropic did not accept the workspace ID. Copy it from the Anthropic Console (Settings, Workspaces); "
        "it starts with wrkspc_. The workspace name does not work here."
    ),
    "unavailable": "Could not reach Anthropic. Try again later.",
}


def provider_error(kind: ProviderErrorKind) -> ProviderError:
    return ProviderError(kind, _MESSAGES[kind])


def _map_sdk_error(exc: Exception) -> ProviderError:
    """Most specific class first: the timeout error subclasses the connection error."""
    import anthropic

    if isinstance(exc, anthropic.APITimeoutError):
        return provider_error("timeout")
    if isinstance(exc, anthropic.APIConnectionError):
        return provider_error("unavailable")
    if isinstance(exc, (anthropic.AuthenticationError, anthropic.PermissionDeniedError)):
        return provider_error("auth")
    if isinstance(exc, anthropic.RateLimitError):
        return provider_error("rate_limit")
    if isinstance(exc, anthropic.OverloadedError) or getattr(exc, "status_code", None) == 529:
        return provider_error("overloaded")
    # Anthropic's error text is never passed on, only matched: this one has a fix the user can make themselves.
    detail = str(getattr(exc, "message", "")).lower()
    if isinstance(exc, anthropic.BadRequestError) and "workspace" in detail:
        return provider_error("workspace_invalid" if "valid workspace id" in detail else "workspace")
    if isinstance(
        exc,
        (
            anthropic.BadRequestError,
            anthropic.NotFoundError,
            anthropic.UnprocessableEntityError,
            anthropic.RequestTooLargeError,
        ),
    ):
        return provider_error("bad_request")
    return provider_error("unavailable")


class AnthropicProvider:
    """One wrapper around the Anthropic SDK; the only place it is called."""

    def _client(self, api_key: str, timeout_s: float | None = None, workspace_id: str | None = None) -> Any:
        import anthropic

        # One attempt only: the SDK would otherwise retry a timed-out call, doubling the documented 60-second limit.
        # The user sees a clear "try again" instead.
        kwargs: dict[str, Any] = {"api_key": api_key, "max_retries": 0}
        if workspace_id:
            kwargs["default_headers"] = {"anthropic-workspace-id": workspace_id}
        base_url = os.environ.get(BASE_URL_ENV, "").strip()
        if base_url:
            kwargs["base_url"] = base_url
        if timeout_s is not None:
            kwargs["timeout"] = timeout_s
        return anthropic.Anthropic(**kwargs)

    def complete_structured(
        self,
        *,
        api_key: str,
        model: str,
        system: str,
        user: str,
        response_model: type[BaseModel],
        max_output_tokens: int,
        timeout_s: float,
        workspace_id: str | None = None,
    ) -> tuple[dict, Usage, str]:
        """One request constrained to `response_model`'s JSON schema (`output_config.format`); returns the parsed JSON
        dict. Validating it against the model is the caller's job (the policy layer), not done here."""
        import anthropic

        try:
            response = self._client(api_key, timeout_s, workspace_id).messages.create(
                model=model,
                max_tokens=max_output_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={
                    "format": {"type": "json_schema", "schema": anthropic.transform_schema(response_model)}
                },
            )
        except anthropic.AnthropicError as exc:
            raise _map_sdk_error(exc) from None
        text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), None)
        if response.stop_reason in ("refusal", "max_tokens") or text is None:
            raise provider_error("bad_request")
        try:
            parsed = json.loads(text)
        except ValueError:
            raise provider_error("bad_request") from None
        if not isinstance(parsed, dict):
            raise provider_error("bad_request")
        usage = Usage(input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens)
        return parsed, usage, str(response.model)

    def list_models(self, api_key: str, workspace_id: str | None = None) -> list[ModelInfo]:
        import anthropic

        try:
            page = self._client(api_key, REQUEST_TIMEOUT_S, workspace_id).models.list()
            return [ModelInfo(id=m.id, display_name=m.display_name) for m in page]
        except anthropic.AnthropicError as exc:
            raise _map_sdk_error(exc) from None


@dataclass
class FakeCall:
    api_key: str
    model: str
    system: str
    user: str
    response_model: str
    workspace_id: str | None = None


@dataclass
class FakeProvider:
    """Test double: returns a canned dict per `response_model` class name (or `default`), records every call, and can
    be told to fail with a `ProviderError` or to answer `list_models` with a fixed list."""

    responses: dict[str, dict] = field(default_factory=dict)
    default: dict = field(default_factory=dict)
    models: list[ModelInfo] = field(default_factory=lambda: [ModelInfo("fake-model", "Fake model")])
    error: ProviderError | None = None
    usage: Usage = field(default_factory=lambda: Usage(input_tokens=10, output_tokens=5))
    calls: list[FakeCall] = field(default_factory=list)
    model_list_calls: list[str] = field(default_factory=list)
    model_list_workspaces: list[str | None] = field(default_factory=list)

    def complete_structured(
        self,
        *,
        api_key: str,
        model: str,
        system: str,
        user: str,
        response_model: type[BaseModel],
        max_output_tokens: int,
        timeout_s: float,
        workspace_id: str | None = None,
    ) -> tuple[dict, Usage, str]:
        self.calls.append(FakeCall(api_key, model, system, user, response_model.__name__, workspace_id))
        if self.error is not None:
            raise self.error
        return dict(self.responses.get(response_model.__name__, self.default)), self.usage, model

    def list_models(self, api_key: str, workspace_id: str | None = None) -> list[ModelInfo]:
        self.model_list_calls.append(api_key)
        self.model_list_workspaces.append(workspace_id)
        if self.error is not None:
            raise self.error
        return list(self.models)

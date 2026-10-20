"""Types shared by the guardrail policy and the provider implementations.

Kept free of any SDK import so a disabled instance never loads one, and so the
policy module and the provider module agree on one contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol

from pydantic import BaseModel


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int


ProviderErrorKind = Literal["auth", "rate_limit", "overloaded", "timeout", "bad_request", "workspace", "workspace_invalid", "unavailable"]


class ProviderError(Exception):
    """A provider failure with a fixed, user-facing message (never the key or the content)."""

    def __init__(self, kind: ProviderErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind: ProviderErrorKind = kind
        self.message = message


@dataclass(frozen=True)
class ModelInfo:
    id: str
    display_name: str


class LlmProvider(Protocol):
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
    ) -> tuple[dict[str, Any], Usage, str]:
        """Returns (parsed JSON, token usage, model that answered)."""
        ...

    def list_models(self, api_key: str, workspace_id: str | None = None) -> list[ModelInfo]: ...

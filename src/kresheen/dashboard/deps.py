from __future__ import annotations

from fastapi import Request

from kresheen.engine.llm.types import LlmProvider
from kresheen.storage.repository import Repository


def get_repo(request: Request) -> Repository:
    return request.app.state.repo  # type: ignore[no-any-return]


def get_llm_provider(request: Request) -> LlmProvider:
    """The provider AI routes call; `create_app(llm_provider=...)` swaps in a fake for tests."""
    return request.app.state.llm_provider  # type: ignore[no-any-return]

"""`_list_models_for_key` (through AnthropicProvider) maps anthropic's SDK exceptions to HTTP errors --
tests patch `anthropic.Anthropic` itself (not the network) so no real
request ever leaves this process."""

from __future__ import annotations

import anthropic
import httpx2
import pytest
from fastapi import HTTPException

from kresheen.dashboard.routes.api_agent_config import ModelOut, _list_models_for_key
from kresheen.engine.llm.provider import AnthropicProvider

_FAKE_REQUEST = httpx2.Request("GET", "https://api.anthropic.com/v1/models")


class _FakeModel:
    def __init__(self, id_: str, display_name: str):
        self.id = id_
        self.display_name = display_name


def test_list_models_for_key_maps_sdk_models_to_model_out(monkeypatch):
    class _FakeModelsResource:
        def list(self):
            return [_FakeModel("claude-haiku-4-5", "Claude Haiku 4.5")]

    class _FakeClient:
        def __init__(self, api_key: str, **kwargs):
            self.api_key = api_key
            self.models = _FakeModelsResource()

    monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)

    result = _list_models_for_key(AnthropicProvider(), "sk-ant-fake")

    assert result == [ModelOut(id="claude-haiku-4-5", display_name="Claude Haiku 4.5")]


def test_list_models_for_key_raises_422_on_invalid_key(monkeypatch):
    class _FakeModelsResource:
        def list(self):
            raise anthropic.AuthenticationError(
                "invalid x-api-key", response=httpx2.Response(401, request=_FAKE_REQUEST), body=None
            )

    class _FakeClient:
        def __init__(self, api_key: str, **kwargs):
            self.models = _FakeModelsResource()

    monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)

    with pytest.raises(HTTPException) as exc_info:
        _list_models_for_key(AnthropicProvider(), "sk-ant-invalid")

    assert exc_info.value.status_code == 422


def test_list_models_for_key_raises_502_on_connection_error(monkeypatch):
    class _FakeModelsResource:
        def list(self):
            raise anthropic.APIConnectionError(request=_FAKE_REQUEST)

    class _FakeClient:
        def __init__(self, api_key: str, **kwargs):
            self.models = _FakeModelsResource()

    monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)

    with pytest.raises(HTTPException) as exc_info:
        _list_models_for_key(AnthropicProvider(), "sk-ant-fake")

    assert exc_info.value.status_code == 502

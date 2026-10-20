"""AnthropicProvider with the SDK client mocked: no network, no key. Covers error mapping, base_url and lazy import."""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx2 as httpx
import pytest
from pydantic import BaseModel

from kresheen.engine.llm.provider import AnthropicProvider, FakeProvider
from kresheen.engine.llm.types import ModelInfo, ProviderError, Usage


class Answer(BaseModel):
    text: str


def _request() -> httpx.Request:
    return httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def _status_error(cls, status: int):
    return cls("boom sk-ant-secret", response=httpx.Response(status, request=_request()), body=None)


def _message(text: str = '{"text": "hi"}', stop_reason: str = "end_turn"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=11, output_tokens=7),
        model="claude-test",
    )


def _call(provider: AnthropicProvider):
    return provider.complete_structured(
        api_key="sk-ant-test",
        model="claude-test",
        system="sys",
        user="data",
        response_model=Answer,
        max_output_tokens=100,
        timeout_s=5,
    )


@pytest.fixture
def sdk_client(monkeypatch):
    import anthropic

    client = MagicMock()
    ctor = MagicMock(return_value=client)
    monkeypatch.setattr(anthropic, "Anthropic", ctor)
    monkeypatch.delenv("KRESHEEN_AI_BASE_URL", raising=False)
    return client, ctor


def test_importing_provider_does_not_import_anthropic():
    code = (
        "import sys; import kresheen.engine.llm.provider, kresheen.engine.llm.settings, kresheen.dashboard.app; "
        "sys.exit(1 if 'anthropic' in sys.modules else 0)"
    )
    assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0


def test_complete_structured_returns_parsed_dict_usage_and_model(sdk_client):
    client, ctor = sdk_client
    client.messages.create.return_value = _message()

    parsed, usage, model = _call(AnthropicProvider())

    assert parsed == {"text": "hi"}
    assert usage == Usage(11, 7)
    assert model == "claude-test"
    kwargs = client.messages.create.call_args.kwargs
    assert kwargs["system"] == "sys"
    assert kwargs["messages"] == [{"role": "user", "content": "data"}]
    fmt = kwargs["output_config"]["format"]
    assert fmt["type"] == "json_schema" and fmt["schema"]["properties"]["text"]["type"] == "string"
    assert ctor.call_args.kwargs["api_key"] == "sk-ant-test"
    assert ctor.call_args.kwargs["timeout"] == 5


def test_base_url_comes_from_env_only(sdk_client, monkeypatch):
    client, ctor = sdk_client
    client.messages.create.return_value = _message()
    _call(AnthropicProvider())
    assert "base_url" not in ctor.call_args.kwargs

    monkeypatch.setenv("KRESHEEN_AI_BASE_URL", "http://127.0.0.1:9999")
    _call(AnthropicProvider())
    assert ctor.call_args.kwargs["base_url"] == "http://127.0.0.1:9999"


@pytest.mark.parametrize(
    ("name", "status", "kind"),
    [
        ("AuthenticationError", 401, "auth"),
        ("PermissionDeniedError", 403, "auth"),
        ("RateLimitError", 429, "rate_limit"),
        ("OverloadedError", 529, "overloaded"),
        ("BadRequestError", 400, "bad_request"),
        ("InternalServerError", 500, "unavailable"),
    ],
)
def test_status_errors_map_to_provider_errors_with_fixed_messages(sdk_client, name, status, kind):
    import anthropic

    client, _ = sdk_client
    client.messages.create.side_effect = _status_error(getattr(anthropic, name), status)

    with pytest.raises(ProviderError) as info:
        _call(AnthropicProvider())

    assert info.value.kind == kind
    assert "sk-ant" not in info.value.message and "boom" not in info.value.message
    assert info.value.__cause__ is None  # the SDK error (which can echo request details) is not chained


def test_timeout_and_connection_errors_are_distinct(sdk_client):
    import anthropic

    client, _ = sdk_client
    client.messages.create.side_effect = anthropic.APITimeoutError(request=_request())
    with pytest.raises(ProviderError) as info:
        _call(AnthropicProvider())
    assert info.value.kind == "timeout"

    client.messages.create.side_effect = anthropic.APIConnectionError(request=_request())
    with pytest.raises(ProviderError) as info:
        _call(AnthropicProvider())
    assert info.value.kind == "unavailable"


@pytest.mark.parametrize(
    "message",
    [_message("not json"), _message("[1, 2]"), _message(stop_reason="refusal"), _message(stop_reason="max_tokens"),
     SimpleNamespace(content=[], stop_reason="end_turn", usage=None, model="m")],
)
def test_unusable_responses_are_bad_request(sdk_client, message):
    client, _ = sdk_client
    client.messages.create.return_value = message
    with pytest.raises(ProviderError) as info:
        _call(AnthropicProvider())
    assert info.value.kind == "bad_request"


def test_list_models_maps_and_wraps_errors(sdk_client):
    import anthropic

    client, _ = sdk_client
    client.models.list.return_value = [SimpleNamespace(id="a", display_name="A"), SimpleNamespace(id="b", display_name="B")]
    assert AnthropicProvider().list_models("sk-ant-test") == [ModelInfo("a", "A"), ModelInfo("b", "B")]

    client.models.list.side_effect = _status_error(anthropic.AuthenticationError, 401)
    with pytest.raises(ProviderError) as info:
        AnthropicProvider().list_models("sk-ant-test")
    assert info.value.kind == "auth"


def test_fake_provider_records_calls_and_returns_canned_answers():
    fake = FakeProvider(responses={"Answer": {"text": "canned"}})
    parsed, usage, model = fake.complete_structured(
        api_key="k", model="m", system="s", user="u", response_model=Answer, max_output_tokens=1, timeout_s=1
    )
    assert parsed == {"text": "canned"} and model == "m" and usage.input_tokens == 10
    assert [c.response_model for c in fake.calls] == ["Answer"]

    failing = FakeProvider(error=ProviderError("rate_limit", "slow down"))
    with pytest.raises(ProviderError):
        failing.list_models("k")


def test_workspace_id_is_sent_as_a_header_only_when_set(sdk_client):
    client, ctor = sdk_client
    client.messages.create.return_value = _message()
    _call(AnthropicProvider())
    assert "default_headers" not in ctor.call_args.kwargs
    AnthropicProvider().complete_structured(
        api_key="sk-ant-test",
        model="claude-test",
        system="sys",
        user="data",
        response_model=Answer,
        max_output_tokens=100,
        timeout_s=5,
        workspace_id="wrkspc_abc123",
    )
    assert ctor.call_args.kwargs["default_headers"] == {"anthropic-workspace-id": "wrkspc_abc123"}
    client.models.list.return_value = []
    AnthropicProvider().list_models("sk-ant-test", workspace_id="wrkspc_abc123")
    assert ctor.call_args.kwargs["default_headers"] == {"anthropic-workspace-id": "wrkspc_abc123"}


def test_a_missing_workspace_is_its_own_error_with_a_fixed_message(sdk_client):
    import anthropic

    client, _ = sdk_client
    client.models.list.side_effect = anthropic.BadRequestError(
        "This API key is not scoped to a workspace, so this request must include the anthropic-workspace-id header",
        response=httpx.Response(400, request=_request()),
        body=None,
    )
    with pytest.raises(ProviderError) as info:
        AnthropicProvider().list_models("sk-ant-test")
    assert info.value.kind == "workspace"
    assert "workspace ID" in info.value.message and "anthropic-workspace-id" not in info.value.message
    # any other 400 stays the generic bad request
    client.models.list.side_effect = _status_error(anthropic.BadRequestError, 400)
    with pytest.raises(ProviderError) as info:
        AnthropicProvider().list_models("sk-ant-test")
    assert info.value.kind == "bad_request"


def test_a_rejected_workspace_id_gets_its_own_message(sdk_client):
    import anthropic

    client, _ = sdk_client
    client.models.list.side_effect = anthropic.BadRequestError(
        "anthropic-workspace-id header must be a valid workspace ID.",
        response=httpx.Response(400, request=_request()),
        body=None,
    )
    with pytest.raises(ProviderError) as info:
        AnthropicProvider().list_models("sk-ant-test", workspace_id="Default")
    assert info.value.kind == "workspace_invalid" and "wrkspc_" in info.value.message


def test_one_attempt_with_the_documented_timeout_and_no_sdk_retry(sdk_client):
    """docs/ai.md promises a 60-second timeout; an SDK retry would silently double it."""
    from kresheen.engine.llm.limits import REQUEST_TIMEOUT_S

    client, ctor = sdk_client
    client.messages.create.return_value = _message()
    AnthropicProvider().complete_structured(
        api_key="sk-ant-test", model="claude-test", system="sys", user="data",
        response_model=Answer, max_output_tokens=100, timeout_s=REQUEST_TIMEOUT_S,
    )
    assert ctor.call_args.kwargs["max_retries"] == 0
    assert ctor.call_args.kwargs["timeout"] == 60.0

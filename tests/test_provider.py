"""AnthropicProvider request shape and response handling, with the SDK client stubbed out."""

from types import SimpleNamespace
from typing import Any

import pytest

from agentcapmap.classify.provider import AnthropicProvider, ProviderError


class StubMessages:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        return self.response


def _provider(
    monkeypatch: pytest.MonkeyPatch, response: Any, model: str = "claude-opus-5-5"
) -> tuple[AnthropicProvider, StubMessages]:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    provider = AnthropicProvider(model=model)
    stub = StubMessages(response)
    provider._client = SimpleNamespace(beta=SimpleNamespace(messages=stub))  # type: ignore[assignment]
    return provider, stub


def _response(text: str | None = '{"ok": true}', stop_reason: str = "end_turn") -> Any:
    content = [SimpleNamespace(type="thinking", thinking="")]
    if text is not None:
        content.append(SimpleNamespace(type="text", text=text))
    return SimpleNamespace(content=content, stop_reason=stop_reason, model="claude-opus-5-5")


def test_request_shape_for_current_model(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, stub = _provider(monkeypatch, _response())
    result = provider.complete_json("SYS", "USER", {"type": "object"})
    assert result.text == '{"ok": true}'
    assert result.model == "claude-opus-5-5"

    kw = stub.kwargs
    assert kw["model"] == "claude-opus-5-5"
    assert kw["output_config"] == {
        "effort": "medium",
        "format": {"type": "json_schema", "schema": {"type": "object"}},
    }
    assert kw["system"][0]["text"] == "SYS"
    assert kw["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert kw["messages"] == [{"role": "user", "content": "USER"}]
    assert kw["fallbacks"] == "default"
    assert kw["betas"] == ["server-side-fallback-2026-07-01"]
    # Current models reject sampling parameters.
    assert kw["extra_body"] is None
    assert "temperature" not in kw


def test_temperature_zero_for_models_that_accept_it(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, stub = _provider(monkeypatch, _response(), model="claude-sonnet-4-6")
    provider.complete_json("SYS", "USER", {})
    assert stub.kwargs["extra_body"] == {"temperature": 0}


def test_model_and_effort_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTCAPMAP_MODEL", "claude-sonnet-5-5")
    monkeypatch.setenv("AGENTCAPMAP_EFFORT", "low")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    provider = AnthropicProvider()
    assert provider.model == "claude-sonnet-5-5"
    monkeypatch.setenv("AGENTCAPMAP_EFFORT", "extreme")
    with pytest.raises(ValueError, match="invalid effort"):
        AnthropicProvider()


@pytest.mark.parametrize(
    ("response", "message", "permanent"),
    [
        (_response(stop_reason="refusal"), "declined", True),
        (_response(stop_reason="max_tokens"), "truncated", True),
        (_response(text=None), "no text block", False),
    ],
)
def test_unusable_responses(
    monkeypatch: pytest.MonkeyPatch, response: Any, message: str, permanent: bool
) -> None:
    provider, _ = _provider(monkeypatch, response)
    with pytest.raises(ProviderError, match=message) as exc:
        provider.complete_json("SYS", "USER", {})
    assert exc.value.permanent is permanent


def test_connection_errors_become_provider_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import anthropic

    provider, stub = _provider(monkeypatch, None)

    def boom(**kwargs: Any) -> Any:
        raise anthropic.APIConnectionError(request=None)  # type: ignore[arg-type]

    stub.create = boom  # type: ignore[method-assign]
    with pytest.raises(ProviderError, match="could not reach") as exc:
        provider.complete_json("SYS", "USER", {})
    assert not exc.value.permanent

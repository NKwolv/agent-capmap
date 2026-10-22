"""LLM provider interface. The classifier only needs "system + user + schema -> JSON text"."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, cast, get_args

if TYPE_CHECKING:
    from anthropic.types.beta import BetaOutputConfigParam, BetaTextBlockParam

Effort = Literal["low", "medium", "high", "xhigh", "max"]

DEFAULT_MODEL: Final = "claude-opus-5-5"
DEFAULT_EFFORT: Final = "medium"
MODEL_ENV: Final = "AGENTCAPMAP_MODEL"
EFFORT_ENV: Final = "AGENTCAPMAP_EFFORT"

# Current Claude models reject sampling parameters; these older ones still accept
# temperature, so we pin it to 0 there (design rule 3).
_TEMPERATURE_MODELS: Final = (
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
    "claude-opus-4-5",
    "claude-opus-4-1",
)


class ProviderError(Exception):
    """The provider could not produce a response.

    `permanent` errors (refusal, truncation) would recur on retry, so their result may be
    cached; transient ones (network, auth, rate limit) must not be.
    """

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str  # model that actually produced the text (may differ after a fallback)


class LLMProvider(Protocol):
    @property
    def model(self) -> str:
        """Model identifier used for requests (part of the classification cache key)."""

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> LLMResponse:
        """Return JSON text constrained to `schema`."""


def configured_model() -> str:
    return os.environ.get(MODEL_ENV, "").strip() or DEFAULT_MODEL


class AnthropicProvider:
    """Claude via the official SDK, with structured outputs and refusal fallback."""

    def __init__(self, model: str | None = None, effort: str | None = None) -> None:
        import anthropic  # imported lazily so --offline never needs credentials

        self._anthropic = anthropic
        self._model = model or configured_model()
        chosen = effort or os.environ.get(EFFORT_ENV, "").strip() or DEFAULT_EFFORT
        if chosen not in get_args(Effort):
            raise ValueError(f"invalid effort {chosen!r}; expected one of {get_args(Effort)}")
        self._effort = cast(Effort, chosen)
        # Credentials come from ANTHROPIC_API_KEY (or an `ant auth login` profile).
        self._client = anthropic.Anthropic(max_retries=3)

    @property
    def model(self) -> str:
        return self._model

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> LLMResponse:
        anthropic = self._anthropic
        extra_body: dict[str, Any] = {}
        if self._model.startswith(_TEMPERATURE_MODELS):
            extra_body["temperature"] = 0
        system_blocks: list[BetaTextBlockParam] = [
            {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
        ]
        output_config: BetaOutputConfigParam = {
            "effort": self._effort,
            "format": {"type": "json_schema", "schema": schema},
        }
        try:
            response = self._client.beta.messages.create(
                model=self._model,
                max_tokens=16000,
                system=system_blocks,
                messages=[{"role": "user", "content": user}],
                output_config=output_config,
                # A tool description quoting attack text can trip a safety classifier;
                # server-side fallback lets another model finish the classification.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                extra_body=extra_body or None,
            )
        except anthropic.AuthenticationError as exc:
            raise ProviderError(f"authentication failed: {exc.message}") from None
        except anthropic.RateLimitError:
            raise ProviderError("rate limited after retries") from None
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"API error {exc.status_code}: {exc.message}") from None
        except anthropic.APIConnectionError:
            raise ProviderError("could not reach the Anthropic API") from None

        if response.stop_reason == "refusal":
            raise ProviderError("model declined to classify this tool", permanent=True)
        if response.stop_reason == "max_tokens":
            raise ProviderError("response truncated at max_tokens", permanent=True)
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise ProviderError("response contained no text block")
        return LLMResponse(text=text, model=response.model)

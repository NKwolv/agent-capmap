"""Scripted LLM provider for tests. No network."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from typing import Any

from agentcapmap.classify.provider import LLMResponse, ProviderError
from agentcapmap.taxonomy import AXES, DEFAULTS

Reply = str | ProviderError | Callable[[str], str]


def classification_json(
    tool: str,
    *,
    confidence: float = 0.9,
    suspicious: tuple[bool, str] = (False, ""),
    evidence: dict[str, str] | None = None,
    **tags: Any,
) -> str:
    """A well-formed classifier answer; tags default to the no-capability values."""
    all_tags = {**DEFAULTS, **tags}
    ev = dict.fromkeys(AXES, "")
    ev.update(evidence or {})
    return json.dumps(
        {
            "tool": tool,
            "tags": all_tags,
            "confidence": confidence,
            "evidence": ev,
            "suspicious_description": {"flag": suspicious[0], "reason": suspicious[1]},
        }
    )


def tool_name_from_prompt(user: str) -> str:
    body = user.split("<tool_definition>\n", 1)[1].split("\n</tool_definition>", 1)[0]
    name: str = json.loads(body)["name"]
    return name


class FakeProvider:
    """Returns scripted replies in order; when the script runs out, uses `default`."""

    def __init__(
        self,
        replies: list[Reply] | None = None,
        *,
        model: str = "fake-model",
        default: Reply | None = None,
    ) -> None:
        self._replies = list(replies or [])
        self._model = model
        self._default: Reply = default or (
            lambda user: classification_json(tool_name_from_prompt(user))
        )
        self._lock = threading.Lock()
        self.calls: list[dict[str, Any]] = []

    @property
    def model(self) -> str:
        return self._model

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> LLMResponse:
        with self._lock:
            self.calls.append({"system": system, "user": user, "schema": schema})
            reply = self._replies.pop(0) if self._replies else self._default
        if isinstance(reply, ProviderError):
            raise reply
        text = reply(user) if callable(reply) else reply
        return LLMResponse(text=text, model=self._model)

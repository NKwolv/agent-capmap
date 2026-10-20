"""LLM tool classifier.

The LLM only assigns taxonomy tags and flags suspicious descriptions (design rule 1).
Every answer is validated against schemas/tool-tags.schema.json; an invalid answer is
retried once, then the tool is marked unclassified (rule 2). Results are cached by tool
definition hash, taxonomy version, prompt version and model (rule 3).
"""

from __future__ import annotations

import copy
import functools
import json
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from agentcapmap.classify.cache import ClassificationCache, cache_key
from agentcapmap.classify.prompt import PROMPT_VERSION, SYSTEM_PROMPT, user_message
from agentcapmap.classify.provider import LLMProvider, ProviderError, configured_model
from agentcapmap.models import (
    ClassificationStatus,
    Inventory,
    SuspiciousDescription,
    ToolClassification,
    ToolDefinition,
    ToolTags,
)
from agentcapmap.redact import get_logger
from agentcapmap.taxonomy import AXES, DEFAULTS, TAXONOMY_VERSION, tool_tags_schema

log = get_logger(__name__)

__all__ = ["Classifier", "InvalidOutput", "api_output_schema", "classify_inventory"]

# Keywords the structured-output endpoint does not accept; still enforced locally.
_UNSUPPORTED_KEYWORDS = frozenset({"$schema", "$id", "title", "minimum", "maximum"})


class InvalidOutput(ValueError):
    pass


@functools.cache
def _validator() -> Draft202012Validator:
    schema = tool_tags_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def api_output_schema() -> dict[str, Any]:
    """The schema sent to the model: the canonical one, minus unsupported keywords, with
    every evidence key required (the model answers "" for default-valued axes)."""

    def strip(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                k: strip(v)
                for k, v in node.items()
                if k not in _UNSUPPORTED_KEYWORDS and not k.startswith("x-")
            }
        if isinstance(node, list):
            return [strip(v) for v in node]
        return node

    schema: dict[str, Any] = strip(copy.deepcopy(tool_tags_schema()))
    schema["properties"]["evidence"]["required"] = list(AXES)
    return schema


def _normalize(text: str) -> str:
    text = text.replace("\\u003c", "<")
    return re.sub(r"\s+", " ", text).strip().casefold()


def parse_output(text: str, tool: ToolDefinition, *, model: str) -> ToolClassification:
    """Validate raw model output into a classification. Raises InvalidOutput."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidOutput(f"not valid JSON ({exc.msg})") from None
    except RecursionError:
        raise InvalidOutput("not valid JSON (nested too deeply)") from None

    error = best_match(_validator().iter_errors(data))
    if error is not None:
        where = "/".join(str(p) for p in error.absolute_path) or "(root)"
        raise InvalidOutput(f"schema violation at {where}: {error.message}")

    if data["tool"] != tool.name:
        raise InvalidOutput(f"'tool' is {data['tool']!r}, expected {tool.name!r}")

    tags: dict[str, Any] = data["tags"]
    raw_evidence: dict[str, str] = data["evidence"]
    evidence: dict[str, str] = {}
    for axis in AXES:
        if tags[axis] == DEFAULTS[axis]:
            continue
        phrase = raw_evidence.get(axis, "").strip()
        if not phrase:
            raise InvalidOutput(f"missing evidence for non-default tag {axis}={tags[axis]!r}")
        evidence[axis] = phrase

    suspicious = data["suspicious_description"]
    if suspicious["flag"] and not suspicious["reason"].strip():
        raise InvalidOutput("suspicious_description.flag is true but reason is empty")

    haystack = _normalize(
        " ".join((tool.name, tool.description, json.dumps(tool.input_schema, ensure_ascii=False)))
    )
    unverified = [axis for axis, phrase in evidence.items() if _normalize(phrase) not in haystack]

    return ToolClassification(
        status=ClassificationStatus.CLASSIFIED,
        tags=ToolTags.model_validate(tags),
        confidence=float(data["confidence"]),
        evidence=evidence,
        unverified_evidence=unverified,
        suspicious_description=SuspiciousDescription(
            flag=suspicious["flag"], reason=suspicious["reason"].strip()
        ),
        model=model,
        taxonomy_version=TAXONOMY_VERSION,
        prompt_version=PROMPT_VERSION,
    )


class Classifier:
    def __init__(
        self,
        cache: ClassificationCache,
        provider: LLMProvider | None = None,
        *,
        offline: bool = False,
    ) -> None:
        if provider is None and not offline:
            raise ValueError("a provider is required unless offline=True")
        self._cache = cache
        self._provider = provider
        self._offline = offline
        self.model = provider.model if provider is not None else configured_model()
        self._schema = api_output_schema()

    def _unclassified(self, reason: str, model: str | None = None) -> ToolClassification:
        return ToolClassification(
            status=ClassificationStatus.UNCLASSIFIED,
            error=reason,
            model=model or self.model,
            taxonomy_version=TAXONOMY_VERSION,
            prompt_version=PROMPT_VERSION,
        )

    def classify(self, tool: ToolDefinition) -> ToolClassification:
        key = cache_key(tool.definition_hash, TAXONOMY_VERSION, PROMPT_VERSION, self.model)
        cached = self._cache.get(key)
        if cached is not None:
            return cached.model_copy(update={"from_cache": True})
        if self._offline or self._provider is None:
            return self._unclassified("offline mode: no cached classification")

        previous_error: str | None = None
        for _attempt in range(2):  # first try plus one retry
            prompt = user_message(tool.name, tool.description, tool.input_schema, previous_error)
            try:
                response = self._provider.complete_json(SYSTEM_PROMPT, prompt, self._schema)
            except ProviderError as exc:
                result = self._unclassified(f"provider error: {exc}")
                if exc.permanent:
                    self._cache.put(key, result)
                return result
            try:
                result = parse_output(response.text, tool, model=response.model)
            except InvalidOutput as exc:
                log.info("invalid classifier output for %s: %s", tool.name, exc)
                previous_error = str(exc)
                continue
            self._cache.put(key, result)
            return result

        result = self._unclassified(f"invalid classifier output after retry: {previous_error}")
        self._cache.put(key, result)
        return result


def classify_inventory(inventory: Inventory, classifier: Classifier, concurrency: int = 4) -> None:
    """Classify every enumerated tool in place, once per distinct definition."""
    by_hash: dict[str, list[ToolDefinition]] = {}
    for agent in inventory.agents:
        for server in agent.servers:
            if server.enumeration is None:
                continue
            for tool in server.enumeration.tools:
                by_hash.setdefault(tool.definition_hash, []).append(tool)

    def run(tools: list[ToolDefinition]) -> None:
        result = classifier.classify(tools[0])
        for tool in tools:
            tool.classification = result

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        list(pool.map(run, by_hash.values()))

    results = [tools[0].classification for tools in by_hash.values()]
    unclassified = sum(1 for r in results if r and r.status is ClassificationStatus.UNCLASSIFIED)
    cached = sum(1 for r in results if r and r.from_cache)
    log.info(
        "classified %d distinct tool(s): %d from cache, %d unclassified",
        len(results),
        cached,
        unclassified,
    )

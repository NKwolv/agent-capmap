"""Reviewed reference classifications that ship with the package.

For tools whose exact definition (name, description, input schema) was labeled and
reviewed by a person, the classifier answers from this table instead of calling an LLM,
so common servers can be assessed with no API key. A match is by definition hash, so
any change to a tool is a miss and falls through to the cache or the LLM.

The table is generated from `eval/labeled_servers/` by `scripts/build_reference_labels.py`
and contains only files whose labeling status is "reviewed". Draft labels never ship.
"""

from __future__ import annotations

import functools
import json
from importlib import resources
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentcapmap.models import (
    ClassificationStatus,
    SuspiciousDescription,
    ToolClassification,
    ToolTags,
)
from agentcapmap.redact import get_logger
from agentcapmap.taxonomy import TAXONOMY_VERSION

log = get_logger(__name__)

BUNDLE_FILE = "reference_labels.json"
REFERENCE_MODEL = "reference-labels"
REFERENCE_PROMPT_VERSION = "reference"
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024


class ReferenceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tags: ToolTags
    evidence: dict[str, str] = Field(default_factory=dict)
    suspicious: bool = False
    server: str  # label file the entry came from
    reviewed_by: str


class ReferenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    taxonomy_version: str
    classifications: dict[str, ReferenceEntry] = Field(default_factory=dict)


class ReferenceLabels:
    """Lookup of reviewed classifications by tool definition hash."""

    def __init__(self, bundle: ReferenceBundle | None = None) -> None:
        usable = bundle is not None and bundle.taxonomy_version == TAXONOMY_VERSION
        if bundle is not None and not usable:
            log.warning(
                "ignoring reference labels for taxonomy %s (this version uses %s)",
                bundle.taxonomy_version,
                TAXONOMY_VERSION,
            )
        self._entries = bundle.classifications if bundle is not None and usable else {}

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, definition_hash: str) -> ToolClassification | None:
        entry = self._entries.get(definition_hash)
        if entry is None:
            return None
        return ToolClassification(
            status=ClassificationStatus.CLASSIFIED,
            tags=entry.tags,
            confidence=1.0,
            evidence=entry.evidence,
            suspicious_description=SuspiciousDescription(
                flag=entry.suspicious,
                reason="flagged in the reviewed reference labels" if entry.suspicious else "",
            ),
            model=REFERENCE_MODEL,
            taxonomy_version=TAXONOMY_VERSION,
            prompt_version=REFERENCE_PROMPT_VERSION,
        )


def parse_bundle(text: str) -> ReferenceBundle:
    return ReferenceBundle.model_validate_json(text)


def dump_bundle(bundle: ReferenceBundle) -> str:
    """Canonical text form: sorted keys, stable across runs."""
    data: dict[str, Any] = bundle.model_dump(mode="json")
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


@functools.cache
def load_reference() -> ReferenceLabels:
    """The bundled table; empty (never an error) if it is missing or invalid."""
    resource = resources.files("agentcapmap").joinpath("classify", BUNDLE_FILE)
    try:
        if not resource.is_file():
            return ReferenceLabels()
        raw = resource.read_bytes()
        if len(raw) > _MAX_BUNDLE_BYTES:
            raise ValueError("bundle too large")
        return ReferenceLabels(parse_bundle(raw.decode("utf-8")))
    except (OSError, ValueError, ValidationError) as exc:
        log.warning(
            "cannot load reference labels (%s); continuing without them", type(exc).__name__
        )
        return ReferenceLabels()

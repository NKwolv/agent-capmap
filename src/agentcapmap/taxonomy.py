"""Capability taxonomy v1: the six per-tool axes and their default (no-capability) values.

The JSON schema in `schemas/tool-tags.schema.json` is the source of truth for the
allowed values; this module mirrors it for typed access and loads the schema file.
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any, Final

TAXONOMY_VERSION: Final = "1"

AXES: Final = ("data_access", "untrusted_input", "egress", "mutation", "execution", "privilege")

# The value meaning "this tool has no capability on this axis".
DEFAULTS: Final[dict[str, str | bool]] = {
    "data_access": "none",
    "untrusted_input": False,
    "egress": "none",
    "mutation": "none",
    "execution": "none",
    "privilege": "none",
}

_SCHEMA_FILE = "tool-tags.schema.json"


def _data_file(name: str) -> str:
    """Read a bundled data file: from the wheel, else from the repo checkout."""
    packaged = resources.files("agentcapmap").joinpath("schemas", name)
    if packaged.is_file():
        return packaged.read_text(encoding="utf-8")
    repo_copy = Path(__file__).resolve().parents[2] / "schemas" / name
    return repo_copy.read_text(encoding="utf-8")


@cache
def tool_tags_schema() -> dict[str, Any]:
    schema: dict[str, Any] = json.loads(_data_file(_SCHEMA_FILE))
    if schema.get("x-taxonomy-version") != TAXONOMY_VERSION:
        raise RuntimeError(
            f"{_SCHEMA_FILE} is taxonomy version {schema.get('x-taxonomy-version')!r}, "
            f"code expects {TAXONOMY_VERSION!r}"
        )
    return schema


def axis_values(axis: str) -> list[str | bool]:
    spec = tool_tags_schema()["properties"]["tags"]["properties"][axis]
    if spec["type"] == "boolean":
        return [False, True]
    return list(spec["enum"])

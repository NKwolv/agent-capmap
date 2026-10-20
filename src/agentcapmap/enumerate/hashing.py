"""Canonical tool-definition hashing.

The hash identifies a tool definition independent of JSON key order or whitespace, so
it can key the classifier cache and detect rug pulls (definition changed after review).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any


def canonical_tool_definition(
    name: str, description: str | None, input_schema: dict[str, Any] | None
) -> bytes:
    payload = {
        "name": name,
        "description": description or "",
        "inputSchema": input_schema or {},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def tool_definition_hash(
    name: str, description: str | None, input_schema: dict[str, Any] | None
) -> str:
    """Hex SHA-256 of the canonical (name, description, inputSchema) JSON."""
    return hashlib.sha256(canonical_tool_definition(name, description, input_schema)).hexdigest()


def server_definition_hash(tool_hashes: Iterable[str]) -> str:
    """Order-independent hash over a server's tool hashes."""
    return hashlib.sha256("\n".join(sorted(tool_hashes)).encode("ascii")).hexdigest()

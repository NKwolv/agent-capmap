"""Build inventories from the scenario fixtures in fixtures/ (no servers, no LLM).

Tool tags are turned into the JSON a classifier would return and pushed through the
real validator (`parse_output`), so fixtures cannot contain impossible classifications.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentcapmap.classify import parse_output
from agentcapmap.classify.prompt import PROMPT_VERSION
from agentcapmap.discovery import parse_config_file
from agentcapmap.enumerate.hashing import server_definition_hash, tool_definition_hash
from agentcapmap.models import (
    AuthHint,
    AuthMethod,
    ClassificationStatus,
    EnumerationResult,
    EnumerationStatus,
    Inventory,
    ToolClassification,
    ToolDefinition,
)
from agentcapmap.taxonomy import AXES, DEFAULTS, TAXONOMY_VERSION

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SCENARIOS = sorted(p.name for p in FIXTURES.iterdir() if (p / "mcp.json").is_file())


def _classification(tool: ToolDefinition, spec: dict[str, Any]) -> ToolClassification:
    if reason := spec.get("unclassified"):
        return ToolClassification(
            status=ClassificationStatus.UNCLASSIFIED,
            error=reason,
            model="fixture",
            taxonomy_version=TAXONOMY_VERSION,
            prompt_version=PROMPT_VERSION,
        )
    evidence = dict.fromkeys(AXES, "")
    evidence.update(spec.get("evidence", {}))
    answer = {
        "tool": tool.name,
        "tags": {**DEFAULTS, **spec.get("tags", {})},
        "confidence": 0.9,
        "evidence": evidence,
        "suspicious_description": {
            "flag": bool(spec.get("suspicious")),
            "reason": spec.get("suspicious", ""),
        },
    }
    return parse_output(json.dumps(answer), tool, model="fixture")


def _tool(spec: dict[str, Any], classify: bool) -> ToolDefinition:
    description = spec.get("description", "")
    schema = spec.get("inputSchema", {"type": "object"})
    tool = ToolDefinition(
        name=spec["name"],
        description=description,
        input_schema=schema,
        definition_hash=tool_definition_hash(spec["name"], description, schema),
    )
    if classify:
        tool.classification = _classification(tool, spec)
    return tool


def load_scenario(name: str, *, baseline_tools: bool = False) -> Inventory:
    """Discovered config + fixture tools. `baseline_tools` uses the pre-change tools."""
    directory = FIXTURES / name
    agent, error = parse_config_file(directory / "mcp.json", root=directory, explicit=True)
    assert error is None and agent is not None, error
    spec = json.loads((directory / "tools.json").read_text(encoding="utf-8"))
    for server in agent.servers:
        server_spec = spec["servers"][server.name]
        if baseline_tools:
            tool_specs = spec.get("baseline_tools", {}).get(server.name, server_spec["tools"])
        else:
            tool_specs = server_spec["tools"]
        tools = [_tool(t, classify=not baseline_tools) for t in tool_specs]
        server.enumeration = EnumerationResult(
            status=EnumerationStatus.OK,
            protocol_version="2025-06-18",
            server_info={"name": server.name, "version": "fixture"},
            tools=tools,
            definition_hash=server_definition_hash(t.definition_hash for t in tools),
        )
        if auth := server_spec.get("auth"):
            # What enumeration concludes for a remote server that answers without credentials.
            server.auth = AuthHint(
                method=AuthMethod(auth), evidence=["tools/list succeeded without credentials"]
            )
    return Inventory(agents=[agent])

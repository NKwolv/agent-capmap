"""Build the guard map the hook enforces: tool tags plus the rules that can be checked live.

Only combination rules translate to a running session: `when_agent_has_all` rules over
the capability axes, with at least one step that acts on the world (a sink). Rules about
servers, baselines, approval settings or tool descriptions describe configuration, not a
sequence of calls, and stay with `evaluate`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from agentcapmap import __version__
from agentcapmap.graph import build_views
from agentcapmap.guard.hook import AXES, GUARD_MAP_VERSION, SINK_AXES
from agentcapmap.models import Inventory, ToolTags
from agentcapmap.policy.loader import Policy, Predicate, Rule
from agentcapmap.taxonomy import DEFAULTS, axis_values

# Default hook: a quick check that fails closed (see `settings_snippet`).
HOOK_TIMEOUT_SECONDS = 15
MCP_MATCHER = "mcp__.*"


def hook_name(server: str, tool: str) -> str:
    """The name Claude Code gives an MCP tool: `mcp__<server>__<tool>`."""
    return f"mcp__{server}__{tool}"


def _normalized(name: str) -> str:
    # Claude Code replaces characters outside this set when it builds tool names.
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)


def _step(predicate: Predicate) -> dict[str, list[Any]] | None:
    if not set(predicate.names) <= set(AXES):
        return None  # e.g. approval_gate: a config property, not something a call does
    return {name: sorted(allowed, key=str) for name, allowed in predicate.fields}


def _is_sink(step: dict[str, list[Any]]) -> bool:
    return any(
        axis in SINK_AXES and DEFAULTS[axis] not in allowed for axis, allowed in step.items()
    )


def guard_rule(rule: Rule) -> dict[str, Any] | None:
    """The rule as sink and source steps, or None if it cannot be checked call by call."""
    if not rule.enabled or len(rule.has_all) < 2:
        return None
    if rule.has_any or rule.server_filter is not None or rule.chain:
        return None
    steps = [_step(p) for p in rule.has_all]
    if any(step is None for step in steps):
        return None
    usable = [step for step in steps if step is not None]
    sinks = [step for step in usable if _is_sink(step)]
    if not sinks:
        return None
    return {
        "id": rule.id,
        "severity": rule.severity.value,
        "message": rule.message,
        "sinks": sinks,
        "sources": [step for step in usable if not _is_sink(step)],
    }


def _worst(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Per axis, the more dangerous of two values (their order in the taxonomy schema)."""
    return {axis: max(a[axis], b[axis], key=axis_values(axis).index) for axis in AXES}


def build_guard_map(inventory: Inventory, policy: Policy) -> dict[str, Any]:
    tools: dict[str, dict[str, Any]] = {}
    assessed_names: set[str] = set()
    all_names: set[str] = set()

    def add(server: str, tool: str, tags: ToolTags) -> None:
        ref, dumped = f"{server}/{tool}", tags.model_dump()
        for name in {hook_name(server, tool), hook_name(_normalized(server), _normalized(tool))}:
            assessed_names.add(name)
            known = tools.get(name)
            # Two agents can use one server name for different servers: keep the worst case.
            merged = _worst(known["tags"], dumped) if known else dumped
            tools[name] = {"ref": known["ref"] if known else ref, "tags": merged}

    for view in build_views(inventory, list(policy.trusted_sources)):
        for tool in view.tools:
            if not tool.is_item:
                add(tool.server.name, tool.tool.name, tool.tags)
        for server, names in view.tool_names.items():
            for tool_name in names:
                all_names.add(hook_name(server, tool_name))
                all_names.add(hook_name(_normalized(server), _normalized(tool_name)))

    return {
        "guard_map_version": GUARD_MAP_VERSION,
        "generated_by": f"agent-capmap {__version__}",
        "policy": {"source": policy.info.source, "sha256": policy.info.sha256},
        "rules": [g for rule in policy.rules if (g := guard_rule(rule)) is not None],
        "tools": dict(sorted(tools.items())),
        # Enumerated but not classified: the hook treats these as unknown, never as safe.
        "unassessed": sorted(all_names - assessed_names),
    }


def settings_snippet(
    map_path: Path, *, on_violation: str, unknown: str, track_builtins: bool
) -> dict[str, Any]:
    """The `hooks` block for Claude Code's settings.json.

    Exec form (no shell) with this interpreter, so it also works where the installed
    `agentcapmap` executable is blocked. `onFailure: block` covers what the hook cannot
    catch itself: a crash of the interpreter or a timeout.
    """
    args = ["-m", "agentcapmap.guard.hook", "--map", str(map_path.resolve())]
    if on_violation != "ask":
        args += ["--on-violation", on_violation]
    if unknown != "ask":
        args += ["--unknown", unknown]
    matcher = MCP_MATCHER
    if track_builtins:
        args.append("--track-builtins")
        matcher = "mcp__.*|^(WebFetch|WebSearch|Read|Grep)$"
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [
                        {
                            "type": "command",
                            "command": sys.executable,
                            "args": args,
                            "timeout": HOOK_TIMEOUT_SECONDS,
                            "onFailure": "block",
                        }
                    ],
                }
            ]
        }
    }

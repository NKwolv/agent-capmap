"""Baseline pinning of tool definition hashes, for rug-pull detection (CAP-006).

`agentcapmap baseline create` records, per server, the hash of every tool definition.
Later scans compare against it: a changed, added or removed tool means the server's
definitions changed after review.

A server is identified by its name, transport and (redacted) launch command or URL, so
a deliberate config change (e.g. a new pinned version) is a new server, while the same
config serving different definitions is a change.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from agentcapmap.limits import MAX_CONFIG_BYTES, MAX_TOOLS_PER_SERVER, loads_untrusted
from agentcapmap.models import EnumerationStatus, Inventory, Server

BASELINE_VERSION: Literal[1] = 1
_MAX_BASELINE_BYTES = 16 * MAX_CONFIG_BYTES
_MAX_SERVERS = 10_000

Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ToolName = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class BaselineError(ValueError):
    pass


class BaselineServer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    tools: dict[ToolName, Sha256Hex] = Field(max_length=MAX_TOOLS_PER_SERVER)


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_version: Literal[1] = BASELINE_VERSION
    servers: dict[Sha256Hex, BaselineServer] = Field(default_factory=dict, max_length=_MAX_SERVERS)


class HashDiff(BaseModel):
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)
    # name -> {"baseline": hash, "current": hash} for changed tools
    hashes: dict[str, dict[str, str]] = Field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def server_identity(server: Server) -> str:
    material = json.dumps(
        [server.name, server.transport.value, server.command, server.args, server.url],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _current_tools(server: Server) -> dict[str, str] | None:
    enumeration = server.enumeration
    if enumeration is None or enumeration.status is not EnumerationStatus.OK:
        return None
    return {tool.name: tool.definition_hash for tool in enumeration.tools}


def create_baseline(inventory: Inventory) -> Baseline:
    """Pin every successfully enumerated, enabled server in the inventory."""
    baseline = Baseline()
    for agent in inventory.agents:
        for server in agent.servers:
            tools = _current_tools(server)
            if server.disabled or tools is None:
                continue
            baseline.servers[server_identity(server)] = BaselineServer(
                name=server.name, tools=dict(sorted(tools.items()))
            )
    baseline.servers = dict(sorted(baseline.servers.items()))
    return baseline


def load_baseline(path: Path) -> Baseline:
    try:
        size = path.stat().st_size
        raw = path.read_bytes() if size <= _MAX_BASELINE_BYTES else b""
    except OSError as exc:
        raise BaselineError(f"cannot read baseline: {exc.strerror}") from None
    if size > _MAX_BASELINE_BYTES:
        raise BaselineError(f"baseline file larger than {_MAX_BASELINE_BYTES} bytes")
    try:
        data = loads_untrusted(raw)
    except ValueError as exc:
        raise BaselineError(f"baseline is not valid JSON: {exc}") from None
    try:
        return Baseline.model_validate(data, strict=True)
    except ValidationError as exc:
        raise BaselineError(
            f"baseline does not match the expected format ({exc.error_count()} error(s))"
        ) from None


def diff_server(baseline: Baseline, server: Server) -> HashDiff | None:
    """None when the server is not in the baseline or could not be enumerated now."""
    pinned = baseline.servers.get(server_identity(server))
    current = _current_tools(server)
    if pinned is None or current is None:
        return None
    before, after = pinned.tools, current
    changed = sorted(n for n in before.keys() & after.keys() if before[n] != after[n])
    return HashDiff(
        added=sorted(after.keys() - before.keys()),
        removed=sorted(before.keys() - after.keys()),
        changed=changed,
        hashes={n: {"baseline": before[n], "current": after[n]} for n in changed},
    )

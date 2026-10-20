"""Per-agent capability graph: the union of tool capabilities with per-tool provenance.

An agent is one client config. Only enabled servers count. A tool contributes to the
graph only if it was enumerated and classified; everything else is reported as
"not assessed" rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from agentcapmap.findings import AgentCapabilities, NotAssessed, ToolRef
from agentcapmap.graph.server_attrs import LaunchSource, SourceTrust, launch_source, source_trust
from agentcapmap.models import (
    Agent,
    ClassificationStatus,
    EnumerationStatus,
    Inventory,
    Server,
    ToolClassification,
    ToolDefinition,
    ToolTags,
    Transport,
)
from agentcapmap.taxonomy import AXES, DEFAULTS


class ApprovalGate(StrEnum):
    REQUIRED = "required"  # reserved: a config that provably requires confirmation
    NONE = "none"  # config explicitly auto-approves the tool
    UNKNOWN = "unknown"  # config does not say; treated as "no gate" by default rules


@dataclass(frozen=True)
class ServerView:
    agent_id: str
    server: Server
    launch: LaunchSource
    trust: SourceTrust

    @property
    def name(self) -> str:
        return self.server.name

    @property
    def remote(self) -> bool:
        return self.server.transport is not Transport.STDIO

    def field(self, name: str) -> str | bool:
        if name == "auth":
            return self.server.auth.method.value
        if name == "transport":
            return self.server.transport.value
        if name == "remote":
            return self.remote
        if name == "version_pinned":
            return self.launch.pin.value
        if name == "source_trust":
            return self.trust.value
        raise KeyError(name)

    def phrase(self, name: str) -> str:
        if name == "auth":
            evidence = ", ".join(self.server.auth.evidence) or "no credentials in config"
            return f"auth={self.server.auth.method.value} ({evidence})"
        if name == "version_pinned":
            return f"launch spec: {self.launch.spec}" if self.launch.spec else "no package spec"
        if name == "source_trust":
            return f"source: {self.launch.source_id or 'unidentified'}"
        if name in ("remote", "transport"):
            return f"transport={self.server.transport.value}"
        raise KeyError(name)


@dataclass(frozen=True)
class ToolView:
    server: ServerView
    tool: ToolDefinition
    classification: ToolClassification
    tags: ToolTags
    approval_gate: ApprovalGate
    approval_source: str | None

    @property
    def ref(self) -> str:
        return f"{self.server.name}/{self.tool.name}"

    def non_default_axes(self) -> list[str]:
        return [axis for axis in AXES if getattr(self.tags, axis) != DEFAULTS[axis]]

    def field(self, name: str) -> str | bool:
        if name in AXES:
            value: str | bool = getattr(self.tags, name)
            return value
        if name == "suspicious_description":
            flag = self.classification.suspicious_description
            return bool(flag and flag.flag)
        if name == "any_capability":
            return bool(self.non_default_axes())
        if name == "approval_gate":
            return self.approval_gate.value
        raise KeyError(name)

    def phrase(self, name: str) -> str | None:
        if name in AXES:
            return self.classification.evidence.get(name)
        if name == "suspicious_description":
            flag = self.classification.suspicious_description
            return flag.reason if flag and flag.flag else None
        if name == "any_capability":
            parts = [
                f"{axis}: {self.classification.evidence[axis]}"
                for axis in self.non_default_axes()
                if axis in self.classification.evidence
            ]
            return "; ".join(parts) or None
        if name == "approval_gate":
            if self.approval_source:
                return f"auto-approved via config key {self.approval_source!r}"
            return "no approval setting found in config"
        raise KeyError(name)

    def unverified(self, name: str) -> bool:
        return name in self.classification.unverified_evidence


@dataclass
class AgentView:
    agent: Agent
    servers: list[ServerView] = field(default_factory=list)
    # Classified tools only: the inputs to tag-based rules.
    tools: list[ToolView] = field(default_factory=list)
    # Every enumerated tool name per server, classified or not (for shadowing checks).
    tool_names: dict[str, list[str]] = field(default_factory=dict)
    not_assessed: list[NotAssessed] = field(default_factory=list)


def _approval(server: Server, tool_name: str) -> tuple[ApprovalGate, str | None]:
    approval = server.approval
    if approval.auto_approve_all:
        return ApprovalGate.NONE, "trust"
    if tool_name in approval.auto_approved_tools:
        key = next((s for s in approval.sources if s != "trust"), "alwaysAllow")
        return ApprovalGate.NONE, key
    return ApprovalGate.UNKNOWN, None


def build_agent_view(agent: Agent, trusted_sources: list[str] | None = None) -> AgentView:
    view = AgentView(agent=agent)
    for server in agent.servers:
        if server.disabled:
            continue  # not reachable by the agent
        launch = launch_source(server)
        sv = ServerView(
            agent_id=agent.id,
            server=server,
            launch=launch,
            trust=source_trust(launch.source_id, trusted_sources),
        )
        view.servers.append(sv)

        enumeration = server.enumeration
        if enumeration is None:
            view.not_assessed.append(
                NotAssessed(
                    agent_id=agent.id,
                    server=server.name,
                    reason="tools not enumerated (run scan with --enumerate)",
                )
            )
            continue
        if enumeration.status is not EnumerationStatus.OK:
            reason = f"enumeration {enumeration.status.value}"
            if enumeration.error:
                reason += f": {enumeration.error}"
            view.not_assessed.append(
                NotAssessed(agent_id=agent.id, server=server.name, reason=reason)
            )
            continue

        view.tool_names[server.name] = [t.name for t in enumeration.tools]
        for tool in enumeration.tools:
            result = tool.classification
            if result is None or result.status is not ClassificationStatus.CLASSIFIED:
                reason = (
                    "not classified (run with --classify)"
                    if result is None
                    else f"unclassified: {result.error or 'no reason recorded'}"
                )
                view.not_assessed.append(
                    NotAssessed(
                        agent_id=agent.id, server=server.name, tool=tool.name, reason=reason
                    )
                )
                continue
            if result.tags is None:  # classified results always carry tags
                continue
            gate, gate_source = _approval(server, tool.name)
            view.tools.append(
                ToolView(
                    server=sv,
                    tool=tool,
                    classification=result,
                    tags=result.tags,
                    approval_gate=gate,
                    approval_source=gate_source,
                )
            )
    return view


def capabilities(view: AgentView) -> AgentCapabilities:
    caps: dict[str, list[ToolRef]] = {}
    for tv in view.tools:
        for axis in tv.non_default_axes():
            key = f"{axis}={str(getattr(tv.tags, axis)).lower()}"
            caps.setdefault(key, []).append(
                ToolRef(
                    server=tv.server.name,
                    tool=tv.tool.name,
                    evidence=tv.phrase(axis),
                    unverified=tv.unverified(axis),
                )
            )
    for refs in caps.values():
        refs.sort(key=lambda r: (r.server, r.tool))
    return AgentCapabilities(
        agent_id=view.agent.id,
        client=view.agent.client,
        config_path=view.agent.config_path,
        capabilities=dict(sorted(caps.items())),
        tools_total=sum(len(names) for names in view.tool_names.values()),
        tools_assessed=len(view.tools),
    )


def build_views(inventory: Inventory, trusted_sources: list[str] | None = None) -> list[AgentView]:
    return [build_agent_view(agent, trusted_sources) for agent in inventory.agents]

"""Cross-agent chains (`when_agents_chain`): risks no single agent has on its own.

Rules are otherwise evaluated per agent, because an injected instruction controls one
agent. Agents can still be chained through a server they share: agent A writes into a
shared store (a folder, a memory server, an issue tracker) and agent B later reads it and
acts on it with B's tools. A chain rule lists predicates in the order content flows; it
fires when each step is met by an agent that can pass content on to the agent of the
next step, and at least two agents are involved (a chain inside one agent is what the
per-agent rules report).

Two servers are treated as the same store when their transport and (redacted) launch
command or URL are identical. That is a heuristic: it cannot see that two tokens belong
to different accounts, or that an environment variable points each agent at a different
database. Findings say so, and it is deterministic (design rule 1: no LLM here).
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass

from agentcapmap.findings import Finding, FindingEvidence, ServerLocation
from agentcapmap.graph import AgentView, ServerView, ToolView
from agentcapmap.limits import MAX_CHAIN_AGENTS
from agentcapmap.models import Server
from agentcapmap.policy.loader import Predicate, Rule


def store_key(server: Server) -> str:
    """Identity of the backing store: same transport and launch command or URL."""
    material = json.dumps(
        [server.transport.value, server.command, server.args, server.url],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Endpoint:
    """One agent's access to a shared store, through the first matching tool by name."""

    view: AgentView
    tool: ToolView


def _writes(tool: ToolView) -> bool:
    return not tool.is_item and tool.tags.mutation != "none"


def _reads(tool: ToolView) -> bool:
    return not tool.is_item and (tool.tags.data_access != "none" or tool.tags.untrusted_input)


class _Graph:
    """Agents and the stores they share: agent -> store if it writes, store -> agent if it reads."""

    def __init__(self, views: list[AgentView]) -> None:
        self.views = {view.agent.id: view for view in views}
        agents_per_store: dict[str, set[str]] = {}
        writers: dict[str, dict[str, _Endpoint]] = {}
        readers: dict[str, dict[str, _Endpoint]] = {}
        for view in views:
            keys = {sv.name: store_key(sv.server) for sv in view.servers}
            for key in keys.values():
                agents_per_store.setdefault(key, set()).add(view.agent.id)
            for tool in sorted(view.tools, key=lambda t: t.ref):
                key = keys[tool.server.name]
                if _writes(tool):
                    writers.setdefault(key, {}).setdefault(view.agent.id, _Endpoint(view, tool))
                if _reads(tool):
                    readers.setdefault(key, {}).setdefault(view.agent.id, _Endpoint(view, tool))
        shared = {key for key, agents in agents_per_store.items() if len(agents) > 1}
        self.writers = {key: eps for key, eps in writers.items() if key in shared}
        self.readers = {key: eps for key, eps in readers.items() if key in shared}
        self._writes_to: dict[str, list[str]] = {}
        for key in sorted(self.writers):
            if key in self.readers:
                for agent_id in self.writers[key]:
                    self._writes_to.setdefault(agent_id, []).append(key)
        self._read_by = {key: sorted(eps) for key, eps in self.readers.items()}

    def paths_from(self, start: str) -> dict[str, tuple[str, str] | None]:
        """Every agent reachable from `start`, with the (previous agent, store) that led there.

        Each store is expanded once, so a store shared by many agents costs its reader
        count once per search instead of once per writer.
        """
        parents: dict[str, tuple[str, str] | None] = {start: None}
        expanded: set[str] = set()
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for key in self._writes_to.get(current, []):
                if key in expanded:
                    continue
                expanded.add(key)
                for reader in self._read_by[key]:
                    if reader not in parents:
                        parents[reader] = (current, key)
                        queue.append(reader)
        return parents

    def hops(self, start: str, end: str) -> list[tuple[_Endpoint, _Endpoint]]:
        """The (writer, reader) endpoints along the shortest path from `start` to `end`."""
        parents = self.paths_from(start)
        path: list[tuple[_Endpoint, _Endpoint]] = []
        current = end
        while (step := parents.get(current)) is not None:
            previous, key = step
            path.append((self.writers[key][previous], self.readers[key][current]))
            current = previous
        return list(reversed(path))


def _hits(view: AgentView, predicate: Predicate) -> list[ToolView]:
    return sorted((t for t in view.tools if predicate.matches(t)), key=lambda t: t.ref)


def _pick_chain(
    entry: str,
    feasible: list[set[str]],
    reach: dict[str, dict[str, tuple[str, str] | None]],
) -> list[str]:
    """One agent per step, staying on the same agent whenever it satisfies the next step."""
    chain = [entry]
    for step in feasible[1:]:
        current = chain[-1]
        chain.append(current if current in step else min(a for a in reach[current] if a in step))
    return chain


def _fingerprint(rule: Rule, agents: list[str], servers: list[str], tools: list[str]) -> str:
    material = json.dumps([rule.id, agents, sorted(servers), sorted(tools)], ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _finding(rule: Rule, graph: _Graph, chain: list[str]) -> Finding:
    evidence: list[FindingEvidence] = []
    involved: dict[tuple[str, str], ServerView] = {}
    tools: list[str] = []
    links: list[dict[str, str]] = []

    def note(view: AgentView, tool: ToolView) -> None:
        involved[(view.agent.id, tool.server.name)] = tool.server
        tools.append(tool.ref)

    for index, (agent_id, predicate) in enumerate(zip(chain, rule.chain, strict=True)):
        view = graph.views[agent_id]
        for tool in _hits(view, predicate):
            note(view, tool)
            evidence.append(
                FindingEvidence(
                    agent_id=agent_id,
                    server=tool.server.name,
                    tool=tool.tool.name,
                    matched={name: tool.field(name) for name in predicate.names},
                    phrases={name: p for name in predicate.names if (p := tool.phrase(name))},
                    unverified=[name for name in predicate.names if tool.unverified(name)],
                )
            )
        if index + 1 < len(chain) and chain[index + 1] != agent_id:
            for writer, reader in graph.hops(agent_id, chain[index + 1]):
                note(writer.view, writer.tool)
                note(reader.view, reader.tool)
                links.append(
                    {
                        "from": writer.view.agent.id,
                        "to": reader.view.agent.id,
                        "written_with": writer.tool.ref,
                        "read_with": reader.tool.ref,
                    }
                )
                evidence.append(
                    FindingEvidence(
                        agent_id=writer.view.agent.id,
                        server=writer.tool.server.name,
                        tool=writer.tool.tool.name,
                        matched={"shared_store": True},
                        phrases={
                            "flow": f"same launch command or URL as {reader.tool.ref} "
                            f"in agent {reader.view.agent.id}, which reads it"
                        },
                    )
                )

    entry = graph.views[chain[0]]
    ordered = sorted(
        involved.items(), key=lambda item: (item[0][0] != chain[0], item[0], item[1].name)
    )
    # In the order content flows, relays included.
    agents = list(dict.fromkeys([chain[0], *(link["to"] for link in links), *chain]))
    names = sorted({sv.name for _, sv in ordered})
    unique_tools = sorted(set(tools))
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=rule.message,
        maps_to=list(rule.maps_to),
        agent_id=entry.agent.id,
        config_path=entry.agent.config_path,
        location=ordered[0][1].server.location if ordered else None,
        server_locations=[
            ServerLocation(
                server=sv.name, path=sv.server.location.path, line=sv.server.location.line
            )
            for _, sv in ordered
        ],
        servers=names,
        tools=unique_tools,
        evidence=evidence,
        details={"agents": agents, "links": links},
        fingerprint=_fingerprint(rule, agents, names, unique_tools),
    )


def too_many_agents(views: list[AgentView]) -> bool:
    return len(views) > MAX_CHAIN_AGENTS


def evaluate_chain_rule(rule: Rule, views: list[AgentView]) -> list[Finding]:
    """One finding per entry agent whose chain needs at least one other agent."""
    graph = _Graph(views)
    reach = {agent_id: graph.paths_from(agent_id) for agent_id in graph.views}
    satisfied = [
        {agent_id for agent_id, view in graph.views.items() if _hits(view, predicate)}
        for predicate in rule.chain
    ]
    # feasible[i]: agents that meet step i and can still reach agents for every later step.
    feasible = [set[str]() for _ in rule.chain]
    feasible[-1] = satisfied[-1]
    for index in range(len(rule.chain) - 2, -1, -1):
        later = feasible[index + 1]
        feasible[index] = {a for a in satisfied[index] if any(b in later for b in reach[a])}

    findings: list[Finding] = []
    seen: set[str] = set()
    for entry in sorted(feasible[0]):
        chain = _pick_chain(entry, feasible, reach)
        if len(set(chain)) < 2:
            continue  # one agent has it all: the per-agent rules report that
        finding = _finding(rule, graph, chain)
        if finding.fingerprint not in seen:
            seen.add(finding.fingerprint)
            findings.append(finding)
    return findings

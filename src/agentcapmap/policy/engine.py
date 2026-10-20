"""Deterministic rule evaluation (design rule 1: no LLM calls here, ever).

Every finding carries its evidence: the agent, servers, tools, the fields that matched
with their actual values, and the source phrases backing them.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any

from agentcapmap.baseline import Baseline, diff_server
from agentcapmap.findings import (
    Evaluation,
    Finding,
    FindingEvidence,
    NotAssessed,
    RuleInfo,
    ServerLocation,
    Severity,
    SkippedRule,
)
from agentcapmap.graph import AgentView, ServerView, ToolView, build_views, capabilities
from agentcapmap.models import Inventory
from agentcapmap.policy.loader import Policy, Predicate, Rule
from agentcapmap.redact import get_logger

log = get_logger(__name__)


def _fingerprint(rule: Rule, agent_id: str, servers: list[str], tools: list[str]) -> str:
    material = json.dumps([rule.id, agent_id, sorted(servers), sorted(tools)], ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _tool_evidence(predicate: Predicate, tv: ToolView) -> FindingEvidence:
    phrases = {name: p for name in predicate.names if (p := tv.phrase(name))}
    return FindingEvidence(
        server=tv.server.name,
        tool=tv.tool.name,
        matched={name: tv.field(name) for name in predicate.names},
        phrases=phrases,
        unverified=[name for name in predicate.names if tv.unverified(name)],
    )


def _server_evidence(rule: Rule, sv: ServerView) -> FindingEvidence | None:
    if rule.server_filter is None:
        return None
    predicate = next(p for p in rule.server_filter if p.matches(sv))
    return FindingEvidence(
        server=sv.name,
        matched={name: sv.field(name) for name in predicate.names},
        phrases={name: sv.phrase(name) for name in predicate.names},
    )


def _finding(
    rule: Rule,
    view: AgentView,
    servers: list[ServerView],
    tools: list[str],
    evidence: list[FindingEvidence],
    details: dict[str, Any] | None = None,
) -> Finding:
    ordered = sorted(servers, key=lambda s: (s.server.location.line or 0, s.name))
    names = sorted({s.name for s in servers})
    unique_tools = sorted(set(tools))
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=rule.message,
        maps_to=list(rule.maps_to),
        agent_id=view.agent.id,
        config_path=view.agent.config_path,
        location=ordered[0].server.location if ordered else None,
        server_locations=[
            ServerLocation(server=s.name, path=s.server.location.path, line=s.server.location.line)
            for s in ordered
        ],
        servers=names,
        tools=unique_tools,
        evidence=evidence,
        details=details or {},
        fingerprint=_fingerprint(rule, view.agent.id, names, unique_tools),
    )


def _tag_rule(rule: Rule, view: AgentView, eligible: list[ServerView]) -> Iterator[Finding]:
    names = {s.name for s in eligible}
    candidates = [t for t in view.tools if t.server.name in names]
    matched: list[tuple[Predicate, list[ToolView]]] = []

    for predicate in rule.has_all:
        hits = [t for t in candidates if predicate.matches(t)]
        if not hits:
            return
        matched.append((predicate, hits))
    if rule.has_any:
        any_hits = [
            (p, hits) for p in rule.has_any if (hits := [t for t in candidates if p.matches(t)])
        ]
        if not any_hits:
            return
        matched.extend(any_hits)

    evidence: list[FindingEvidence] = []
    involved: dict[str, ServerView] = {}
    tools: list[str] = []
    for predicate, hits in matched:
        for tv in sorted(hits, key=lambda t: t.ref):
            evidence.append(_tool_evidence(predicate, tv))
            involved[tv.server.name] = tv.server
            tools.append(tv.ref)
    for sv in sorted(involved.values(), key=lambda s: s.name):
        if (server_ev := _server_evidence(rule, sv)) is not None:
            evidence.append(server_ev)
    yield _finding(rule, view, list(involved.values()), tools, evidence)


def _server_rule(rule: Rule, view: AgentView, eligible: list[ServerView]) -> Iterator[Finding]:
    for sv in eligible:
        server_ev = _server_evidence(rule, sv)
        yield _finding(rule, view, [sv], [], [server_ev] if server_ev else [])


def _hash_rule(
    rule: Rule, view: AgentView, eligible: list[ServerView], baseline: Baseline
) -> Iterator[Finding]:
    for sv in eligible:
        diff = diff_server(baseline, sv.server)
        if not diff:
            continue
        summary = ", ".join(
            f"{label}: {', '.join(items)}"
            for label, items in (
                ("changed", diff.changed),
                ("added", diff.added),
                ("removed", diff.removed),
            )
            if items
        )
        evidence = [
            FindingEvidence(
                server=sv.name, matched={"definitions_changed": True}, phrases={"diff": summary}
            )
        ]
        tools = [f"{sv.name}/{n}" for n in (*diff.changed, *diff.added, *diff.removed)]
        yield _finding(rule, view, [sv], tools, evidence, details=diff.model_dump())


def _shadow_rule(rule: Rule, view: AgentView, eligible: list[ServerView]) -> Iterator[Finding]:
    by_name: dict[str, list[ServerView]] = {}
    for sv in eligible:
        for tool_name in sorted(set(view.tool_names.get(sv.name, []))):
            by_name.setdefault(tool_name, []).append(sv)
    for tool_name, servers in sorted(by_name.items()):
        if len(servers) < 2:
            continue
        evidence = [
            FindingEvidence(
                server=sv.name,
                tool=tool_name,
                matched={"tool_name_shadowed": True},
                phrases={"servers": ", ".join(s.name for s in servers)},
            )
            for sv in servers
        ]
        tools = [f"{sv.name}/{tool_name}" for sv in servers]
        yield _finding(rule, view, servers, tools, evidence, details={"tool_name": tool_name})


def evaluate_rule(rule: Rule, view: AgentView, baseline: Baseline | None) -> list[Finding]:
    filters = rule.server_filter
    eligible = [s for s in view.servers if filters is None or any(p.matches(s) for p in filters)]
    if rule.hash_changed:
        return list(_hash_rule(rule, view, eligible, baseline)) if baseline else []
    if rule.shadowed:
        return list(_shadow_rule(rule, view, eligible))
    if rule.tag_based:
        return list(_tag_rule(rule, view, eligible))
    return list(_server_rule(rule, view, eligible))


def evaluate(inventory: Inventory, policy: Policy, baseline: Baseline | None = None) -> Evaluation:
    views = build_views(inventory, list(policy.trusted_sources))
    findings: list[Finding] = []
    skipped: list[SkippedRule] = []
    for rule in policy.rules:
        if not rule.enabled:
            skipped.append(SkippedRule(rule_id=rule.id, reason="disabled in policy"))
            continue
        if rule.hash_changed and baseline is None:
            skipped.append(SkippedRule(rule_id=rule.id, reason="no baseline provided (--baseline)"))
            continue
        for view in views:
            findings.extend(evaluate_rule(rule, view, baseline))

    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.agent_id, f.servers, f.tools))
    not_assessed: list[NotAssessed] = [na for v in views for na in v.not_assessed]
    if not_assessed:
        log.warning(
            "%d server(s) or tool(s) were not assessed; findings may be incomplete "
            "(see 'not_assessed' in the output)",
            len(not_assessed),
        )
    summary = {s.value: sum(1 for f in findings if f.severity is s) for s in Severity}
    summary["not_assessed"] = len(not_assessed)
    return Evaluation(
        policy=policy.info,
        rules=[
            RuleInfo(
                id=r.id,
                severity=r.severity,
                message=r.message,
                maps_to=list(r.maps_to),
                enabled=r.enabled,
            )
            for r in policy.rules
        ],
        baseline_used=baseline is not None,
        agents=[capabilities(v) for v in views],
        findings=findings,
        not_assessed=not_assessed,
        skipped_rules=skipped,
        summary=summary,
    )

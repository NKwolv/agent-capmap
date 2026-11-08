"""Compare two evaluations: what findings and capabilities appeared or went away.

Findings are matched by their stable fingerprint; capabilities by agent id and the
`field=value` capability key. Both inputs are evaluation JSON produced by `evaluate`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from agentcapmap.findings import Evaluation, Finding, Severity
from agentcapmap.report._text import md_code

_MAX_ROWS = 100


class CapabilityChange(BaseModel):
    agent_id: str
    capability: str
    tools: list[str] = Field(default_factory=list)  # "server/tool"


class EvaluationDiff(BaseModel):
    new_findings: list[Finding] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)
    gained_capabilities: list[CapabilityChange] = Field(default_factory=list)
    lost_capabilities: list[CapabilityChange] = Field(default_factory=list)


def _capabilities(evaluation: Evaluation) -> dict[tuple[str, str], list[str]]:
    return {
        (agent.agent_id, capability): sorted({f"{ref.server}/{ref.tool}" for ref in refs})
        for agent in evaluation.agents
        for capability, refs in agent.capabilities.items()
    }


def _changes(
    source: dict[tuple[str, str], list[str]], other: dict[tuple[str, str], list[str]]
) -> list[CapabilityChange]:
    return [
        CapabilityChange(agent_id=agent, capability=capability, tools=tools)
        for (agent, capability), tools in sorted(source.items())
        if (agent, capability) not in other
    ]


def diff_evaluations(old: Evaluation, new: Evaluation) -> EvaluationDiff:
    old_prints = {f.fingerprint for f in old.findings}
    new_prints = {f.fingerprint for f in new.findings}
    old_caps, new_caps = _capabilities(old), _capabilities(new)
    return EvaluationDiff(
        new_findings=[f for f in new.findings if f.fingerprint not in old_prints],
        resolved_findings=[f for f in old.findings if f.fingerprint not in new_prints],
        gained_capabilities=_changes(new_caps, old_caps),
        lost_capabilities=_changes(old_caps, new_caps),
    )


def should_fail_diff(
    diff: EvaluationDiff, fail_on: Severity | None, fail_on_new_capability: bool
) -> bool:
    """Fail on a *new* finding at or above `fail_on`, or on any gained capability."""
    if fail_on is not None and any(f.severity.rank >= fail_on.rank for f in diff.new_findings):
        return True
    return fail_on_new_capability and bool(diff.gained_capabilities)


def _capability_lines(title: str, changes: list[CapabilityChange]) -> list[str]:
    lines = [f"## {title} ({len(changes)})", ""]
    if not changes:
        return [*lines, "None.", ""]
    for change in changes[:_MAX_ROWS]:
        tools = ", ".join(md_code(t, 120) for t in change.tools[:10])
        lines.append(
            f"- {md_code(change.agent_id, 120)}: {md_code(change.capability, 80)} via {tools}"
        )
    if len(changes) > _MAX_ROWS:
        lines.append(f"- ... and {len(changes) - _MAX_ROWS} more")
    return [*lines, ""]


def _finding_lines(title: str, findings: list[Finding]) -> list[str]:
    lines = [f"## {title} ({len(findings)})", ""]
    if not findings:
        return [*lines, "None.", ""]
    for finding in findings[:_MAX_ROWS]:
        lines.append(
            f"- **{finding.severity.value}** {md_code(finding.rule_id, 40)}: "
            f"{md_code(finding.message, 300)}"
        )
    if len(findings) > _MAX_ROWS:
        lines.append(f"- ... and {len(findings) - _MAX_ROWS} more")
    return [*lines, ""]


def render_markdown(diff: EvaluationDiff) -> str:
    lines = ["# agent-capmap diff", ""]
    lines += _finding_lines("New findings", diff.new_findings)
    lines += _capability_lines("Gained capabilities", diff.gained_capabilities)
    lines += _finding_lines("Resolved findings", diff.resolved_findings)
    lines += _capability_lines("Lost capabilities", diff.lost_capabilities)
    return "\n".join(lines)

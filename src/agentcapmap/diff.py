"""Compare two evaluations: what findings and capabilities appeared or went away.

Findings are matched by their stable fingerprint; capabilities by agent id and the
`field=value` capability key. Both inputs are evaluation JSON produced by `evaluate`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from agentcapmap.findings import (
    Evaluation,
    Finding,
    NotAssessed,
    Severity,
    WaivedFinding,
)
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
    # Servers or tools that could not be assessed now but were not before: in config-only
    # mode this is how a newly added MCP server shows up.
    new_not_assessed: list[NotAssessed] = Field(default_factory=list)
    # Findings waived in the new evaluation but not in the old one: a decision to accept a
    # risk, which a reviewer should see, not a finding that was fixed.
    newly_waived: list[WaivedFinding] = Field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.new_findings
            or self.resolved_findings
            or self.gained_capabilities
            or self.lost_capabilities
            or self.new_not_assessed
            or self.newly_waived
        )


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
    seen = {(n.agent_id, n.server, n.tool) for n in old.not_assessed}
    old_waived = {w.finding.fingerprint for w in old.waived}
    new_waived = {w.finding.fingerprint for w in new.waived}
    return EvaluationDiff(
        new_findings=[f for f in new.findings if f.fingerprint not in old_prints],
        resolved_findings=[
            f
            for f in old.findings
            if f.fingerprint not in new_prints and f.fingerprint not in new_waived
        ],
        newly_waived=[w for w in new.waived if w.finding.fingerprint not in old_waived],
        gained_capabilities=_changes(new_caps, old_caps),
        lost_capabilities=_changes(old_caps, new_caps),
        new_not_assessed=[
            n for n in new.not_assessed if (n.agent_id, n.server, n.tool) not in seen
        ],
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


def _not_assessed_lines(items: list[NotAssessed]) -> list[str]:
    lines = [f"## Newly not assessed ({len(items)})", ""]
    if not items:
        return [*lines, "None.", ""]
    for item in items[:_MAX_ROWS]:
        where = f"{item.server}/{item.tool}" if item.tool else item.server
        lines.append(f"- {md_code(where, 160)}: {md_code(item.reason, 200)}")
    if len(items) > _MAX_ROWS:
        lines.append(f"- ... and {len(items) - _MAX_ROWS} more")
    return [*lines, ""]


def _waived_lines(items: list[WaivedFinding]) -> list[str]:
    lines = [f"## Newly waived ({len(items)})", ""]
    if not items:
        return [*lines, "None.", ""]
    lines += ["Accepted in this change: a reviewer should agree with each reason.", ""]
    for item in items[:_MAX_ROWS]:
        lines.append(
            f"- {md_code(item.finding.rule_id, 40)} on "
            f"{md_code(', '.join(item.finding.servers), 160)}: {md_code(item.waiver.reason, 300)} "
            f"(owner {md_code(item.waiver.owner, 100)}, until "
            f"{md_code(item.waiver.expires.isoformat(), 12)})"
        )
    if len(items) > _MAX_ROWS:
        lines.append(f"- ... and {len(items) - _MAX_ROWS} more")
    return [*lines, ""]


def render_markdown(diff: EvaluationDiff) -> str:
    lines = ["# agent-capmap diff", ""]
    if diff.changed:
        lines += [
            f"{len(diff.new_findings)} new finding(s), "
            f"{len(diff.gained_capabilities)} gained capability(ies), "
            f"{len(diff.new_not_assessed)} newly not assessed, "
            f"{len(diff.newly_waived)} newly waived, "
            f"{len(diff.resolved_findings)} resolved.",
            "",
        ]
    else:
        lines += ["No changes compared with the base.", ""]
    lines += _finding_lines("New findings", diff.new_findings)
    lines += _capability_lines("Gained capabilities", diff.gained_capabilities)
    lines += _not_assessed_lines(diff.new_not_assessed)
    lines += _waived_lines(diff.newly_waived)
    lines += _finding_lines("Resolved findings", diff.resolved_findings)
    lines += _capability_lines("Lost capabilities", diff.lost_capabilities)
    return "\n".join(lines)

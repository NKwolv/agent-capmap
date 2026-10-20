"""Markdown report (also used for the GitHub Actions job summary).

Only constant labels, numbers and severities appear outside code spans; every value
derived from configs, servers or policy files goes through `md_code`.
"""

from __future__ import annotations

from agentcapmap.findings import Evaluation, Finding, Severity
from agentcapmap.report._text import md_code

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}
_MAX_FINDINGS = 200
_MAX_ROWS = 50


def _finding(index: int, finding: Finding) -> list[str]:
    where = finding.location
    location = f"{where.path}:{where.line}" if where and where.line else finding.config_path
    lines = [
        f"### {index}. {md_code(finding.rule_id, 40)} | {_SEVERITY_LABEL[finding.severity]}",
        "",
        md_code(finding.message, 500),
        "",
        f"- **Agent:** {md_code(finding.agent_id, 200)} at {md_code(location, 200)}",
        f"- **Servers:** {', '.join(md_code(s, 100) for s in finding.servers)}",
    ]
    if finding.tools:
        lines.append(
            f"- **Tools:** {', '.join(md_code(t, 120) for t in finding.tools[:_MAX_ROWS])}"
        )
    if finding.maps_to:
        lines.append(f"- **Maps to:** {', '.join(md_code(m, 64) for m in finding.maps_to)}")
    if finding.details:
        for key in ("changed", "added", "removed"):
            names = finding.details.get(key)
            if names:
                rendered = ", ".join(md_code(n, 120) for n in names[:_MAX_ROWS])
                lines.append(f"- **Tools {key}:** {rendered}")
    if finding.evidence:
        lines += ["", "| Server | Tool | Matched | Evidence |", "|---|---|---|---|"]
        for ev in finding.evidence[:_MAX_ROWS]:
            matched = ", ".join(f"{k}={str(v).lower()}" for k, v in ev.matched.items())
            phrases = "; ".join(f"{k}: {v}" for k, v in ev.phrases.items())
            if ev.unverified:
                phrases += f" (unverified: {', '.join(ev.unverified)})"
            lines.append(
                "| "
                + " | ".join(
                    [
                        md_code(ev.server, 100, in_table=True),
                        md_code(ev.tool or "", 100, in_table=True),
                        md_code(matched, 200, in_table=True),
                        md_code(phrases, 300, in_table=True),
                    ]
                )
                + " |"
            )
        if len(finding.evidence) > _MAX_ROWS:
            lines.append(f"\n_{len(finding.evidence) - _MAX_ROWS} more evidence rows omitted._")
    return [*lines, ""]


def render(evaluation: Evaluation) -> str:
    summary = evaluation.summary
    lines = [
        "# agent-capmap report",
        "",
        f"**Policy:** {md_code(evaluation.policy.source, 200)} "
        f"(sha256 {md_code(evaluation.policy.sha256[:12], 12)}) | "
        f"**Baseline:** {'used' if evaluation.baseline_used else 'not used'} | "
        f"**Agents:** {len(evaluation.agents)}",
        "",
        "| Severity | Findings |",
        "|---|---|",
        *(f"| {_SEVERITY_LABEL[s]} | {summary.get(s.value, 0)} |" for s in Severity),
        "",
    ]
    not_assessed = len(evaluation.not_assessed)
    if not_assessed:
        lines += [
            f"> [!WARNING]\n> {not_assessed} server(s) or tool(s) were **not assessed**, so "
            "findings may be incomplete. See the table at the end.",
            "",
        ]
    if evaluation.skipped_rules:
        skipped = ", ".join(
            f"{md_code(s.rule_id, 40)} ({md_code(s.reason, 100)})" for s in evaluation.skipped_rules
        )
        lines += [f"Skipped rules: {skipped}", ""]

    lines += ["## Findings", ""]
    if not evaluation.findings:
        lines += ["No findings.", ""]
    for index, finding in enumerate(evaluation.findings[:_MAX_FINDINGS], start=1):
        lines += _finding(index, finding)
    if len(evaluation.findings) > _MAX_FINDINGS:
        lines += [
            f"_{len(evaluation.findings) - _MAX_FINDINGS} more findings omitted; "
            "see the JSON output._",
            "",
        ]

    if not_assessed:
        lines += ["## Not assessed", "", "| Agent | Server | Tool | Reason |", "|---|---|---|---|"]
        for item in evaluation.not_assessed[:_MAX_FINDINGS]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        md_code(item.agent_id, 120, in_table=True),
                        md_code(item.server, 100, in_table=True),
                        md_code(item.tool or "", 100, in_table=True),
                        md_code(item.reason, 200, in_table=True),
                    ]
                )
                + " |"
            )
        lines.append("")

    lines += ["## Capabilities by agent", ""]
    for agent in evaluation.agents:
        lines += [
            f"### {md_code(agent.agent_id, 200)}",
            "",
            f"{agent.tools_assessed} of {agent.tools_total} tool(s) assessed.",
            "",
        ]
        if not agent.capabilities:
            lines += ["No capabilities beyond the defaults.", ""]
            continue
        lines += ["| Capability | Tools |", "|---|---|"]
        for capability, refs in agent.capabilities.items():
            tools = ", ".join(f"{r.server}/{r.tool}" for r in refs[:_MAX_ROWS])
            cap_cell = md_code(capability, 60, in_table=True)
            lines.append(f"| {cap_cell} | {md_code(tools, 500, in_table=True)} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

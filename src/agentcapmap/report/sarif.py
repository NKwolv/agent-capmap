"""SARIF 2.1.0 output for GitHub code scanning.

- Rules come from the policy; GitHub ranks them by `security-severity`.
- Each result points at the config file and line where the (first) server is defined.
- Locations must be repository-relative. Absolute paths, `..` segments and URLs are
  never emitted; GitHub rejects results without a location, so such findings are left
  out of the SARIF (still present in JSON/Markdown) and a notification says so.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from agentcapmap import __version__
from agentcapmap.findings import Evaluation, Finding, RuleInfo, ServerLocation, Severity
from agentcapmap.report._text import clean

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/NKwolv/agent-capmap"
FINGERPRINT_KEY = "agentcapmapFinding/v1"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub buckets: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def safe_uri(path: str | None) -> str | None:
    """A repository-relative URI reference, or None if the path is not safely relative."""
    if not path:
        return None
    normalized = path.replace("\\", "/")
    if normalized.startswith("/") or _WINDOWS_DRIVE.match(normalized) or "://" in normalized:
        return None
    segments = normalized.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        return None
    return quote(normalized, safe="/-._~")


def _location(loc: ServerLocation | None, path: str, line: int | None) -> dict[str, Any] | None:
    uri = safe_uri(loc.path if loc else path)
    if uri is None:
        return None
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
    start = loc.line if loc else line
    if start and start > 0:
        physical["region"] = {"startLine": start}
    return {"physicalLocation": physical}


def _rule(rule: RuleInfo) -> dict[str, Any]:
    message = clean(rule.message, 1000)
    refs = ", ".join(clean(m, 64) for m in rule.maps_to)
    help_text = message + (f" Maps to: {refs}." if refs else "")
    return {
        "id": rule.id,
        "name": rule.id.replace("-", ""),
        "shortDescription": {"text": clean(rule.message.split(". ")[0], 200)},
        "fullDescription": {"text": message},
        "help": {"text": help_text},
        "helpUri": f"{INFORMATION_URI}/blob/main/docs/threat-model.md",
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", "mcp", *(clean(m, 64) for m in rule.maps_to)],
            "precision": "high",
            "problem.severity": "error" if _LEVEL[rule.severity] == "error" else "warning",
            "security-severity": _SECURITY_SEVERITY[rule.severity],
        },
    }


def _message(finding: Finding) -> str:
    parts = [clean(finding.message, 600), f"Agent: {clean(finding.agent_id, 200)}."]
    if finding.tools:
        parts.append(f"Tools: {clean(', '.join(finding.tools), 400)}.")
    evidence = [
        f"{clean(ev.tool or ev.server, 80)} [{clean(k, 40)}]: {clean(v, 160)}"
        for ev in finding.evidence
        for k, v in ev.phrases.items()
    ]
    if evidence:
        parts.append(
            "Evidence: " + "; ".join(evidence[:8]) + ("; ..." if len(evidence) > 8 else "")
        )
    return " ".join(parts)


def _result(finding: Finding, rule_index: int) -> dict[str, Any] | None:
    first = finding.server_locations[0] if finding.server_locations else None
    path = finding.location.path if finding.location else finding.config_path
    line = finding.location.line if finding.location else None
    primary = _location(first, path, line)
    if primary is None:
        return None
    related = []
    for index, loc in enumerate(finding.server_locations[1:], start=1):
        if (location := _location(loc, loc.path, loc.line)) is not None:
            location["id"] = index
            location["message"] = {"text": f"server {clean(loc.server, 100)}"}
            related.append(location)
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": _message(finding)},
        "locations": [primary],
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "properties": {
            "severity": finding.severity.value,
            "agent": clean(finding.agent_id, 200),
            "servers": [clean(s, 100) for s in finding.servers],
            "tools": [clean(t, 200) for t in finding.tools],
        },
    }
    if related:
        result["relatedLocations"] = related
    return result


def render(evaluation: Evaluation) -> dict[str, Any]:
    rules = [r for r in evaluation.rules if r.enabled]
    rule_index = {r.id: i for i, r in enumerate(rules)}
    results: list[dict[str, Any]] = []
    omitted = 0
    for finding in evaluation.findings:
        result = _result(finding, rule_index[finding.rule_id])
        if result is None:
            omitted += 1
        else:
            results.append(result)

    notifications: list[dict[str, Any]] = []
    if evaluation.not_assessed:
        notifications.append(
            {
                "level": "warning",
                "descriptor": {"id": "not-assessed"},
                "message": {
                    "text": f"{len(evaluation.not_assessed)} server(s) or tool(s) were not "
                    "assessed (not enumerated or not classified); findings may be incomplete."
                },
            }
        )
    for skipped in evaluation.skipped_rules:
        notifications.append(
            {
                "level": "note",
                "descriptor": {"id": "rule-skipped"},
                "message": {
                    "text": f"Rule {skipped.rule_id} skipped: {clean(skipped.reason, 200)}"
                },
            }
        )
    if omitted:
        notifications.append(
            {
                "level": "warning",
                "descriptor": {"id": "result-omitted"},
                "message": {
                    "text": f"{omitted} finding(s) omitted from SARIF because their config "
                    "file is outside the repository; see the JSON or Markdown report."
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-capmap",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule(r) for r in rules],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
                "properties": {
                    "policy": evaluation.policy.model_dump(mode="json"),
                    "summary": evaluation.summary,
                    "baselineUsed": evaluation.baseline_used,
                },
            }
        ],
    }

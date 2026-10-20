"""Render an evaluation as JSON, Markdown or SARIF, and decide the exit status."""

from __future__ import annotations

import json
from enum import StrEnum

from agentcapmap.findings import Evaluation, Severity
from agentcapmap.report import markdown, sarif


class Format(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


def render(evaluation: Evaluation, fmt: Format) -> str:
    if fmt is Format.MARKDOWN:
        return markdown.render(evaluation)
    if fmt is Format.SARIF:
        return json.dumps(sarif.render(evaluation), indent=2, ensure_ascii=False) + "\n"
    return evaluation.model_dump_json(indent=2) + "\n"


def should_fail(
    evaluation: Evaluation, fail_on: Severity | None, fail_on_not_assessed: bool = False
) -> bool:
    """True when a finding is at or above `fail_on`, or anything was not assessed and
    `fail_on_not_assessed` is set."""
    if fail_on is not None and any(f.severity.rank >= fail_on.rank for f in evaluation.findings):
        return True
    return fail_on_not_assessed and bool(evaluation.not_assessed)


__all__ = ["Format", "render", "should_fail"]

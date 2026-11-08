"""Waivers: findings a person has decided to accept, recorded with an owner and an end date.

A waiver names one finding by its fingerprint (exact match, no wildcards, so it can never
hide a future finding). It must have a reason, an owner and an `expires` date no more than
a year ahead. Expired waivers stop applying: the finding is active again and the waiver is
reported. Waived findings are never hidden: they are listed with their reason.

The waivers file is hostile input (in a repository, a pull request can edit it): it is
parsed with the hardened YAML loader used for policies, validated against
schemas/waivers.schema.json and bounded in size and count.
"""

from __future__ import annotations

import functools
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from agentcapmap.findings import Evaluation, Finding, Severity, WaivedFinding, Waiver, WaiverIssue
from agentcapmap.policy.loader import PolicyError
from agentcapmap.policy.loader import _parse_yaml as parse_yaml
from agentcapmap.redact import get_logger
from agentcapmap.taxonomy import data_file

log = get_logger(__name__)

MAX_WAIVER_FILE_BYTES = 512 * 1024
MAX_WAIVER_DAYS = 366  # a waiver is a temporary decision: it must be renewed within a year


class WaiverError(ValueError):
    """The waivers file cannot be used. Nothing is waived when this is raised."""


@functools.cache
def _validator() -> Draft202012Validator:
    schema = json.loads(data_file("schemas", "waivers.schema.json"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _stringify_dates(data: Any) -> Any:
    """YAML turns an unquoted `2027-02-01` into a date; the schema wants the text."""
    if isinstance(data, dict) and isinstance(data.get("waivers"), list):
        for item in data["waivers"]:
            if isinstance(item, dict) and isinstance(item.get("expires"), date):
                item["expires"] = item["expires"].isoformat()
    return data


def parse_waivers(text: str, source: str, *, today: date | None = None) -> list[Waiver]:
    today = today or date.today()
    try:
        data = _stringify_dates(parse_yaml(text))
    except PolicyError as exc:
        raise WaiverError(f"{source}: {exc}") from None
    error = best_match(_validator().iter_errors(data))
    if error is not None:
        where = "/".join(str(p) for p in error.absolute_path) or "(root)"
        raise WaiverError(f"{source}: invalid waivers at {where}: {error.message}")

    waivers: list[Waiver] = []
    seen: set[str] = set()
    for index, raw in enumerate(data["waivers"], start=1):
        try:
            waiver = Waiver.model_validate(raw)
        except ValueError:
            raise WaiverError(f"{source}: waiver {index} has an invalid expires date") from None
        if waiver.fingerprint in seen:
            raise WaiverError(f"{source}: fingerprint {waiver.fingerprint} appears twice")
        seen.add(waiver.fingerprint)
        if waiver.expires > today + timedelta(days=MAX_WAIVER_DAYS):
            raise WaiverError(
                f"{source}: waiver {index} expires {waiver.expires}, more than "
                f"{MAX_WAIVER_DAYS} days ahead: waivers are temporary, renew them instead"
            )
        waivers.append(waiver)
    return waivers


def load_waivers(path: Path, *, today: date | None = None) -> list[Waiver]:
    try:
        if path.stat().st_size > MAX_WAIVER_FILE_BYTES:
            raise WaiverError(f"{path}: waivers file larger than {MAX_WAIVER_FILE_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise WaiverError(f"cannot read waivers {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise WaiverError(f"{path}: waivers are not UTF-8 text") from None
    return parse_waivers(text, path.as_posix(), today=today)


def apply_waivers(
    evaluation: Evaluation, waivers: list[Waiver], *, today: date | None = None
) -> Evaluation:
    """Move findings accepted by a valid waiver out of `findings`; report waiver problems."""
    today = today or date.today()
    by_print = {w.fingerprint: w for w in waivers}
    active: list[Finding] = []
    waived: list[WaivedFinding] = []
    issues: list[WaiverIssue] = []
    matched: set[str] = set()

    for finding in evaluation.findings:
        waiver = by_print.get(finding.fingerprint)
        if waiver is None:
            active.append(finding)
            continue
        matched.add(waiver.fingerprint)
        if waiver.expires < today:
            active.append(finding)  # fail closed: an expired waiver accepts nothing
            issues.append(
                WaiverIssue(
                    kind="expired",
                    fingerprint=waiver.fingerprint,
                    owner=waiver.owner,
                    message=f"waiver for {finding.rule_id} expired on {waiver.expires}; "
                    "the finding is active again",
                )
            )
        elif waiver.rule is not None and waiver.rule != finding.rule_id:
            active.append(finding)
            issues.append(
                WaiverIssue(
                    kind="rule_mismatch",
                    fingerprint=waiver.fingerprint,
                    owner=waiver.owner,
                    message=f"waiver says {waiver.rule} but the finding is {finding.rule_id}; "
                    "it was not applied",
                )
            )
        else:
            waived.append(WaivedFinding(finding=finding, waiver=waiver))

    for waiver in waivers:
        if waiver.fingerprint not in matched:
            issues.append(
                WaiverIssue(
                    kind="unused",
                    fingerprint=waiver.fingerprint,
                    owner=waiver.owner,
                    message="matches no current finding (fixed, renamed or stale): remove it",
                )
            )

    summary = dict(evaluation.summary)
    for severity in Severity:
        summary[severity.value] = sum(1 for f in active if f.severity is severity)
    summary["waived"] = len(waived)
    if issues:
        log.warning("%d waiver issue(s); see 'waiver_issues' in the output", len(issues))
    return evaluation.model_copy(
        update={"findings": active, "waived": waived, "waiver_issues": issues, "summary": summary}
    )

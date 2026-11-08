"""Waivers: loading, validation, applying, reporting, exit codes and diffs."""

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft4Validator

from agentcapmap.cli import main
from agentcapmap.diff import diff_evaluations
from agentcapmap.diff import render_markdown as render_diff
from agentcapmap.findings import Evaluation, Severity
from agentcapmap.policy import evaluate, load_policy
from agentcapmap.policy.waivers import (
    MAX_WAIVER_FILE_BYTES,
    WaiverError,
    apply_waivers,
    load_waivers,
    parse_waivers,
)
from agentcapmap.report import Format, render, should_fail
from agentcapmap.report.sarif import render as render_sarif
from tests.scenarios import load_scenario
from tests.test_report import SARIF_SCHEMA_PATH

TODAY = date(2026, 11, 8)
FUTURE = (TODAY + timedelta(days=90)).isoformat()


@pytest.fixture(scope="module")
def evaluation() -> Evaluation:
    result = evaluate(load_scenario("trifecta"), load_policy(), None)
    assert any(f.rule_id == "CAP-001" for f in result.findings)
    return result


def _fp(evaluation: Evaluation, rule: str = "CAP-001") -> str:
    return next(f.fingerprint for f in evaluation.findings if f.rule_id == rule)


def _yaml(*entries: str) -> str:
    return "version: 1\nwaivers:\n" + "".join(entries)


def _entry(
    fingerprint: str,
    *,
    owner: str = "alice",
    reason: str = "Accepted: sandboxed directory, reviewed",
    expires: str = FUTURE,
    rule: str | None = None,
) -> str:
    extra = f"    rule: {rule}\n" if rule else ""
    return (
        f"  - fingerprint: {fingerprint}\n    owner: {owner}\n"
        f"    reason: {json.dumps(reason)}\n    expires: {expires}\n{extra}"
    )


# --- loading and validation --------------------------------------------------------------


def test_parses_a_valid_file_including_unquoted_yaml_dates() -> None:
    fp = "a" * 32
    [waiver] = parse_waivers(_yaml(_entry(fp, expires=FUTURE)), "w.yaml", today=TODAY)
    assert (waiver.fingerprint, waiver.owner) == (fp, "alice")
    assert waiver.expires == TODAY + timedelta(days=90)
    [quoted] = parse_waivers(_yaml(_entry(fp, expires=f'"{FUTURE}"')), "w.yaml", today=TODAY)
    assert quoted.expires == waiver.expires


def test_an_empty_waiver_list_is_fine() -> None:
    assert parse_waivers("version: 1\nwaivers: []\n", "w.yaml", today=TODAY) == []


@pytest.mark.parametrize(
    "text",
    [
        "version: 2\nwaivers: []\n",
        "waivers: []\n",
        "version: 1\nwaivers: []\nextra: true\n",
        _yaml(f"  - fingerprint: {'a' * 32}\n    owner: x\n    expires: 2027-01-01\n"),  # no reason
        _yaml(_entry("a" * 32, reason="too short")),
        _yaml(_entry("*")),
        _yaml(_entry("A" * 32)),
        _yaml(_entry("a" * 31)),
        _yaml(_entry("a" * 32, owner='""')),
        _yaml(_entry("a" * 32, expires="next-week")),
        _yaml(_entry("a" * 32, expires="2026-13-45")),
        _yaml(_entry("a" * 32) + "    severity: low\n"),
        _yaml(_entry("a" * 32), _entry("a" * 32)),
    ],
    ids=[
        "wrong-version", "no-version", "unknown-top-key", "no-reason", "short-reason",
        "wildcard", "uppercase-hex", "short-hex", "empty-owner", "bad-date-text",
        "impossible-date", "unknown-field", "duplicate",
    ],
)  # fmt: skip
def test_invalid_files_are_rejected_not_partially_applied(text: str) -> None:
    with pytest.raises(WaiverError):
        parse_waivers(text, "w.yaml", today=TODAY)


def test_waivers_must_expire_within_a_year() -> None:
    too_far = (TODAY + timedelta(days=400)).isoformat()
    with pytest.raises(WaiverError, match="temporary"):
        parse_waivers(_yaml(_entry("a" * 32, expires=too_far)), "w.yaml", today=TODAY)
    last_ok = (TODAY + timedelta(days=366)).isoformat()
    assert parse_waivers(_yaml(_entry("a" * 32, expires=last_ok)), "w.yaml", today=TODAY)


def test_hostile_yaml_is_refused() -> None:
    anchored = "version: 1\nwaivers: &x []\n"
    with pytest.raises(WaiverError, match="anchors"):
        parse_waivers(anchored, "w.yaml", today=TODAY)
    with pytest.raises(WaiverError, match="duplicate key"):
        parse_waivers("version: 1\nversion: 1\nwaivers: []\n", "w.yaml", today=TODAY)
    with pytest.raises(WaiverError):
        parse_waivers("version: 1\nwaivers: " + "[" * 500 + "]" * 500 + "\n", "w.yaml", today=TODAY)


def test_file_problems_are_reported_cleanly(tmp_path: Path) -> None:
    with pytest.raises(WaiverError, match="cannot read"):
        load_waivers(tmp_path / "missing.yaml")
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * (MAX_WAIVER_FILE_BYTES + 1))
    with pytest.raises(WaiverError, match="larger than"):
        load_waivers(big)
    binary = tmp_path / "bin.yaml"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(WaiverError, match="not UTF-8"):
        load_waivers(binary)


# --- applying ----------------------------------------------------------------------------


def _apply(evaluation: Evaluation, *entries: str, today: date = TODAY) -> Evaluation:
    waivers = parse_waivers(_yaml(*entries), "w.yaml", today=today)
    return apply_waivers(evaluation, waivers, today=today)


def test_a_waived_finding_leaves_the_gate_but_stays_visible(evaluation: Evaluation) -> None:
    before_critical = evaluation.summary["critical"]
    result = _apply(evaluation, _entry(_fp(evaluation), rule="CAP-001"))
    assert before_critical >= 1 and result.summary["critical"] == before_critical - 1
    assert result.summary["waived"] == 1
    assert "CAP-001" not in {f.rule_id for f in result.findings}
    [waived] = result.waived
    assert waived.finding.rule_id == "CAP-001" and waived.waiver.owner == "alice"
    assert result.waiver_issues == []
    assert should_fail(evaluation, Severity.CRITICAL)
    assert not should_fail(result, Severity.CRITICAL)
    assert len(evaluation.findings) == len(result.findings) + 1  # input is not modified


def test_the_last_day_still_counts_and_the_day_after_does_not(evaluation: Evaluation) -> None:
    entry = _entry(_fp(evaluation), expires=TODAY.isoformat())
    assert _apply(evaluation, entry).waived  # expires today: valid through today
    tomorrow = TODAY + timedelta(days=1)
    expired = apply_waivers(
        evaluation, parse_waivers(_yaml(entry), "w", today=TODAY), today=tomorrow
    )
    assert not expired.waived
    assert "CAP-001" in {f.rule_id for f in expired.findings}  # fail closed
    [issue] = expired.waiver_issues
    assert issue.kind == "expired" and issue.owner == "alice"
    assert should_fail(expired, Severity.CRITICAL)


def test_a_waiver_for_the_wrong_rule_is_not_applied(evaluation: Evaluation) -> None:
    result = _apply(evaluation, _entry(_fp(evaluation), rule="CAP-002"))
    assert not result.waived and "CAP-001" in {f.rule_id for f in result.findings}
    assert [i.kind for i in result.waiver_issues] == ["rule_mismatch"]


def test_a_waiver_that_matches_nothing_is_reported_as_stale(evaluation: Evaluation) -> None:
    result = _apply(evaluation, _entry("b" * 32))
    assert not result.waived and len(result.findings) == len(evaluation.findings)
    assert [i.kind for i in result.waiver_issues] == ["unused"]


def test_exact_match_only_so_other_findings_are_untouched(evaluation: Evaluation) -> None:
    others = [f for f in evaluation.findings if f.rule_id != "CAP-001"]
    result = _apply(evaluation, _entry(_fp(evaluation)))
    assert [f.fingerprint for f in result.findings] == [f.fingerprint for f in others]


# --- reports -----------------------------------------------------------------------------


def test_markdown_lists_waived_findings_with_their_reasons(evaluation: Evaluation) -> None:
    result = _apply(evaluation, _entry(_fp(evaluation), reason="Sandboxed; ticket SEC-12 reviewed"))
    text = render(result, Format.MARKDOWN)
    assert "## Waived findings (1)" in text
    assert "`Sandboxed; ticket SEC-12 reviewed`" in text and "`alice`" in text
    findings_section = text.split("## Findings", 1)[1].split("## Waived findings", 1)[0]
    assert "CAP-001" not in findings_section


def test_markdown_renders_hostile_waiver_text_inertly(evaluation: Evaluation) -> None:
    hostile = "[click](http://evil.example) <img src=x onerror=alert(1)> | table | break"
    result = _apply(evaluation, _entry(_fp(evaluation), reason=hostile, owner="'<b>bob</b>'"))
    text = render(result, Format.MARKDOWN)
    assert "<img" not in text.replace("`", "") or "`" in text  # only inside code spans
    line = next(row for row in text.splitlines() if "http://evil.example" in row)
    assert "`[click](http://evil.example)" in line
    assert "<b>" not in line.replace("`<b>", "")


def test_expired_and_unused_waivers_show_up_as_issues(evaluation: Evaluation) -> None:
    expired = _entry(_fp(evaluation), expires=TODAY.isoformat())
    waivers = parse_waivers(_yaml(expired, _entry("c" * 32)), "w", today=TODAY)
    result = apply_waivers(evaluation, waivers, today=TODAY + timedelta(days=5))
    text = render(result, Format.MARKDOWN)
    assert "## Waiver issues (2)" in text and "**expired**" in text and "**unused**" in text


def test_sarif_omits_waived_findings_and_says_so(evaluation: Evaluation) -> None:
    result = _apply(evaluation, _entry(_fp(evaluation)), _entry("d" * 32))
    sarif = render_sarif(result)
    run = sarif["runs"][0]
    assert len(run["results"]) == len(result.findings)
    ids = {n["descriptor"]["id"] for n in run["invocations"][0]["toolExecutionNotifications"]}
    assert {"findings-waived", "waiver-unused"} <= ids
    schema = json.loads(SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert list(Draft4Validator(schema).iter_errors(sarif)) == []


# --- command line ------------------------------------------------------------------------


@pytest.fixture
def inventory_file(tmp_path: Path) -> Path:
    path = tmp_path / "inventory.json"
    path.write_text(load_scenario("trifecta").model_dump_json(), encoding="utf-8")
    return path


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "waivers.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_cli_a_valid_waiver_turns_a_failing_gate_green(
    tmp_path: Path, inventory_file: Path, evaluation: Evaluation
) -> None:
    out = tmp_path / "eval.json"
    base = ["evaluate", str(inventory_file), "-o", str(out), "--fail-on", "critical"]
    assert main(base) == 1
    waivers = _write(tmp_path, _yaml(_entry(_fp(evaluation), expires=FUTURE_FROM_NOW())))
    assert main([*base, "--waivers", str(waivers)]) == 0
    saved = Evaluation.model_validate_json(out.read_text(encoding="utf-8"))
    assert [w.finding.rule_id for w in saved.waived] == ["CAP-001"]


def FUTURE_FROM_NOW() -> str:
    return (date.today() + timedelta(days=30)).isoformat()


def test_cli_an_expired_waiver_does_not_hide_the_finding(
    tmp_path: Path, inventory_file: Path, evaluation: Evaluation
) -> None:
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    waivers = _write(tmp_path, _yaml(_entry(_fp(evaluation), expires=yesterday)))
    code = main(
        ["evaluate", str(inventory_file), "-o", str(tmp_path / "e.json"), "--fail-on", "critical",
         "--waivers", str(waivers)]
    )  # fmt: skip
    assert code == 1


def test_cli_a_broken_waivers_file_is_an_error_not_a_silent_ignore(
    tmp_path: Path, inventory_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    waivers = _write(tmp_path, "version: 1\nwaivers: [{fingerprint: '*'}]\n")
    code = main(["evaluate", str(inventory_file), "--waivers", str(waivers)])
    assert code == 2
    assert "invalid waivers" in capsys.readouterr().err


# --- diff --------------------------------------------------------------------------------


def test_diff_shows_a_newly_waived_finding_for_review(evaluation: Evaluation) -> None:
    head = _apply(evaluation, _entry(_fp(evaluation), reason="Accepted by the author of the PR"))
    diff = diff_evaluations(evaluation, head)
    assert [w.finding.rule_id for w in diff.newly_waived] == ["CAP-001"]
    assert diff.resolved_findings == []  # waived is not "fixed"
    assert diff.changed
    text = render_diff(diff)
    assert "## Newly waived (1)" in text and "`Accepted by the author of the PR`" in text
    assert "1 newly waived" in text


def test_diff_ignores_waivers_that_already_existed(evaluation: Evaluation) -> None:
    both = _apply(evaluation, _entry(_fp(evaluation)))
    assert diff_evaluations(both, both).newly_waived == []
    assert not diff_evaluations(both, both).changed

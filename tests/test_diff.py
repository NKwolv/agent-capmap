"""Evaluation diff: new/resolved findings, gained/lost capabilities, exit codes."""

import json
from pathlib import Path

import pytest

from agentcapmap.cli import main
from agentcapmap.diff import diff_evaluations, render_markdown, should_fail_diff
from agentcapmap.findings import Evaluation, Severity
from agentcapmap.policy import evaluate, load_policy
from tests.scenarios import load_scenario


@pytest.fixture(scope="module")
def risky() -> Evaluation:
    result = evaluate(load_scenario("trifecta"), load_policy(), None)
    assert result.findings
    assert any(agent.capabilities for agent in result.agents)
    return result


def _emptied(evaluation: Evaluation) -> Evaluation:
    """The same agents before they gained anything risky."""
    return evaluation.model_copy(
        update={
            "findings": [],
            "agents": [a.model_copy(update={"capabilities": {}}) for a in evaluation.agents],
        }
    )


def test_identical_evaluations_have_no_diff(risky: Evaluation) -> None:
    diff = diff_evaluations(risky, risky)
    assert not (
        diff.new_findings
        or diff.resolved_findings
        or diff.gained_capabilities
        or diff.lost_capabilities
    )
    assert not should_fail_diff(diff, Severity.INFO, True)


def test_new_findings_and_gained_capabilities(risky: Evaluation) -> None:
    diff = diff_evaluations(_emptied(risky), risky)
    assert diff.new_findings == risky.findings
    assert diff.resolved_findings == []
    assert diff.gained_capabilities
    assert all(c.tools for c in diff.gained_capabilities)
    assert should_fail_diff(diff, Severity.INFO, False)
    assert should_fail_diff(diff, None, True)
    assert not should_fail_diff(diff, None, False)


def test_resolved_findings_and_lost_capabilities(risky: Evaluation) -> None:
    diff = diff_evaluations(risky, _emptied(risky))
    assert diff.resolved_findings == risky.findings
    assert diff.lost_capabilities
    assert diff.new_findings == [] and diff.gained_capabilities == []
    # Getting safer never fails the build.
    assert not should_fail_diff(diff, Severity.INFO, True)


def test_only_new_findings_count_against_fail_on(risky: Evaluation) -> None:
    # The finding already existed before, so --fail-on must not trip on it.
    assert not should_fail_diff(diff_evaluations(risky, risky), Severity.INFO, False)


def test_cli_diff_exit_codes(risky: Evaluation, tmp_path: Path) -> None:
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(_emptied(risky).model_dump_json(), encoding="utf-8")
    new.write_text(risky.model_dump_json(), encoding="utf-8")
    out = tmp_path / "diff.json"

    assert main(["diff", str(old), str(new), "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["new_findings"]
    assert main(["diff", str(old), str(new), "-o", str(out), "--fail-on", "info"]) == 1
    assert main(["diff", str(old), str(new), "-o", str(out), "--fail-on-new-capability"]) == 1
    assert main(["diff", str(new), str(old), "-o", str(out), "--fail-on", "info"]) == 0


def test_cli_diff_rejects_bad_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    assert main(["diff", str(bad), str(bad)]) == 2
    assert "not a valid evaluation" in capsys.readouterr().err


def test_markdown_renders_hostile_text_inertly(risky: Evaluation) -> None:
    hostile = risky.findings[0].model_copy(update={"message": "[click](http://evil) <b>x</b>"})
    diff = diff_evaluations(_emptied(risky), risky.model_copy(update={"findings": [hostile]}))
    text = render_markdown(diff)
    assert "`[click](http://evil) <b>x</b>`" in text
    assert text.startswith("# agent-capmap diff")

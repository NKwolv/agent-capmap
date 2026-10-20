"""Golden-file tests: every scenario fixture produces exactly the expected findings."""

import ast
import json
import os
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.baseline import Baseline, create_baseline, load_baseline
from agentcapmap.findings import Evaluation
from agentcapmap.policy import evaluate, load_policy
from tests.scenarios import FIXTURES, SCENARIOS, load_scenario

UPDATE_GOLDEN = os.environ.get("AGENTCAPMAP_UPDATE_GOLDEN") == "1"

# The intent of each scenario, stated independently of the golden files.
EXPECTED_RULES = {
    "clean": set(),
    "trifecta": {"CAP-001"},
    "exec-injection": {"CAP-002", "CAP-003"},
    "no-approval-destructive": {"CAP-003"},
    "poisoned-description": {"CAP-008"},
    "overscoped-token": {"CAP-005", "CAP-007"},
    "rug-pull": {"CAP-006", "CAP-008"},
    "shadowing": {"CAP-009"},
}


def _baseline(name: str) -> Baseline | None:
    path = FIXTURES / name / "baseline.json"
    return load_baseline(path) if path.is_file() else None


def _evaluate(name: str) -> Evaluation:
    return evaluate(load_scenario(name), load_policy(), _baseline(name))


def _golden_view(evaluation: Evaluation) -> dict[str, Any]:
    """Everything that matters, minus policy prose that may be reworded freely."""
    data = evaluation.model_dump(mode="json")
    for finding in data["findings"]:
        finding.pop("message")
        finding.pop("maps_to")
    return {
        "findings": data["findings"],
        "not_assessed": data["not_assessed"],
        "skipped_rules": data["skipped_rules"],
        "summary": data["summary"],
    }


def test_every_section_7_scenario_exists() -> None:
    assert set(SCENARIOS) == set(EXPECTED_RULES)


@pytest.mark.parametrize("name", SCENARIOS)
def test_golden_findings(name: str) -> None:
    actual = _golden_view(_evaluate(name))
    golden = FIXTURES / name / "expected.json"
    if UPDATE_GOLDEN:
        golden.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8")
    assert actual == json.loads(golden.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario_triggers_exactly_its_rules(name: str) -> None:
    assert {f.rule_id for f in _evaluate(name).findings} == EXPECTED_RULES[name]


def test_clean_fixture_has_no_critical_or_high_findings() -> None:
    evaluation = _evaluate("clean")
    assert evaluation.summary["critical"] == 0
    assert evaluation.summary["high"] == 0
    assert evaluation.findings == []
    # The unclassified tool is reported, not silently treated as safe or as worst-case.
    assert [(n.server, n.tool) for n in evaluation.not_assessed] == [("clock", "convert_time")]


def test_every_finding_carries_evidence() -> None:
    for name in SCENARIOS:
        for finding in _evaluate(name).findings:
            assert finding.agent_id and finding.servers, (name, finding.rule_id)
            assert finding.evidence, (name, finding.rule_id)
            assert finding.location is not None and finding.location.line, (name, finding.rule_id)
            for ev in finding.evidence:
                assert ev.matched, (name, finding.rule_id)
                if ev.tool is not None and finding.rule_id not in ("CAP-009",):
                    assert ev.phrases, (name, finding.rule_id, ev)


def test_trifecta_evidence_names_each_leg() -> None:
    (finding,) = _evaluate("trifecta").findings
    by_tool = {(e.server, e.tool): e for e in finding.evidence}
    assert by_tool[("github", "list_issues")].phrases == {
        "untrusted_input": "including issues opened by anyone"
    }
    assert by_tool[("github", "get_file_contents")].matched == {"data_access": "private_read"}
    assert by_tool[("mailer", "send_email")].matched == {"egress": "external"}
    assert finding.tools == ["github/get_file_contents", "github/list_issues", "mailer/send_email"]


def test_rug_pull_baseline_matches_the_pre_change_definitions() -> None:
    regenerated = create_baseline(load_scenario("rug-pull", baseline_tools=True))
    assert regenerated == _baseline("rug-pull")
    (finding,) = [f for f in _evaluate("rug-pull").findings if f.rule_id == "CAP-006"]
    assert finding.details["changed"] == ["search_notes"]
    assert finding.details["added"] == ["export_notes"]
    assert finding.details["removed"] == []


def test_hash_rule_is_skipped_without_a_baseline() -> None:
    evaluation = evaluate(load_scenario("rug-pull"), load_policy(), None)
    assert "CAP-006" not in {f.rule_id for f in evaluation.findings}
    assert [s.rule_id for s in evaluation.skipped_rules] == ["CAP-006"]


def test_rule_engine_never_imports_the_llm() -> None:
    """Design rule 1: risk decisions are deterministic code, never the LLM."""
    src = Path(__file__).resolve().parents[1] / "src" / "agentcapmap"
    engine_files = [
        *(src / "policy").glob("*.py"),
        *(src / "graph").glob("*.py"),
        src / "baseline.py",
        src / "findings.py",
    ]
    for path in engine_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                assert not module.startswith(("anthropic", "agentcapmap.classify")), (
                    f"{path.name} imports {module}"
                )

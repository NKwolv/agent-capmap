"""Evaluation harness: metric math, label validation, rule agreement, planted recall."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentcapmap.enumerate.hashing import tool_definition_hash
from agentcapmap.evaluation import (
    UNCLASSIFIED,
    EvalDataError,
    LabeledServer,
    axis_metrics,
    fixture_inventory,
    label_manifest,
    load_labeled_servers,
    planted_recall,
    rule_agreement,
    score_classifier,
    truth_classification,
)
from agentcapmap.models import ClassificationStatus, ToolClassification, ToolDefinition, ToolTags
from agentcapmap.policy import load_policy
from agentcapmap.taxonomy import DEFAULTS
from tests.scenarios import FIXTURES


def _tool(name: str, description: str, **tags: Any) -> dict[str, Any]:
    schema = {"type": "object"}
    return {
        "name": name,
        "description": description,
        "input_schema": schema,
        "definition_hash": tool_definition_hash(name, description, schema),
        "label": {"tags": {**DEFAULTS, **tags}, "evidence": {}, "suspicious": False, "notes": ""},
    }


def _server(
    server_id: str, tools: list[dict[str, Any]], status: str = "reviewed"
) -> dict[str, Any]:
    return {
        "id": server_id,
        "category": "test",
        "source": f"npm:{server_id}",
        "version": "1.0.0",
        "captured": {},
        "labeling": {"status": status, "labeled_by": "tester"},
        "tools": tools,
    }


SERVERS = {
    "issues": _server("issues", [_tool("list_issues", "List issues", untrusted_input=True)]),
    "files": _server("files", [_tool("read_file", "Read a file", data_access="private_read")]),
    "mail": _server("mail", [_tool("send_email", "Send email", egress="external")]),
    "clock": _server("clock", [_tool("now", "Current time")]),
}
CATALOG = {sid: {"id": sid, "command": "npx", "args": ["-y", f"{sid}@1.0.0"]} for sid in SERVERS}


def _labeled() -> dict[str, LabeledServer]:
    return {k: LabeledServer.model_validate(v) for k, v in SERVERS.items()}


def _prediction(tags: dict[str, Any] | None) -> ToolClassification:
    if tags is None:
        return ToolClassification(
            status=ClassificationStatus.UNCLASSIFIED,
            error="x",
            taxonomy_version="1",
            prompt_version="1",
        )
    return ToolClassification(
        status=ClassificationStatus.CLASSIFIED,
        tags=ToolTags(**{**DEFAULTS, **tags}),
        confidence=0.9,
        taxonomy_version="1",
        prompt_version="1",
    )


def _perfect() -> dict[str, ToolClassification]:
    return {
        t.definition_hash: truth_classification(t.label)
        for s in _labeled().values()
        for t in s.tools
        if t.label
    }


# --- metric math -------------------------------------------------------------------------


def test_axis_metrics_hand_computed() -> None:
    # truth/predicted for egress: 2 right external, 1 external missed, 1 false external,
    # 1 none right, 1 unclassified.
    pairs = [
        ("external", "external"),
        ("external", "external"),
        ("external", "none"),
        ("none", "external"),
        ("none", "none"),
        ("internal", UNCLASSIFIED),
    ]
    m = axis_metrics("egress", pairs)
    assert m.accuracy == pytest.approx(3 / 6)
    ext = m.per_value["external"]
    assert ext.precision == pytest.approx(2 / 3)
    assert ext.recall == pytest.approx(2 / 3)
    assert ext.support == 3
    # Detection: non-default truth {ext, ext, ext, internal}; predicted non-default hits 2,
    # false alarm 1 (none->external), misses 2 (ext->none, internal->unclassified).
    assert m.detection.precision == pytest.approx(2 / 3)
    assert m.detection.recall == pytest.approx(2 / 4)
    assert m.confusion["internal"][UNCLASSIFIED] == 1


def test_perfect_classifier_scores_100() -> None:
    report = score_classifier(_labeled().values(), _perfect())
    assert report.exact_match == 1.0
    assert report.unclassified == 0
    assert report.disagreements == []
    assert all(m.accuracy == 1.0 for m in report.axes.values())


def test_missing_and_wrong_predictions_are_counted() -> None:
    labeled = _labeled()
    predictions = _perfect()
    predictions[labeled["mail"].tools[0].definition_hash] = _prediction({"egress": "none"})
    predictions.pop(labeled["files"].tools[0].definition_hash)
    report = score_classifier(labeled.values(), predictions)
    assert report.tools == 4
    assert report.unclassified == 1
    assert report.exact_match == pytest.approx(2 / 4)
    wrong = {(d.server, d.axis, d.truth, d.predicted) for d in report.disagreements}
    assert ("mail", "egress", "external", "none") in wrong
    assert ("files", "data_access", "private_read", UNCLASSIFIED) in wrong


# --- label files -------------------------------------------------------------------------


def _write(tmp_path: Path, data: dict[str, Any], name: str = "s.json") -> Path:
    (tmp_path / name).write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


def test_load_and_manifest(tmp_path: Path) -> None:
    for sid, data in SERVERS.items():
        _write(tmp_path, data, f"{sid}.json")
    assert [s.id for s in load_labeled_servers(tmp_path)] == ["clock", "files", "issues", "mail"]
    manifest = label_manifest(tmp_path)
    assert set(manifest) == {"clock.json", "files.json", "issues.json", "mail.json"}


def test_edited_definition_is_rejected(tmp_path: Path) -> None:
    data = json.loads(json.dumps(SERVERS["mail"]))
    data["tools"][0]["description"] = "Send email (edited after capture)"
    with pytest.raises(EvalDataError, match="was edited"):
        load_labeled_servers(_write(tmp_path, data))


def test_labeled_file_with_missing_label_is_rejected(tmp_path: Path) -> None:
    data = json.loads(json.dumps(SERVERS["mail"]))
    data["tools"][0]["label"] = None
    with pytest.raises(EvalDataError, match="has no label"):
        load_labeled_servers(_write(tmp_path, data))


def test_unknown_fields_and_bad_tags_are_rejected(tmp_path: Path) -> None:
    data = json.loads(json.dumps(SERVERS["mail"]))
    data["tools"][0]["label"]["tags"]["egress"] = "everywhere"
    with pytest.raises(ValidationError):
        load_labeled_servers(_write(tmp_path, data))
    data = json.loads(json.dumps(SERVERS["mail"]))
    data["extra"] = True
    with pytest.raises(ValidationError):
        load_labeled_servers(_write(tmp_path, data, "x.json"))


# --- rule agreement ------------------------------------------------------------------------

AGENTS = {
    "trifecta": ["issues", "files", "mail"],
    "quiet": ["clock"],
    "missing": ["clock", "not-captured"],
}


def test_rule_agreement_perfect_and_degraded() -> None:
    labeled, policy = _labeled(), load_policy()
    perfect = rule_agreement(AGENTS, labeled, CATALOG, _perfect(), policy)
    assert perfect.agents == 2  # "missing" skipped
    assert (perfect.precision, perfect.recall) == (1.0, 1.0)
    assert (perfect.clean_agents, perfect.false_alarm_agents) == (1, 0)
    assert {a["agent"]: a["truth"] for a in perfect.per_agent}["trifecta"] == ["CAP-001"]

    # The classifier misses the email egress: the trifecta is no longer detected...
    missed = _perfect()
    missed[labeled["mail"].tools[0].definition_hash] = _prediction({})
    degraded = rule_agreement(AGENTS, labeled, CATALOG, missed, policy)
    assert degraded.recall == 0.0
    # ...and over-tagging the clock as host execution is a false alarm on a clean agent.
    noisy = _perfect()
    noisy[labeled["clock"].tools[0].definition_hash] = _prediction(
        {"execution": "host", "untrusted_input": True}
    )
    alarm = rule_agreement(AGENTS, labeled, CATALOG, noisy, policy)
    assert alarm.false_positive_rate == 1.0


# --- planted recall ----------------------------------------------------------------------


def _fixture_oracle() -> dict[str, dict[str, Any]]:
    """definition_hash -> (tags, suspicious) from the fixtures' own tools.json."""
    oracle: dict[str, dict[str, Any]] = {}
    for tools_file in FIXTURES.glob("*/tools.json"):
        for server in json.loads(tools_file.read_text(encoding="utf-8"))["servers"].values():
            for t in server["tools"]:
                schema = t.get("inputSchema", {"type": "object"})
                h = tool_definition_hash(t["name"], t.get("description", ""), schema)
                oracle[h] = t
    return oracle


def test_planted_recall_perfect_and_blind_classifiers() -> None:
    oracle = _fixture_oracle()

    def perfect(tool: ToolDefinition) -> ToolClassification:
        spec = oracle[tool.definition_hash]
        result = _prediction(spec.get("tags", {}))
        if spec.get("suspicious"):
            from agentcapmap.models import SuspiciousDescription

            result.suspicious_description = SuspiciousDescription(flag=True, reason="x")
        return result

    def blind(tool: ToolDefinition) -> ToolClassification:
        return _prediction({})

    policy = load_policy()
    assert planted_recall(FIXTURES, perfect, policy).recall == 1.0
    assert planted_recall(FIXTURES, blind, policy).recall == 0.0


def test_fixture_inventory_uses_the_classifier_not_the_fixture_tags() -> None:
    calls: list[str] = []

    def spy(tool: ToolDefinition) -> ToolClassification:
        calls.append(tool.name)
        return _prediction({})

    inventory = fixture_inventory(FIXTURES / "trifecta", spy)
    assert sorted(calls) == ["get_file_contents", "list_issues", "send_email"]
    assert inventory.agents[0].servers[0].enumeration is not None


def test_run_eval_end_to_end_offline(tmp_path: Path) -> None:
    """The one-command runner works on the real label set without network or API key."""
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            str(root / "eval" / "run_eval.py"),
            "--offline",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--out",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    results = (tmp_path / "results.md").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    # Empty cache: nothing classified, so the run is honest about it.
    assert data["classifier"]["unclassified"] == data["classifier"]["tools"]
    assert data["provisional"] is True
    assert "PROVISIONAL" in results
    assert "_To be written by a person" in results

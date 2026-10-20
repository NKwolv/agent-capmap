"""Report formats (SARIF, Markdown), exit codes, and output-injection resistance."""

import hashlib
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft4Validator

from agentcapmap.cli import main
from agentcapmap.findings import Evaluation, Severity
from agentcapmap.policy import evaluate, load_policy, parse_policy
from agentcapmap.report import Format, render, should_fail
from agentcapmap.report.sarif import FINGERPRINT_KEY, safe_uri
from agentcapmap.report.sarif import render as render_sarif
from tests.scenarios import FIXTURES, SCENARIOS, load_scenario

SARIF_SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
SARIF_SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"


def _evaluation(name: str) -> Evaluation:
    baseline_path = FIXTURES / name / "baseline.json"
    from agentcapmap.baseline import load_baseline

    baseline = load_baseline(baseline_path) if baseline_path.is_file() else None
    return evaluate(load_scenario(name), load_policy(), baseline)


@pytest.fixture(scope="module")
def sarif_validator() -> Draft4Validator:
    raw = SARIF_SCHEMA_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SARIF_SCHEMA_SHA256, "vendored schema modified"
    return Draft4Validator(json.loads(raw))


# --- SARIF ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", SCENARIOS)
def test_sarif_validates_against_the_official_schema(
    name: str, sarif_validator: Draft4Validator
) -> None:
    sarif = json.loads(render(_evaluation(name), Format.SARIF))
    errors = sorted(sarif_validator.iter_errors(sarif), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:5]]


def test_sarif_meets_github_code_scanning_expectations() -> None:
    evaluation = _evaluation("trifecta")
    sarif = render_sarif(evaluation)
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [f"CAP-00{i}" for i in range(1, 10)]
    for rule in rules:
        assert float(rule["properties"]["security-severity"]) >= 0
        assert "security" in rule["properties"]["tags"]
    (result,) = run["results"]
    assert result["ruleId"] == "CAP-001"
    assert rules[result["ruleIndex"]]["id"] == "CAP-001"
    assert result["level"] == "error"
    assert rules[result["ruleIndex"]]["properties"]["security-severity"] == "9.5"
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"] == {"uri": "mcp.json", "uriBaseId": "%SRCROOT%"}
    assert location["region"] == {"startLine": 3}
    assert result["partialFingerprints"][FINGERPRINT_KEY] == evaluation.findings[0].fingerprint
    # The second server is a related location on its own line.
    (related,) = result["relatedLocations"]
    assert related["physicalLocation"]["region"]["startLine"] == 14
    assert "including issues opened by anyone" in result["message"]["text"]


def test_sarif_levels_by_severity() -> None:
    results = render_sarif(_evaluation("overscoped-token"))["runs"][0]["results"]
    assert {r["ruleId"]: r["level"] for r in results} == {"CAP-005": "error", "CAP-007": "warning"}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("mcp.json", "mcp.json"),
        ("configs/team a/.mcp.json", "configs/team%20a/.mcp.json"),
        ("/etc/passwd", None),
        ("C:/Users/x/mcp.json", None),
        ("C:\\Users\\x\\mcp.json", None),
        ("../outside/mcp.json", None),
        ("a/../../b", None),
        ("a//b", None),
        ("./mcp.json", None),
        ("file:///etc/passwd", None),
        ("https://evil.example/x", None),
        ("", None),
    ],
)
def test_safe_uri(path: str, expected: str | None) -> None:
    assert safe_uri(path) == expected


def test_findings_outside_the_repo_are_omitted_with_a_notification() -> None:
    evaluation = _evaluation("trifecta")
    finding = evaluation.findings[0]
    assert finding.location is not None
    finding.location = finding.location.model_copy(update={"path": "/home/u/.cursor/mcp.json"})
    finding.server_locations = [
        loc.model_copy(update={"path": "/home/u/.cursor/mcp.json"})
        for loc in finding.server_locations
    ]
    run = render_sarif(evaluation)["runs"][0]
    assert run["results"] == []
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert any(n["descriptor"]["id"] == "result-omitted" for n in notes)
    assert "/home/u" not in json.dumps(run)


def test_not_assessed_and_skipped_rules_are_reported_in_sarif() -> None:
    notes = render_sarif(_evaluation("clean"))["runs"][0]["invocations"][0][
        "toolExecutionNotifications"
    ]
    assert {n["descriptor"]["id"] for n in notes} == {"not-assessed", "rule-skipped"}


# --- Markdown ------------------------------------------------------------------------

HOSTILE = (
    "](https://evil.example/phish) <img src=x onerror=alert(1)> **bold** "
    "\x1b[2J\u202egnirts desrever | `tick` ``double`` \n# heading"
)


def _strip_code_spans(markdown: str) -> str:
    """Remove inline code spans (any fence length), leaving the markup around them."""
    out, i = [], 0
    while i < len(markdown):
        if markdown[i] == "`":
            run = re.match(r"`+", markdown[i:]).group(0)  # type: ignore[union-attr]
            end = markdown.find(run, i + len(run))
            while end != -1 and (markdown[end + len(run) : end + len(run) + 1] == "`"):
                end = markdown.find(run, end + 1)
            if end == -1:
                out.append(markdown[i:])
                break
            i = end + len(run)
            continue
        out.append(markdown[i])
        i += 1
    return "".join(out)


def _hostile_evaluation() -> Evaluation:
    inventory = load_scenario("trifecta")
    tool = inventory.agents[0].servers[0].enumeration.tools[0]  # type: ignore[union-attr]
    tool.name = "list_issues" + HOSTILE
    assert tool.classification is not None
    tool.classification.evidence["untrusted_input"] = HOSTILE
    policy = parse_policy(
        "version: 1\ntaxonomy_version: '1'\nrules:\n"
        "  - id: T-1\n    severity: critical\n"
        f"    message: {json.dumps(HOSTILE)}\n"
        "    maps_to: ['OWASP-LLM01']\n"
        "    when_agent_has_any: [{untrusted_input: true}]\n",
        "hostile.yaml",
    )
    return evaluate(inventory, policy)


def test_markdown_neutralizes_hostile_text() -> None:
    markdown = render(_hostile_evaluation(), Format.MARKDOWN)
    outside_code = _strip_code_spans(markdown)
    for needle in ("<img", "](https://evil", "**bold**", "\x1b", "\u202e", "# heading"):
        assert needle not in outside_code, needle
    assert "\x1b" not in markdown and "\u202e" not in markdown
    # The hostile text is still visible to the reader, just inert.
    assert "onerror=alert(1)" in markdown


def test_markdown_tables_keep_their_shape_with_hostile_cells() -> None:
    markdown = render(_hostile_evaluation(), Format.MARKDOWN)
    for line in markdown.splitlines():
        if line.startswith("| ") and "Matched" not in line and "---" not in line:
            unescaped = len(re.findall(r"(?<!\\)\|", line))
            assert unescaped - 1 in (2, 4), line  # 2 or 4 columns, never more


def test_markdown_report_content() -> None:
    markdown = render(_evaluation("trifecta"), Format.MARKDOWN)
    assert markdown.startswith("# agent-capmap report\n")
    assert "| Critical | 1 |" in markdown
    assert "`CAP-001`" in markdown
    assert "`untrusted_input: including issues opened by anyone`" in markdown
    assert "## Capabilities by agent" in markdown
    clean = render(_evaluation("clean"), Format.MARKDOWN)
    assert "No findings." in clean
    assert "[!WARNING]" in clean and "not assessed" in clean


# --- exit codes ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [(Severity.CRITICAL, True), (Severity.HIGH, True), (Severity.INFO, True), (None, False)],
)
def test_should_fail_thresholds(fail_on: Severity | None, expected: bool) -> None:
    assert should_fail(_evaluation("trifecta"), fail_on) is expected


def test_should_fail_below_threshold_and_not_assessed() -> None:
    shadowing = _evaluation("shadowing")  # one medium finding
    assert not should_fail(shadowing, Severity.HIGH)
    assert should_fail(shadowing, Severity.MEDIUM)
    clean = _evaluation("clean")
    assert not should_fail(clean, Severity.INFO)
    assert should_fail(clean, None, fail_on_not_assessed=True)


def _inventory_file(tmp_path: Path, name: str) -> str:
    path = tmp_path / f"{name}.json"
    path.write_text(load_scenario(name).model_dump_json(), encoding="utf-8")
    return str(path)


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    trifecta, clean = _inventory_file(tmp_path, "trifecta"), _inventory_file(tmp_path, "clean")
    out = tmp_path / "out.sarif"
    assert (
        main(["evaluate", trifecta, "--format", "sarif", "-o", str(out), "--fail-on", "high"]) == 1
    )
    assert json.loads(out.read_text())["version"] == "2.1.0"  # written before failing
    assert main(["evaluate", trifecta, "--fail-on", "none"]) == 0
    assert main(["evaluate", clean, "--fail-on", "info"]) == 0
    assert main(["evaluate", clean, "--fail-on-not-assessed"]) == 1
    capsys.readouterr()
    assert main(["scan", ".", "--format", "sarif"]) == 2
    assert "need --evaluate" in capsys.readouterr().err


def test_cli_report_rerenders_a_saved_evaluation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evaluation = tmp_path / "evaluation.json"
    assert main(["evaluate", _inventory_file(tmp_path, "trifecta"), "-o", str(evaluation)]) == 0
    assert main(["report", str(evaluation), "--format", "markdown"]) == 0
    assert "| Critical | 1 |" in capsys.readouterr().out
    assert main(["report", str(evaluation), "--fail-on", "critical"]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text('{"findings": 1}')
    assert main(["report", str(bad)]) == 2


def test_python_sources_are_ascii_only() -> None:
    """Invisible or bidi characters in source are a "Trojan Source" risk; keep code ASCII."""
    root = Path(__file__).resolve().parents[1]
    offenders = [
        f"{path.relative_to(root)}:{number}"
        for path in [*(root / "src").rglob("*.py"), *(root / "tests").rglob("*.py")]
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1)
        if any(ord(ch) > 127 for ch in line)
    ]
    assert offenders == []

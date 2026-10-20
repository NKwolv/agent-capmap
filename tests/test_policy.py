"""Policy loading (hostile-input handling) and rule-engine semantics."""

import json
import time
from pathlib import Path

import pytest

from agentcapmap.findings import Severity
from agentcapmap.models import Agent, Inventory
from agentcapmap.policy import DEFAULT_POLICY_NAME, PolicyError, evaluate, load_policy, parse_policy
from agentcapmap.taxonomy import AXES, axis_values, data_file
from tests.scenarios import load_scenario

MINIMAL = """
version: 1
taxonomy_version: "1"
rules:
  - id: T-1
    severity: high
    when_agent_has_any:
      - egress: external
    message: test
"""


def _policy(rules: str, extra: str = "") -> str:
    return f'version: 1\ntaxonomy_version: "1"\n{extra}rules:\n{rules}'


# --- loading: hostile input ------------------------------------------------------------


def test_default_policy_loads_and_defines_the_nine_rules() -> None:
    policy = load_policy()
    assert policy.info.source == DEFAULT_POLICY_NAME
    assert [r.id for r in policy.rules] == [f"CAP-00{i}" for i in range(1, 10)]
    assert {r.id: r.severity for r in policy.rules}["CAP-001"] is Severity.CRITICAL
    assert len(policy.info.sha256) == 64


def test_yaml_aliases_are_rejected() -> None:
    bomb = """
version: 1
taxonomy_version: "1"
a: &a ["x", "x", "x", "x", "x", "x", "x", "x", "x"]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
rules: [*c]
"""
    with pytest.raises(PolicyError, match="anchors and aliases are not allowed"):
        parse_policy(bomb, "bomb.yaml")


def test_merge_keys_are_rejected() -> None:
    text = _policy(
        """
  - &base
    id: T-1
    severity: high
    message: m
    when_agent_has_any: [{egress: external}]
  - <<: *base
    id: T-2
"""
    )
    with pytest.raises(PolicyError, match="anchors and aliases"):
        parse_policy(text, "merge.yaml")


def test_duplicate_keys_are_rejected() -> None:
    text = _policy(
        """
  - id: T-1
    severity: low
    severity: critical
    message: m
    when_agent_has_any: [{egress: external}]
"""
    )
    with pytest.raises(PolicyError, match="duplicate key 'severity'"):
        parse_policy(text, "dupe.yaml")


@pytest.mark.parametrize(
    "payload",
    [
        "!!python/object/apply:os.system ['echo pwned']",
        "!!python/name:os.system",
        "!!binary aGVsbG8=",
    ],
)
def test_unsafe_yaml_tags_are_rejected(payload: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy(f"{MINIMAL}\nextra: {payload}\n", "tags.yaml")


def test_deep_flow_nesting_is_rejected_quickly() -> None:
    # PyYAML is super-linear in flow depth (8,000 brackets took ~50 s): reject up front.
    start = time.perf_counter()
    for opener in "[{":
        with pytest.raises(PolicyError, match="nested more than 32 levels"):
            parse_policy(opener * 200_000, "deep.yaml")
    assert time.perf_counter() - start < 1.0


def test_reasonable_flow_nesting_is_accepted() -> None:
    rule = (
        "  - {id: T-1, severity: low, message: m, when_agent_has_any: [{egress: [external]}]}"
        + chr(10)
    )
    assert parse_policy(_policy(rule), "p.yaml").rules[0].id == "T-1"


def test_invalid_yaml_reports_line_without_echoing_content() -> None:
    with pytest.raises(PolicyError, match=r"invalid YAML at line \d+") as exc:
        parse_policy("version: 1\nrules: [secret-value-xyz: :\n", "bad.yaml")
    assert "secret-value-xyz" not in str(exc.value)


@pytest.mark.parametrize(
    ("rules", "where"),
    [
        ("  - {id: T-1, severity: high, message: m, when_agent_has_any: [{egres: external}]}", ""),
        (
            "  - {id: T-1, severity: urgent, message: m, when_agent_has_any: [{egress: external}]}",
            "",
        ),
        (
            "  - {id: T-1, severity: high, message: m, when_agent_has_any: [{egress: everywhere}]}",
            "",
        ),
        ("  - {id: t-1, severity: high, message: m, when_agent_has_any: [{egress: external}]}", ""),
        ("  - {id: T-1, severity: high, message: m}", ""),
        ("  - {id: T-1, severity: high, message: m, when_server: {auth: maybe}}", ""),
        ("  - {id: T-1, severity: high, message: m, when_agent_has_any: [{}]}", ""),
        (
            "  - {id: T-1, severity: high, message: m, run: rm -rf /, when_server: {remote: true}}",
            "",
        ),
    ],
)
def test_schema_violations_are_rejected(rules: str, where: str) -> None:
    with pytest.raises(PolicyError, match="invalid policy"):
        parse_policy(_policy(rules + "\n"), "p.yaml")


def test_unknown_top_level_field_and_bad_trusted_source() -> None:
    with pytest.raises(PolicyError, match="invalid policy"):
        parse_policy(MINIMAL + "include: /etc/passwd\n", "p.yaml")
    with pytest.raises(PolicyError, match="invalid policy at trusted_sources"):
        parse_policy(
            _policy(
                "  - {id: T-1, severity: low, message: m, when_server: {remote: true}}\n",
                'trusted_sources: ["ftp:evil"]\n',
            ),
            "p.yaml",
        )


def test_duplicate_rule_ids_and_contradictory_conditions() -> None:
    dupes = _policy(
        "  - {id: T-1, severity: low, message: m, when_server: {remote: true}}\n"
        "  - {id: T-1, severity: low, message: m, when_server: {remote: false}}\n"
    )
    with pytest.raises(PolicyError, match="duplicate rule id"):
        parse_policy(dupes, "p.yaml")
    combo = _policy(
        "  - {id: T-1, severity: low, message: m, when_hash_changed: true,"
        " when_agent_has_any: [{egress: external}]}\n"
    )
    with pytest.raises(PolicyError, match="cannot be combined"):
        parse_policy(combo, "p.yaml")


def test_wrong_taxonomy_version_is_rejected() -> None:
    with pytest.raises(PolicyError, match="invalid policy at taxonomy_version"):
        parse_policy(MINIMAL.replace('taxonomy_version: "1"', 'taxonomy_version: "2"'), "p.yaml")


def test_oversized_and_unreadable_policy_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentcapmap.policy.loader._MAX_POLICY_BYTES", 64)
    big = tmp_path / "big.yaml"
    big.write_text(MINIMAL)
    with pytest.raises(PolicyError, match="larger than 64 bytes"):
        load_policy(big)
    with pytest.raises(PolicyError, match="cannot read policy"):
        load_policy(tmp_path / "missing.yaml")
    binary = tmp_path / "bin.yaml"
    binary.write_bytes(b"\xff\xfe\x00")
    monkeypatch.setattr("agentcapmap.policy.loader._MAX_POLICY_BYTES", 10_000)
    with pytest.raises(PolicyError, match="not UTF-8"):
        load_policy(binary)


def test_policy_schema_values_match_the_taxonomy() -> None:
    schema = json.loads(data_file("schemas", "policy.schema.json"))
    defs = schema["$defs"]
    for axis in AXES:
        if axis == "untrusted_input":
            continue
        assert defs[axis]["oneOf"][0]["enum"] == axis_values(axis), axis


# --- engine semantics ----------------------------------------------------------------


def _rules_of(rule_yaml: str, name: str = "trifecta", extra: str = "") -> set[str]:
    policy = parse_policy(_policy(rule_yaml, extra), "test.yaml")
    return {f.rule_id for f in evaluate(load_scenario(name), policy).findings}


def test_has_all_is_satisfied_across_different_tools_and_servers() -> None:
    rule = (
        "  - id: T-1\n    severity: high\n    message: m\n    when_agent_has_all:\n"
        "      - untrusted_input: true\n      - egress: external\n"
    )
    assert _rules_of(rule) == {"T-1"}


def test_fields_in_one_predicate_must_match_on_the_same_tool() -> None:
    # No single trifecta tool is both untrusted_input and external egress.
    rule = (
        "  - id: T-1\n    severity: high\n    message: m\n    when_agent_has_any:\n"
        "      - untrusted_input: true\n        egress: external\n"
    )
    assert _rules_of(rule) == set()


def test_server_filter_restricts_which_tools_count() -> None:
    rule = (
        "  - id: T-1\n    severity: high\n    message: m\n"
        "    when_server: {transport: http}\n"
        "    when_agent_has_any: [{egress: external}]\n"
    )
    assert _rules_of(rule) == set()  # the email server is stdio


def test_server_filter_list_means_any_of() -> None:
    rule = (
        "  - id: T-1\n    severity: low\n    message: m\n"
        "    when_server: [{version_pinned: unpinned}, {source_trust: untrusted}]\n"
    )
    assert _rules_of(rule) == set()  # pinned, and no trusted_sources configured
    assert _rules_of(rule, extra='trusted_sources: ["npm:@modelcontextprotocol/*"]\n') == {"T-1"}


def test_trusted_sources_make_matching_servers_trusted() -> None:
    rule = (
        "  - id: T-1\n    severity: low\n    message: m\n"
        "    when_server: {source_trust: untrusted}\n"
    )
    trusted = 'trusted_sources: ["docker:ghcr.io/github/github-mcp-server", "npm:@acme/*"]\n'
    assert _rules_of(rule, extra=trusted) == set()


def test_disabled_rules_are_reported_as_skipped() -> None:
    policy = parse_policy(
        _policy(
            "  - {id: T-1, severity: high, message: m, enabled: false,"
            " when_agent_has_any: [{egress: external}]}\n"
        ),
        "p.yaml",
    )
    evaluation = evaluate(load_scenario("trifecta"), policy)
    assert evaluation.findings == []
    assert [(s.rule_id, s.reason) for s in evaluation.skipped_rules] == [
        ("T-1", "disabled in policy")
    ]


def test_disabled_servers_are_ignored() -> None:
    inventory = load_scenario("trifecta")
    for server in inventory.agents[0].servers:
        if server.name == "mailer":
            server.disabled = True
    assert {f.rule_id for f in evaluate(inventory, load_policy()).findings} == set()


def test_unenumerated_servers_are_not_assessed_not_assumed_safe() -> None:
    inventory = load_scenario("trifecta")
    inventory.agents[0].servers[0].enumeration = None
    evaluation = evaluate(inventory, load_policy())
    assert {f.rule_id for f in evaluation.findings} == set()
    assert evaluation.not_assessed[0].reason.startswith("tools not enumerated")
    assert evaluation.summary["not_assessed"] == 1


def test_findings_are_deterministic_and_sorted() -> None:
    inventory = Inventory(agents=[*load_scenario("exec-injection").agents])
    first = evaluate(inventory, load_policy()).model_dump_json()
    second = evaluate(inventory, load_policy()).model_dump_json()
    assert first == second
    severities = [f["severity"] for f in json.loads(first)["findings"]]
    assert severities == ["critical", "high"]


def test_findings_are_per_agent() -> None:
    a = load_scenario("trifecta").agents[0]
    b = Agent(**{**a.model_dump(), "id": "other-agent"})
    b.servers = [s for s in a.servers if s.name == "github"]
    evaluation = evaluate(Inventory(agents=[a, b]), load_policy())
    # Only the agent that also has the mailer has the trifecta.
    assert [f.agent_id for f in evaluation.findings] == [a.id]


def test_capabilities_retain_provenance() -> None:
    (agent,) = evaluate(load_scenario("trifecta"), load_policy()).agents
    assert sorted(agent.capabilities) == [
        "data_access=private_read",
        "egress=external",
        "mutation=reversible_write",
        "untrusted_input=true",
    ]
    (ref,) = agent.capabilities["egress=external"]
    assert (ref.server, ref.tool, ref.evidence) == (
        "mailer",
        "send_email",
        "Send an email to any recipient address",
    )
    assert (agent.tools_total, agent.tools_assessed) == (3, 3)

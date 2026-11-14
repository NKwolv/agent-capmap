"""Cross-agent chain rules (when_agents_chain, CAP-012 and CAP-013)."""

from typing import Any

import pytest

from agentcapmap.enumerate.hashing import tool_definition_hash
from agentcapmap.findings import Evaluation
from agentcapmap.limits import MAX_CHAIN_AGENTS
from agentcapmap.models import (
    Agent,
    AuthHint,
    AuthMethod,
    ClassificationStatus,
    EnumerationResult,
    EnumerationStatus,
    Inventory,
    Server,
    SourceLocation,
    ToolClassification,
    ToolDefinition,
    ToolTags,
    Transport,
)
from agentcapmap.policy import PolicyError, evaluate, load_policy, parse_policy
from agentcapmap.report import markdown, sarif
from agentcapmap.taxonomy import DEFAULTS

UNTRUSTED = {"untrusted_input": True}
PRIVATE = {"data_access": "private_read"}
EGRESS = {"egress": "external"}
WRITE = {"mutation": "reversible_write"}
HOST_EXEC = {"execution": "host"}

NOTES = ["-y", "@acme/notes@1.0.0", "/shared/notes"]


def _tool(name: str, tags: dict[str, Any] | None) -> ToolDefinition:
    tool = ToolDefinition(name=name, definition_hash=tool_definition_hash(name, "", {}))
    if tags is not None:
        tool.classification = ToolClassification(
            status=ClassificationStatus.CLASSIFIED,
            tags=ToolTags(**{**DEFAULTS, **tags}),
            confidence=0.9,
            evidence=dict.fromkeys(tags, f"{name} evidence"),
            taxonomy_version="1",
            prompt_version="1",
        )
    return tool


def _server(name: str, args: list[str], tools: dict[str, dict[str, Any] | None]) -> Server:
    return Server(
        name=name,
        transport=Transport.STDIO,
        command="npx",
        args=args,
        auth=AuthHint(method=AuthMethod.NONE),
        location=SourceLocation(path=f"{name}.json", line=3),
        enumeration=EnumerationResult(
            status=EnumerationStatus.OK, tools=[_tool(n, t) for n, t in tools.items()]
        ),
    )


def _agent(agent_id: str, *servers: Server) -> Agent:
    return Agent(id=agent_id, client="generic", config_path=f"{agent_id}.json", servers=[*servers])


def _fetch() -> Server:
    return _server("fetch", ["-y", "@acme/fetch@1.0.0"], {"fetch": UNTRUSTED})


def _mailer() -> Server:
    return _server("mailer", ["-y", "@acme/mailer@1.0.0"], {"send_email": EGRESS})


def _notes(name: str = "notes", *, write: bool = False, read: bool = False) -> Server:
    tools: dict[str, dict[str, Any] | None] = {}
    if write:
        tools["write_note"] = WRITE
    if read:
        tools["read_note"] = PRIVATE
    return _server(name, NOTES, tools)


def _evaluate(*agents: Agent) -> Evaluation:
    return evaluate(Inventory(agents=[*agents]), load_policy())


def _rules(evaluation: Evaluation) -> list[str]:
    return [f.rule_id for f in evaluation.findings]


def _web_and_mail() -> tuple[Agent, Agent]:
    """The basic chain: `web` reads the internet and writes notes; `mail` reads them and emails."""
    web = _agent("web", _fetch(), _notes(write=True))
    mail = _agent("mail", _notes("team-notes", read=True), _mailer())
    return web, mail


def test_trifecta_split_across_two_agents_is_found() -> None:
    web, mail = _web_and_mail()
    evaluation = _evaluate(web, mail)
    assert _rules(evaluation) == ["CAP-012"]  # and no single-agent CAP-001
    (finding,) = evaluation.findings
    assert finding.agent_id == "web"  # where the injected instruction enters
    assert finding.details["agents"] == ["web", "mail"]
    assert finding.details["links"] == [
        {
            "from": "web",
            "to": "mail",
            "written_with": "notes/write_note",
            "read_with": "team-notes/read_note",
        }
    ]
    assert finding.tools == [
        "fetch/fetch",
        "mailer/send_email",
        "notes/write_note",
        "team-notes/read_note",
    ]
    by_agent = {(ev.agent_id, ev.tool) for ev in finding.evidence}
    assert ("web", "fetch") in by_agent and ("mail", "send_email") in by_agent
    assert all(ev.agent_id for ev in finding.evidence)


def test_content_only_flows_from_writer_to_reader() -> None:
    # `web` can read the shared notes but not write them, so nothing it ingests can
    # reach `mail`; `mail` writing notes does not help an attacker who controls `web`.
    web = _agent("web", _fetch(), _notes(read=True))
    mail = _agent("mail", _notes(write=True, read=True), _mailer())
    assert _rules(_evaluate(web, mail)) == []


def test_private_data_upstream_of_the_entry_point_does_not_count() -> None:
    # The agent holding the private data cannot be instructed by the injected one.
    vault = _agent(
        "vault", _server("db", ["-y", "@acme/db@1.0.0"], {"query": PRIVATE}), _notes(write=True)
    )
    web = _agent("web", _fetch(), _server("notes", NOTES, {"list_notes": UNTRUSTED}), _mailer())
    assert _rules(_evaluate(vault, web)) == []


def test_servers_with_different_launch_arguments_are_not_the_same_store() -> None:
    web = _agent("web", _fetch(), _notes(write=True))
    other = _server("notes", ["-y", "@acme/notes@1.0.0", "/somewhere/else"], {"read_note": PRIVATE})
    mail = _agent("mail", other, _mailer())
    assert _rules(_evaluate(web, mail)) == []


def test_an_agent_with_everything_is_reported_by_the_per_agent_rule_only() -> None:
    solo = _agent("solo", _fetch(), _notes(write=True, read=True), _mailer())
    mail = _agent("mail", _notes(read=True), _mailer())
    assert _rules(_evaluate(solo, mail)) == ["CAP-001"]


def test_chain_can_start_with_two_steps_on_the_entry_agent() -> None:
    # `web` reads untrusted content and private data, and hands it to the agent with egress.
    web = _agent(
        "web",
        _fetch(),
        _server("db", ["-y", "@acme/db@1.0.0"], {"query": PRIVATE}),
        _notes(write=True),
    )
    mail = _agent("mail", _notes(read=True), _mailer())
    (finding,) = _evaluate(web, mail).findings
    assert finding.rule_id == "CAP-012"
    assert finding.details["agents"] == ["web", "mail"]


def test_chain_through_a_relay_agent() -> None:
    board = ["-y", "@acme/board@2.0.0"]
    web = _agent("web", _fetch(), _notes(write=True))
    relay = _agent("relay", _notes(read=True), _server("board", board, {"post": WRITE}))
    mail = _agent(
        "mail",
        _server("board", board, {"read_posts": UNTRUSTED}),
        _server("crm", ["-y", "@acme/crm@1.0.0"], {"lookup": PRIVATE}),
        _mailer(),
    )
    evaluation = _evaluate(web, relay, mail)
    chained = [f for f in evaluation.findings if f.rule_id == "CAP-012"]
    # `mail` alone already has the trifecta (it reads untrusted posts): that is CAP-001.
    assert "CAP-001" in _rules(evaluation)
    # `web` is a second way in, through the relay; `relay` (which reads the notes as
    # private data, so is no entry point itself) only passes content on.
    assert [f.agent_id for f in chained] == ["web"]
    assert chained[0].details["agents"] == ["web", "relay", "mail"]
    assert [(link["from"], link["to"]) for link in chained[0].details["links"]] == [
        ("web", "relay"),
        ("relay", "mail"),
    ]


def test_untrusted_content_reaching_host_execution_in_another_agent() -> None:
    web = _agent("web", _fetch(), _notes(write=True))
    dev = _agent(
        "dev", _notes(read=True), _server("shell", ["-y", "@acme/shell@1.0.0"], {"run": HOST_EXEC})
    )
    evaluation = _evaluate(web, dev)
    assert "CAP-013" in _rules(evaluation)
    assert "CAP-002" not in _rules(evaluation)


def test_disabled_servers_and_unclassified_tools_make_no_link() -> None:
    web, mail = _web_and_mail()
    web.servers[1].disabled = True
    assert _rules(_evaluate(web, mail)) == []

    web, mail = _web_and_mail()
    web.servers[1] = _server("notes", NOTES, {"write_note": None})  # not classified
    evaluation = _evaluate(web, mail)
    assert _rules(evaluation) == []
    assert any(na.tool == "write_note" for na in evaluation.not_assessed)  # never "safe"


def test_denied_tools_make_no_link() -> None:
    web, mail = _web_and_mail()
    web.servers[1].approval.denied_patterns = ["write_*"]
    assert _rules(_evaluate(web, mail)) == []


def test_findings_are_deterministic_and_one_per_entry_agent() -> None:
    web, mail = _web_and_mail()
    web2 = _agent("web2", _fetch(), _notes(write=True))
    first = _evaluate(web, mail, web2)
    second = _evaluate(web2, mail, web)
    assert [f.agent_id for f in first.findings] == ["web", "web2"]
    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]
    assert len({f.fingerprint for f in first.findings}) == 2


def test_too_many_agents_skips_chain_rules_instead_of_stalling() -> None:
    agents = [_agent(f"a{i}", _fetch()) for i in range(MAX_CHAIN_AGENTS + 1)]
    evaluation = _evaluate(*agents)
    assert {s.rule_id for s in evaluation.skipped_rules} >= {"CAP-012", "CAP-013"}
    assert evaluation.findings == []


def test_many_agents_sharing_one_store_stay_fast() -> None:
    # 300 agents all reading and writing the same store: thousands of possible links.
    agents = [_agent(f"a{i:03d}", _notes(write=True, read=True)) for i in range(300)]
    agents.append(_agent("web", _fetch(), _notes(write=True)))
    agents.append(_agent("zmail", _notes(read=True), _mailer()))
    evaluation = _evaluate(*agents)
    assert [f.agent_id for f in evaluation.findings if f.rule_id == "CAP-012"] == ["web"]


def test_reports_name_every_agent_in_the_chain() -> None:
    evaluation = _evaluate(*_web_and_mail())
    text = markdown.render(evaluation)
    assert "**Chain of agents:** `web` -> `mail`" in text
    assert "`notes (agent web)`" in text
    message = sarif.render(evaluation)["runs"][0]["results"][0]["message"]["text"]
    assert "Chain of agents: web -> mail." in message


# --- policy loading --------------------------------------------------------------------

_HEAD = (
    'version: 1\ntaxonomy_version: "1"\nrules:\n  - id: T-1\n    severity: high\n    message: m\n'
)


def test_custom_chain_rule() -> None:
    policy = parse_policy(
        _HEAD + "    when_agents_chain:\n      - untrusted_input: true\n      - egress: external\n",
        "test.yaml",
    )
    evaluation = evaluate(Inventory(agents=[*_web_and_mail()]), policy)
    assert _rules(evaluation) == ["T-1"]


@pytest.mark.parametrize(
    "condition",
    [
        "    when_agents_chain:\n      - untrusted_input: true\n",  # one step is not a chain
        "    when_agents_chain:\n      - untrusted_input: true\n      - nonsense: 1\n",
        "    when_agents_chain: true\n",
    ],
)
def test_invalid_chain_rules_are_rejected(condition: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy(_HEAD + condition, "test.yaml")


@pytest.mark.parametrize(
    "extra",
    [
        "    when_server:\n      remote: true\n",
        "    when_agent_has_any:\n      - egress: external\n",
        "    when_hash_changed: true\n",
    ],
)
def test_chain_cannot_be_combined_with_other_conditions(extra: str) -> None:
    chain = "    when_agents_chain:\n      - untrusted_input: true\n      - egress: external\n"
    with pytest.raises(PolicyError, match="when_agents_chain"):
        parse_policy(_HEAD + chain + extra, "test.yaml")

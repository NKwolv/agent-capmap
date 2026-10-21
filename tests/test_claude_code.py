"""Claude Code: ~/.claude.json scopes, project .mcp.json, permission-derived approval."""

import json
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.discovery import discover, user_config_paths
from agentcapmap.enumerate import enumerate_server
from agentcapmap.enumerate.hashing import tool_definition_hash
from agentcapmap.graph import ApprovalGate, build_agent_view
from agentcapmap.models import (
    Agent,
    ClassificationStatus,
    EnumerationResult,
    EnumerationStatus,
    Inventory,
    ToolClassification,
    ToolDefinition,
    ToolTags,
    Transport,
)
from agentcapmap.policy import evaluate, load_policy
from agentcapmap.redact import REDACTED
from agentcapmap.taxonomy import DEFAULTS

FAKE_API_KEY = "sk-ant-api03-FAKE-not-a-real-key-000000000000"
FAKE_DB_PASSWORD = "fake-db-password-1234"


def _write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


@pytest.fixture
def home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    proj1, proj2, proj4 = tmp_path / "proj1", tmp_path / "proj2", tmp_path / "proj4"
    for p in (proj1, proj2, proj4):
        p.mkdir()
    _write(
        home / ".claude.json",
        {
            "numStartups": 12,
            "primaryApiKey": FAKE_API_KEY,
            "oauthAccount": {"emailAddress": "someone@example.com"},
            "mcpServers": {
                "github": {
                    "type": "http",
                    "url": "https://api.githubcopilot.com/mcp/",
                    "headers": {"Authorization": "Bearer ${GITHUB_PAT}"},
                },
                "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2026.8.18"]},
            },
            "projects": {
                proj1.as_posix(): {
                    "mcpServers": {
                        "db": {
                            "command": "npx",
                            "args": ["-y", "@acme/db@1.0.0"],
                            "env": {"DB_PASSWORD": FAKE_DB_PASSWORD},
                        }
                    },
                    "disabledMcpServers": ["fetch"],
                    "allowedTools": ["mcp__db__query"],
                    "history": [{"display": "unrelated chat history"}],
                },
                proj2.as_posix(): {"mcpServers": {}},
                (tmp_path / "gone").as_posix(): {"mcpServers": {}},
                proj4.as_posix(): {
                    "mcpServers": {"live": {"type": "ws", "url": "wss://ws.example.com/mcp"}}
                },
            },
        },
    )
    _write(
        home / ".claude" / "settings.json",
        {
            "permissions": {
                "allow": ["mcp__github__get_*", "mcp__*", "mcp__db__run(sql:*)"],
                "deny": ["mcp__fetch__fetch"],
                "defaultMode": "default",
            }
        },
    )
    _write(
        proj2 / ".mcp.json",
        {
            "mcpServers": {
                "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2026.9.1"]},
                "sheets": {"command": "npx", "args": ["-y", "@acme/sheets@2.0.0"]},
            }
        },
    )
    _write(proj2 / ".claude" / "settings.local.json", {"disabledMcpjsonServers": ["sheets"]})
    _write(
        proj2 / ".claude" / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}}
    )
    return home


def _agents(home: Path) -> dict[str, Agent]:
    inventory = discover([home / ".claude.json"])
    assert inventory.errors == []
    return {a.id.split("#", 1)[1]: a for a in inventory.agents}


def test_one_agent_per_scope_combination(home: Path, tmp_path: Path) -> None:
    agents = _agents(home)
    assert sorted(agents) == [
        f"project:{(tmp_path / 'proj1').as_posix()}",
        f"project:{(tmp_path / 'proj2').as_posix()}",
        f"project:{(tmp_path / 'proj4').as_posix()}",
        "user",
    ]  # the project with no local servers and no .mcp.json adds nothing: skipped
    assert all(a.client == "claude-code" for a in agents.values())
    assert sorted(s.name for s in agents["user"].servers) == ["fetch", "github"]


def test_local_scope_toggles_and_redaction(home: Path, tmp_path: Path) -> None:
    proj1 = _agents(home)[f"project:{(tmp_path / 'proj1').as_posix()}"]
    servers = {s.name: s for s in proj1.servers}
    assert sorted(servers) == ["db", "fetch", "github"]
    assert servers["fetch"].disabled is True  # /mcp toggle in this project
    assert servers["db"].env == {"DB_PASSWORD": REDACTED}
    assert servers["db"].approval.auto_approved_patterns == ["query"]  # legacy allowedTools


def test_project_scope_precedence_and_approval_settings(home: Path, tmp_path: Path) -> None:
    proj2 = _agents(home)[f"project:{(tmp_path / 'proj2').as_posix()}"]
    servers = {s.name: s for s in proj2.servers}
    assert sorted(servers) == ["fetch", "github"]  # "sheets" is disabled for this project
    assert servers["fetch"].args == ["mcp-server-fetch==2026.9.1"]  # project beats user
    assert servers["fetch"].location.path.endswith("proj2/.mcp.json")
    assert {s.approval.default_gate for s in servers.values()} == {"none"}  # bypass mode


def test_permission_rules(home: Path) -> None:
    user = {s.name: s for s in _agents(home)["user"].servers}
    github, fetch = user["github"].approval, user["fetch"].approval
    # "mcp__*" (unanchored) and parameterized rules grant nothing, as in Claude Code.
    assert github.auto_approved_patterns == ["get_*"]
    assert github.auto_approve_all is False
    assert github.default_gate == "required"
    assert fetch.denied_patterns == ["fetch"]


def test_websocket_servers_are_listed_but_not_enumerated(home: Path, tmp_path: Path) -> None:
    proj4 = _agents(home)[f"project:{(tmp_path / 'proj4').as_posix()}"]
    live = next(s for s in proj4.servers if s.name == "live")
    assert live.transport is Transport.WS
    result = enumerate_server(live)
    assert result.status is EnumerationStatus.SKIPPED
    assert result.error is not None and "WebSocket" in result.error


def test_no_account_data_or_secrets_in_output(home: Path) -> None:
    dumped = discover([home / ".claude.json"]).model_dump_json()
    for leaked in (FAKE_API_KEY, FAKE_DB_PASSWORD, "someone@example.com", "unrelated chat"):
        assert leaked not in dumped


def test_user_config_paths_include_claude_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert tmp_path / ".claude.json" in user_config_paths()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "alt"))
    assert tmp_path / "alt" / ".claude.json" in user_config_paths()


def test_repository_mcp_json_uses_project_settings_only(tmp_path: Path) -> None:
    _write(tmp_path / ".mcp.json", {"mcpServers": {"db": {"command": "npx", "args": ["db@1.0.0"]}}})
    _write(tmp_path / ".claude" / "settings.json", {"permissions": {"allow": ["mcp__db"]}})
    (agent,) = discover([tmp_path]).agents
    assert agent.servers[0].approval.auto_approve_all is True


# --- effect on the policy engine -----------------------------------------------------


def _with_tools(agent: Agent, server: str, tools: dict[str, dict[str, Any]]) -> None:
    definitions = []
    for name, tags in tools.items():
        tool = ToolDefinition(name=name, definition_hash=tool_definition_hash(name, "", {}))
        tool.classification = ToolClassification(
            status=ClassificationStatus.CLASSIFIED,
            tags=ToolTags(**{**DEFAULTS, **tags}),
            confidence=0.9,
            evidence=dict.fromkeys(tags, f"{name} evidence"),
            taxonomy_version="1",
            prompt_version="1",
        )
        definitions.append(tool)
    target = next(s for s in agent.servers if s.name == server)
    target.enumeration = EnumerationResult(status=EnumerationStatus.OK, tools=definitions)


def test_approval_gates_drive_cap_003(home: Path, tmp_path: Path) -> None:
    agents = _agents(home)
    user = agents["user"]
    _with_tools(
        user,
        "github",
        {"get_file": {"data_access": "private_read"}, "delete_repo": {"mutation": "destructive"}},
    )
    _with_tools(user, "fetch", {"fetch": {"untrusted_input": True, "egress": "external"}})
    view = build_agent_view(user)
    gates = {t.tool.name: t.approval_gate for t in view.tools}
    # Denied tool removed; allowed tool auto-approved; the rest need approval.
    assert gates == {"get_file": ApprovalGate.NONE, "delete_repo": ApprovalGate.REQUIRED}
    rules = {f.rule_id for f in evaluate(Inventory(agents=[user]), load_policy()).findings}
    assert "CAP-003" not in rules  # destructive, but Claude Code asks first

    proj2 = agents[f"project:{(tmp_path / 'proj2').as_posix()}"]
    _with_tools(proj2, "github", {"delete_repo": {"mutation": "destructive"}})
    findings = evaluate(Inventory(agents=[proj2]), load_policy()).findings
    (cap3,) = [f for f in findings if f.rule_id == "CAP-003"]
    assert "bypassPermissions" in json.dumps(cap3.evidence[0].phrases)

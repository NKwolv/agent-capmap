"""Config parsers for Windsurf, Cline, Roo Code, Gemini CLI, Qwen Code, Zed and Codex CLI."""

import json
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.discovery import discover, user_config_paths
from agentcapmap.graph import ApprovalGate, build_agent_view
from agentcapmap.models import (
    Agent,
    AuthMethod,
    EnumerationResult,
    EnumerationStatus,
    Server,
    Transport,
)
from agentcapmap.redact import REDACTED
from tests.test_chains import _tool

FAKE_TOKEN = "fake-token-not-real-0123456789abcdef"
FAKE_PASSWORD = "fake-db-password-1234"


def _write(path: Path, content: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if isinstance(content, str) else json.dumps(content, indent=2))
    return path


def _one(path: Path) -> Agent:
    inventory = discover([path])
    assert inventory.errors == [], inventory.errors
    (agent,) = inventory.agents
    return agent


def _servers(agent: Agent) -> dict[str, Server]:
    return {s.name: s for s in agent.servers}


def test_windsurf(tmp_path: Path) -> None:
    path = _write(
        tmp_path / ".codeium" / "windsurf" / "mcp_config.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@acme/github@1.0.0"],
                    "env": {"GITHUB_TOKEN": FAKE_TOKEN},
                    "disabledTools": ["delete_repo", "*"],
                },
                "remote": {"serverUrl": "https://mcp.example.com/sse"},
            }
        },
    )
    agent = _one(path)
    assert agent.client == "windsurf"
    s = _servers(agent)
    assert s["github"].env == {"GITHUB_TOKEN": REDACTED}
    assert s["github"].auth.method is AuthMethod.STATIC
    # Names are literal: a tool called "*" does not hide every other tool.
    assert s["github"].approval.denied_patterns == ["[*]", "delete_repo"]
    assert s["remote"].transport is Transport.SSE
    assert s["remote"].url == "https://mcp.example.com/sse"
    assert FAKE_TOKEN not in agent.model_dump_json()


def test_cline_and_roo(tmp_path: Path) -> None:
    storage = tmp_path / "Code" / "User" / "globalStorage"
    cline = _write(
        storage / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
        {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@acme/fs@1.0.0"],
                    "autoApprove": ["read_file"],
                },
                "off": {"command": "npx", "args": ["x@1.0.0"], "disabled": True},
                "web": {"type": "streamableHttp", "url": "https://mcp.example.com/mcp"},
            }
        },
    )
    agent = _one(cline)
    assert agent.client == "cline"
    s = _servers(agent)
    assert s["fs"].approval.auto_approved_tools == ["read_file"]
    assert s["off"].disabled is True
    assert s["web"].transport is Transport.HTTP

    roo = _write(
        storage / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
        {"mcpServers": {"fs": {"command": "npx", "args": ["x@1.0.0"], "alwaysAllow": ["rm"]}}},
    )
    agent = _one(roo)
    assert agent.client == "roo-code"
    assert _servers(agent)["fs"].approval.auto_approved_tools == ["rm"]

    project = _write(tmp_path / "proj" / ".roo" / "mcp.json", {"mcpServers": {}})
    assert discover([tmp_path / "proj"]).agents == []  # empty project file adds nothing
    _write(project, {"mcpServers": {"db": {"command": "npx", "args": ["db@1.0.0"]}}})
    (agent,) = discover([tmp_path / "proj"]).agents
    assert agent.client == "roo-code"


def test_auto_approved_destructive_tool_has_no_gate(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "cline_mcp_settings.json",
        {"mcpServers": {"fs": {"command": "npx", "args": ["x@1.0.0"], "autoApprove": ["rm"]}}},
    )
    agent = _one(path)
    agent.servers[0].enumeration = EnumerationResult(
        status=EnumerationStatus.OK,
        tools=[_tool("rm", {"mutation": "destructive"}), _tool("ls", {})],
    )
    gates = {t.tool.name: t.approval_gate for t in build_agent_view(agent).tools}
    assert gates == {"rm": ApprovalGate.NONE, "ls": ApprovalGate.UNKNOWN}


@pytest.mark.parametrize(
    ("directory", "client"), [(".gemini", "gemini-cli"), (".qwen", "qwen-code")]
)
def test_gemini_cli_and_qwen(tmp_path: Path, directory: str, client: str) -> None:
    path = _write(
        tmp_path / directory / "settings.json",
        {
            "theme": "dark",
            "mcpServers": {
                "local": {
                    "command": "node",
                    "args": ["server.js"],
                    "trust": True,
                    "excludeTools": ["run_shell"],
                },
                "stream": {
                    "httpUrl": "https://mcp.example.com/mcp",
                    "headers": {"Authorization": f"Bearer {FAKE_TOKEN}"},
                },
                "legacy": {"url": "https://mcp.example.com/events"},
            },
        },
    )
    agent = _one(path)
    assert agent.client == client
    s = _servers(agent)
    assert s["local"].approval.auto_approve_all is True
    assert s["local"].approval.denied_patterns == ["run_shell"]
    assert s["stream"].transport is Transport.HTTP
    assert s["stream"].headers == {"Authorization": REDACTED}
    assert s["legacy"].transport is Transport.SSE  # a bare `url` is SSE in Gemini CLI
    assert FAKE_TOKEN not in agent.model_dump_json()


def test_gemini_settings_without_servers_is_not_an_agent(tmp_path: Path) -> None:
    _write(tmp_path / ".gemini" / "settings.json", {"theme": "dark"})
    assert discover([tmp_path]).agents == []


def test_zed(tmp_path: Path) -> None:
    path = _write(
        tmp_path / ".zed" / "settings.json",
        """
        {
          // Zed settings are JSON with comments
          "agent": { "always_allow_tool_actions": true },
          "context_servers": {
            "new-shape": { "source": "custom", "command": "npx", "args": ["-y", "a@1.0.0"] },
            "old-shape": {
              "command": { "path": "uvx", "args": ["b==1.0.0"], "env": { "API_KEY": "@SECRET@" } }
            },
            "remote": { "url": "https://mcp.example.com/mcp" },
            "off": { "command": "npx", "args": ["c@1.0.0"], "enabled": false },
            "from-extension": { "source": "extension", "settings": { "x": 1 } },
          },
        }
        """.replace("@SECRET@", FAKE_TOKEN),
    )
    agent = _one(path)
    assert agent.client == "zed"
    s = _servers(agent)
    assert sorted(s) == ["new-shape", "off", "old-shape", "remote"]  # extension entry skipped
    assert (s["old-shape"].command, s["old-shape"].args) == ("uvx", ["b==1.0.0"])
    assert s["old-shape"].env == {"API_KEY": REDACTED}
    assert s["off"].disabled is True
    assert s["remote"].transport is Transport.HTTP
    assert all(server.approval.auto_approve_all for server in s.values())
    assert s["new-shape"].location.line == 6
    assert FAKE_TOKEN not in agent.model_dump_json()


def test_zed_without_always_allow_leaves_the_gate_unknown(tmp_path: Path) -> None:
    path = _write(
        tmp_path / ".zed" / "settings.json",
        {"context_servers": {"a": {"command": "npx", "args": ["a@1.0.0"]}}},
    )
    approval = _one(path).servers[0].approval
    assert (approval.auto_approve_all, approval.default_gate) == (False, "unknown")


CODEX_TOML = """
model = "o5"

[mcp_servers.docs]
command = "npx"
args = ["-y", "@acme/docs@1.0.0"]
disabled_tools = ["delete_page"]

[mcp_servers.docs.env]
DOCS_PASSWORD = "@SECRET@"

[mcp_servers."remote api"]
url = "https://mcp.example.com/mcp"
bearer_token_env_var = "REMOTE_TOKEN"
env_http_headers = { "X-Org" = "ORG_ID" }

[mcp_servers.off]
command = "uvx"
args = ["thing==1.0.0"]
enabled = false
""".replace("@SECRET@", FAKE_PASSWORD)


def test_codex_toml(tmp_path: Path) -> None:
    path = _write(tmp_path / ".codex" / "config.toml", CODEX_TOML)
    agent = _one(path)
    assert agent.client == "codex"
    s = _servers(agent)
    assert sorted(s) == ["docs", "off", "remote api"]
    assert s["docs"].env == {"DOCS_PASSWORD": REDACTED}
    assert s["docs"].approval.denied_patterns == ["delete_page"]
    assert s["docs"].location.line == 4
    assert s["remote api"].transport is Transport.HTTP
    assert s["remote api"].auth.evidence == ["header:Authorization"]
    assert s["remote api"].location.line == 12
    # The header value names an environment variable; nothing secret is in the file.
    assert s["remote api"].launch.headers == {
        "X-Org": "${ORG_ID}",
        "Authorization": "Bearer ${REMOTE_TOKEN}",
    }
    assert s["off"].disabled is True
    assert FAKE_PASSWORD not in agent.model_dump_json()


@pytest.mark.parametrize(
    ("relative", "content", "message"),
    [
        (".codex/config.toml", "[mcp_servers\nbroken", "invalid TOML"),
        (".codex/config.toml", 'mcp_servers = "nope"', "must be a table"),
        (".codex/config.toml", "[mcp_servers.a]\ncommand = 5", "'command' must be a string"),
        (
            ".codex/config.toml",
            '[mcp_servers.a]\ncommand = "x"\nhttp_headers = 3',
            "must be a table",
        ),
        (".gemini/settings.json", '{"mcpServers": []}', "must be an object"),
        (".zed/settings.json", '{"context_servers": 7}', "must be an object"),
        (
            ".gemini/settings.json",
            '{"mcpServers": {"a": {"command": "x", "excludeTools": "all"}}}',
            "must be an array of tool names",
        ),
    ],
)
def test_malformed_configs_are_clean_errors(
    tmp_path: Path, relative: str, content: str, message: str
) -> None:
    path = _write(tmp_path / relative, content)
    inventory = discover([path])
    assert inventory.agents == []
    (error,) = inventory.errors
    assert message in error.message


def test_deeply_nested_toml_is_a_clean_error(tmp_path: Path) -> None:
    path = _write(tmp_path / ".codex" / "config.toml", "x = " + "[" * 5000 + "]" * 5000)
    inventory = discover([path])
    assert inventory.agents == []
    assert "TOML" in inventory.errors[0].message


def test_directory_walk_finds_the_new_formats(tmp_path: Path) -> None:
    entry = {"command": "npx", "args": ["a@1.0.0"]}
    _write(
        tmp_path / "a" / ".codeium" / "windsurf" / "mcp_config.json", {"mcpServers": {"s": entry}}
    )
    _write(tmp_path / "b" / "cline_mcp_settings.json", {"mcpServers": {"s": entry}})
    _write(tmp_path / "c" / ".gemini" / "settings.json", {"mcpServers": {"s": entry}})
    _write(tmp_path / "d" / ".zed" / "settings.json", {"context_servers": {"s": entry}})
    _write(tmp_path / "e" / ".codex" / "config.toml", '[mcp_servers.s]\ncommand = "npx"\n')
    # Unrelated files with the same names are not agents and not errors.
    _write(tmp_path / "f" / "config.toml", "[tool]\nname = 1\n")
    _write(tmp_path / "g" / "mcp_config.json", {"mcpServers": {"s": entry}})
    inventory = discover([tmp_path])
    assert inventory.errors == []
    assert sorted(a.client for a in inventory.agents) == [
        "cline",
        "codex",
        "gemini-cli",
        "windsurf",
        "zed",
    ]


def test_user_config_paths_include_the_new_clients(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    paths = {p.as_posix() for p in user_config_paths()}
    home = tmp_path.as_posix()
    assert f"{home}/.codeium/windsurf/mcp_config.json" in paths
    assert f"{home}/.gemini/settings.json" in paths
    assert f"{home}/.codex/config.toml" in paths
    assert any(p.endswith("saoudrizwan.claude-dev/settings/cline_mcp_settings.json") for p in paths)
    assert any(p.lower().endswith("zed/settings.json") for p in paths)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "alt"))
    assert tmp_path / "alt" / "config.toml" in user_config_paths()

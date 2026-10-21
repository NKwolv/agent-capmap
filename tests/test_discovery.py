import json
from pathlib import Path

import pytest

from agentcapmap.discovery import detect_format, discover, parse_config_file
from agentcapmap.models import Agent, AuthMethod, Server, Transport
from agentcapmap.redact import REDACTED
from tests import fake_secrets
from tests.conftest import CONFIG_FIXTURES


def _agent(path: Path) -> Agent:
    agent, error = parse_config_file(path, root=CONFIG_FIXTURES, explicit=True)
    assert error is None, error
    assert agent is not None
    return agent


def _servers(agent: Agent) -> dict[str, Server]:
    return {s.name: s for s in agent.servers}


def test_claude_desktop() -> None:
    agent = _agent(CONFIG_FIXTURES / "claude_desktop" / "claude_desktop_config.json")
    assert agent.client == "claude-desktop"
    assert agent.id == "claude-desktop:claude_desktop/claude_desktop_config.json"
    s = _servers(agent)
    assert list(s) == ["filesystem", "github", "postgres"]

    assert s["filesystem"].transport is Transport.STDIO
    assert s["filesystem"].command == "npx"
    assert s["filesystem"].auth.method is AuthMethod.NONE
    assert s["filesystem"].location.line == 3

    assert s["github"].env == {"GITHUB_PERSONAL_ACCESS_TOKEN": REDACTED}
    assert s["github"].auth.method is AuthMethod.STATIC
    assert s["github"].auth.evidence == ["env:GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert s["github"].location.line == 7

    assert s["postgres"].args[2] == f"postgresql://admin:{REDACTED}@db.internal:5432/prod"
    assert s["postgres"].auth.method is AuthMethod.STATIC


def test_cursor() -> None:
    agent = _agent(CONFIG_FIXTURES / "cursor" / ".cursor" / "mcp.json")
    assert agent.client == "cursor"
    s = _servers(agent)

    assert s["linear"].transport is Transport.SSE
    assert s["linear"].url == "https://mcp.linear.app/sse"
    assert s["linear"].auth.method is AuthMethod.UNKNOWN

    assert s["internal-api"].transport is Transport.HTTP
    assert s["internal-api"].headers == {"Authorization": REDACTED}
    assert s["internal-api"].auth.evidence == ["header:Authorization"]

    assert s["openai-tools"].args == ["openai-mcp", f"--api-key={REDACTED}"]
    assert s["openai-tools"].auth.evidence == ["arg:--api-key"]

    # References are pointers, not secrets: kept verbatim.
    assert s["brave-search"].env == {"BRAVE_API_KEY": "${env:BRAVE_API_KEY}"}
    assert s["brave-search"].auth.method is AuthMethod.STATIC


def test_vscode_mcp_json_jsonc() -> None:
    agent = _agent(CONFIG_FIXTURES / "vscode" / ".vscode" / "mcp.json")
    assert agent.client == "vscode"
    s = _servers(agent)
    assert list(s) == ["github", "playwright", "slack"]

    assert s["github"].transport is Transport.HTTP
    assert s["github"].headers == {"Authorization": "Bearer ${input:gh-pat}"}
    assert s["github"].auth.method is AuthMethod.STATIC

    assert s["playwright"].transport is Transport.STDIO
    assert s["playwright"].auth.method is AuthMethod.NONE

    assert s["slack"].args == ["${workspaceFolder}/tools/slack.js"]
    assert s["slack"].auth.method is AuthMethod.UNKNOWN
    assert s["slack"].auth.evidence == ["envFile"]
    # Workspace root for .vscode/mcp.json is the folder containing .vscode.
    assert Path(s["slack"].launch.base_dir or "").name == "vscode"


def test_vscode_settings_scopes_to_mcp_block() -> None:
    agent = _agent(CONFIG_FIXTURES / "vscode" / ".vscode" / "settings.json")
    s = _servers(agent)
    assert list(s) == ["aws", "search"]
    # The unrelated "servers" -> "aws" key at line 5 must not be picked up.
    assert s["aws"].location.line == 10
    assert s["aws"].env == {
        "AWS_ACCESS_KEY_ID": REDACTED,
        "AWS_SECRET_ACCESS_KEY": REDACTED,
        "AWS_REGION": REDACTED,
    }
    assert s["aws"].auth.evidence == ["env:AWS_ACCESS_KEY_ID", "env:AWS_SECRET_ACCESS_KEY"]

    assert s["search"].url is not None
    assert fake_secrets.QUERY_KEY not in s["search"].url
    assert "region=eu" in s["search"].url
    assert s["search"].auth.evidence == ["header:X-API-Key", "url:embedded-credential"]


def test_claude_code_project_config() -> None:
    agent = _agent(CONFIG_FIXTURES / "claude_code" / ".mcp.json")
    assert agent.client == "claude-code"
    s = _servers(agent)

    assert s["sentry"].transport is Transport.HTTP
    assert s["sentry"].auth.method is AuthMethod.UNKNOWN

    docker_args = s["github-docker"].args
    assert f"GITHUB_PERSONAL_ACCESS_TOKEN={REDACTED}" in docker_args
    assert s["github-docker"].auth.evidence == ["arg:GITHUB_PERSONAL_ACCESS_TOKEN"]

    assert s["slack"].disabled is True

    assert s["api"].transport is Transport.SSE
    assert s["api"].headers == {"X-API-Key": "${API_KEY}"}


def test_generic_mcp_json() -> None:
    agent = _agent(CONFIG_FIXTURES / "generic" / "mcp.json")
    assert agent.client == "generic"
    s = _servers(agent)
    assert s["zapier"].transport is Transport.SSE
    assert s["zapier"].url == f"https://actions.example.com/mcp/{REDACTED}/sse"
    assert s["zapier"].auth.evidence == ["url:embedded-credential"]
    assert s["proxy"].args == ["proxy.py", "--token", REDACTED, "--port", "8080"]


def test_directory_scan_finds_every_fixture_without_leaking() -> None:
    inventory = discover([CONFIG_FIXTURES])
    assert inventory.errors == []
    assert [a.id for a in inventory.agents] == [
        "claude-code:claude_code/.mcp.json",
        "claude-desktop:claude_desktop/claude_desktop_config.json",
        "cursor:cursor/.cursor/mcp.json",
        "generic:generic/mcp.json",
        "vscode:vscode/.vscode/mcp.json",
        "vscode:vscode/.vscode/settings.json",
    ]
    dumped = inventory.model_dump_json()
    fake_secrets.assert_no_secrets(dumped)
    assert "launch" not in json.loads(dumped)["agents"][0]["servers"][0]


def test_launch_spec_never_reprs_secrets() -> None:
    agent = _agent(CONFIG_FIXTURES / "claude_desktop" / "claude_desktop_config.json")
    fake_secrets.assert_no_secrets(repr(agent))
    fake_secrets.assert_no_secrets(str(agent.servers[1].launch))
    # ...but the raw values are kept for launching.
    assert agent.servers[1].launch.env["GITHUB_PERSONAL_ACCESS_TOKEN"] == fake_secrets.GITHUB_PAT


def test_repo_walk_skips_noise_and_reports_bad_configs(tmp_path: Path) -> None:
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / ".mcp.json").write_text(
        '{"mcpServers": {"x": {"command": "x"}}}'
    )
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "settings.json").write_text('{"editor.tabSize": 2}')
    (tmp_path / "settings.json").write_text('{"mcp": {"servers": {"x": {"command": "x"}}}}')
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / ".mcp.json").write_text('{"mcpServers": {')
    (tmp_path / "bad-entry").mkdir()
    (tmp_path / "bad-entry" / ".mcp.json").write_text('{"mcpServers": {"x": {"args": []}}}')
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"ok": {"command": "echo"}}}')

    inventory = discover([tmp_path])
    assert [a.id for a in inventory.agents] == ["claude-code:.mcp.json"]
    errors = {e.path: e.message for e in inventory.errors}
    assert set(errors) == {"bad-entry/.mcp.json", "broken/.mcp.json"}
    assert "needs either 'command' or 'url'" in errors["bad-entry/.mcp.json"]
    assert "invalid JSON" in errors["broken/.mcp.json"]


def test_explicit_file_with_unknown_name_is_sniffed(tmp_path: Path) -> None:
    custom = tmp_path / "team-agents.json"
    custom.write_text('{"servers": {"x": {"type": "stdio", "command": "x"}}}')
    assert detect_format(custom) is None
    inventory = discover([custom])
    assert inventory.agents[0].client == "vscode"

    other = tmp_path / "package.json"
    other.write_text('{"name": "not-mcp"}')
    inventory = discover([other])
    assert inventory.agents == []
    assert inventory.errors[0].message == "not a recognized MCP config"


def test_missing_path_is_reported(tmp_path: Path) -> None:
    inventory = discover([tmp_path / "nope"])
    assert inventory.errors[0].message == "path does not exist"


@pytest.mark.parametrize("transport", ["carrier-pigeon", 42])
def test_unknown_transport_is_an_error(tmp_path: Path, transport: object) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"x": {"type": transport, "command": "x"}}}))
    inventory = discover([cfg])
    assert inventory.agents == []
    assert "server 'x'" in inventory.errors[0].message

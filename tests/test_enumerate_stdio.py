import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from agentcapmap.discovery import discover
from agentcapmap.enumerate import enumerate_inventory, enumerate_server
from agentcapmap.enumerate.hashing import tool_definition_hash
from agentcapmap.enumerate.stdio import StdioTransport
from agentcapmap.enumerate.transport import ForbiddenMethod
from agentcapmap.models import EnumerationStatus, Server
from tests import fake_secrets
from tests.conftest import MOCK_SERVER

MakeConfig = Callable[..., tuple[Path, Path]]

FIVE_TOOLS = [
    {"name": f"tool_{i}", "description": f"Tool number {i}", "inputSchema": {"type": "object"}}
    for i in range(5)
]


def _server(config: Path) -> Server:
    inventory = discover([config])
    assert inventory.errors == [], inventory.errors
    return inventory.agents[0].servers[0]


def _calls(call_log: Path) -> list[str]:
    return call_log.read_text().splitlines() if call_log.exists() else []


def test_lists_tools_with_pagination(mock_stdio_config: MakeConfig) -> None:
    config, call_log = mock_stdio_config({"tools": FIVE_TOOLS, "page_size": 2})
    result = enumerate_server(_server(config), timeout=20)

    assert result.status is EnumerationStatus.OK, result.error
    assert [t.name for t in result.tools] == [f"tool_{i}" for i in range(5)]
    assert result.server_info == {"name": "mock-mcp", "version": "1.0.0"}
    assert result.protocol_version == "2025-06-18"
    assert result.tools[0].definition_hash == tool_definition_hash(
        "tool_0", "Tool number 0", {"type": "object"}
    )
    assert result.definition_hash is not None
    assert _calls(call_log) == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/list",
        "tools/list",
    ]


def test_tolerates_noise_and_answers_server_ping(mock_stdio_config: MakeConfig) -> None:
    config, call_log = mock_stdio_config({"noise": True, "ping_first": True})
    result = enumerate_server(_server(config), timeout=20)
    assert result.status is EnumerationStatus.OK, result.error
    assert [t.name for t in result.tools] == ["read_file", "send_email"]
    assert result.tools[1].annotations == {"destructiveHint": False, "openWorldHint": True}
    assert "response:ping-1" in _calls(call_log)


def test_skips_tools_list_without_tools_capability(mock_stdio_config: MakeConfig) -> None:
    config, call_log = mock_stdio_config({"no_tools_capability": True})
    result = enumerate_server(_server(config), timeout=20)
    assert result.status is EnumerationStatus.OK
    assert result.tools == []
    assert "tools/list" not in _calls(call_log)


def test_timeout(mock_stdio_config: MakeConfig) -> None:
    config, _ = mock_stdio_config({"hang_on": "tools/list"})
    start = time.monotonic()
    result = enumerate_server(_server(config), timeout=3)
    assert result.status is EnumerationStatus.TIMEOUT
    assert time.monotonic() - start < 15


def test_crash_stderr_is_redacted(mock_stdio_config: MakeConfig) -> None:
    config, _ = mock_stdio_config(
        {"stderr_env": "GITHUB_TOKEN"}, env={"GITHUB_TOKEN": fake_secrets.GITHUB_PAT}
    )
    result = enumerate_server(_server(config), timeout=20)
    assert result.status is EnumerationStatus.ERROR
    assert result.error is not None
    assert "authentication failed" in result.error
    fake_secrets.assert_no_secrets(result.error)


def test_crash_stderr_redacts_unshaped_known_secret(mock_stdio_config: MakeConfig) -> None:
    secret = "correct-horse-battery-staple"
    config, _ = mock_stdio_config({"stderr_env": "DB_PASSWORD"}, env={"DB_PASSWORD": secret})
    result = enumerate_server(_server(config), timeout=20)
    assert result.error is not None
    assert secret not in result.error


def test_missing_command(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {"x": {"command": "definitely-not-a-real-binary-xyz"}}}')
    result = enumerate_server(_server(config), timeout=10)
    assert result.status is EnumerationStatus.ERROR
    assert result.error is not None
    assert "failed to start" in result.error


def test_disabled_and_unresolvable_servers_are_not_launched(
    mock_stdio_config: MakeConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, call_log = mock_stdio_config(extra={"disabled": True})
    result = enumerate_server(_server(config), timeout=10)
    assert result.status is EnumerationStatus.SKIPPED
    assert result.error == "disabled in config"

    config, call_log = mock_stdio_config(env={"TOKEN": "${input:token}"})
    result = enumerate_server(_server(config), timeout=10)
    assert result.status is EnumerationStatus.SKIPPED
    assert result.error is not None and "interactive input" in result.error

    monkeypatch.delenv("CAPMAP_UNSET_VAR", raising=False)
    config, call_log = mock_stdio_config(env={"X": "${CAPMAP_UNSET_VAR}"})
    result = enumerate_server(_server(config), timeout=10)
    assert result.status is EnumerationStatus.SKIPPED
    assert _calls(call_log) == []


def test_env_references_are_resolved(
    mock_stdio_config: MakeConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CAPMAP_TEST_TOKEN", fake_secrets.SLACK_TOKEN)
    config, _ = mock_stdio_config(
        {"stderr_env": "SLACK_TOKEN"}, env={"SLACK_TOKEN": "${env:CAPMAP_TEST_TOKEN}"}
    )
    result = enumerate_server(_server(config), timeout=20)
    # The server saw the resolved value (it printed it), and we redacted it.
    assert result.error is not None
    assert "authentication failed using <redacted>" in result.error


def test_forbidden_methods_are_never_sent(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.log"
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"call_log": str(call_log)}))
    transport = StdioTransport(sys.executable, [str(MOCK_SERVER), str(spec)], {})
    try:
        for method in ("tools/call", "resources/read", "prompts/get", "sampling/createMessage"):
            with pytest.raises(ForbiddenMethod):
                transport.request(method, {}, timeout=5)
        with pytest.raises(ForbiddenMethod):
            transport.notify("notifications/cancelled")
        transport.request("initialize", {"protocolVersion": "2025-06-18"}, timeout=20)
    finally:
        transport.close()
    assert _calls(call_log) == ["initialize"]


def test_enumerate_inventory_fills_every_server(
    mock_stdio_config: MakeConfig, tmp_path: Path
) -> None:
    config, _ = mock_stdio_config()
    inventory = discover([config])
    enumerate_inventory(inventory, timeout=20)
    server = inventory.agents[0].servers[0]
    assert server.enumeration is not None
    assert server.enumeration.status is EnumerationStatus.OK

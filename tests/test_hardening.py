"""Regression tests for security hardening: each test pins one vulnerability class shut."""

import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.classify import InvalidOutput, parse_output
from agentcapmap.discovery import discover
from agentcapmap.discovery._common import ConfigError, load_jsonc
from agentcapmap.enumerate import enumerate_server
from agentcapmap.enumerate.hashing import tool_definition_hash
from agentcapmap.enumerate.http import iter_sse
from agentcapmap.enumerate.stdio import default_environment
from agentcapmap.enumerate.transport import TransportError
from agentcapmap.models import EnumerationStatus, Server, ToolDefinition
from agentcapmap.redact import get_logger, redact_text
from tests import fake_secrets
from tests.mock_mcp_server import MockHttpServer

MakeConfig = Callable[..., tuple[Path, Path]]


def _server(config: Path) -> Server:
    inventory = discover([config])
    assert inventory.errors == [], inventory.errors
    return inventory.agents[0].servers[0]


def _remote(tmp_path: Path, entry: dict[str, Any]) -> Server:
    config = tmp_path / "remote.json"
    config.write_text(json.dumps({"mcpServers": {"remote": entry}}))
    return _server(config)


# --- environment isolation -----------------------------------------------------------


def test_launched_server_does_not_inherit_our_secrets(
    mock_stdio_config: MakeConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CAPMAP_PARENT_SECRET", "parent-only-value-123")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-for-servers-000000")
    config, _ = mock_stdio_config(
        {"report_env": ["CAPMAP_PARENT_SECRET", "ANTHROPIC_API_KEY", "EXPLICIT_VAR", "PATH"]},
        env={"EXPLICIT_VAR": "set-by-config"},
    )
    result = enumerate_server(_server(config), timeout=20)
    assert result.status is EnumerationStatus.OK, result.error
    assert result.server_info is not None
    assert result.server_info["env"] == {
        "CAPMAP_PARENT_SECRET": False,
        "ANTHROPIC_API_KEY": False,
        "EXPLICIT_VAR": True,
        "PATH": True,
    }


def test_default_environment_is_an_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x" * 20)
    monkeypatch.setenv("GITHUB_TOKEN", "y" * 20)
    env = default_environment()
    assert "PATH" in {k.upper() for k in env}
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env


# --- hostile stdio servers -----------------------------------------------------------


def test_oversized_stdout_line_is_dropped(
    mock_stdio_config: MakeConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentcapmap.enumerate.stdio.MAX_MESSAGE_BYTES", 1024)
    config, _ = mock_stdio_config({"junk_before_init": "x" * 50_000 + "\n"})
    result = enumerate_server(_server(config), timeout=20)
    assert result.status is EnumerationStatus.OK, result.error


def test_deeply_nested_json_does_not_kill_the_reader(mock_stdio_config: MakeConfig) -> None:
    config, _ = mock_stdio_config({"junk_before_init": "[" * 200_000 + "\n"})
    result = enumerate_server(_server(config), timeout=20)
    assert result.status is EnumerationStatus.OK, result.error


def test_tool_count_is_capped(
    mock_stdio_config: MakeConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentcapmap.enumerate.MAX_TOOLS_PER_SERVER", 10)
    config, _ = mock_stdio_config({"tool_count": 25})
    result = enumerate_server(_server(config), timeout=20)
    assert result.status is EnumerationStatus.ERROR
    assert result.error == "server returned more than 10 tools"


def test_log_output_escapes_terminal_control_sequences(caplog: pytest.LogCaptureFixture) -> None:
    log = get_logger("agentcapmap.test.escape")
    with caplog.at_level(logging.DEBUG, logger="agentcapmap.test.escape"):
        log.debug("server stderr: %s", "\x1b[2J\x1b]0;pwned\x07done")
    assert "\x1b" not in caplog.text
    assert "\x07" not in caplog.text
    assert "\\x1b[2J" in caplog.text


# --- hostile HTTP servers ------------------------------------------------------------


def test_redirects_are_refused_and_credentials_not_forwarded(tmp_path: Path) -> None:
    with MockHttpServer() as target:
        with MockHttpServer(spec={"redirect_to": target.url}) as redirector:
            server = _remote(
                tmp_path,
                {
                    "type": "http",
                    "url": redirector.url,
                    "headers": {"X-API-Key": fake_secrets.SETTINGS_API_KEY},
                },
            )
            result = enumerate_server(server, timeout=10)
        assert target.received_headers == []
    assert result.status is EnumerationStatus.ERROR
    assert result.error is not None and "redirect" in result.error


def test_legacy_sse_cross_origin_endpoint_is_refused(tmp_path: Path) -> None:
    with MockHttpServer(
        mode="legacy-sse", spec={"endpoint": "http://attacker.example/collect"}
    ) as mock:
        server = _remote(
            tmp_path,
            {"url": mock.url, "headers": {"Authorization": f"Bearer {fake_secrets.CURSOR_BEARER}"}},
        )
        result = enumerate_server(server, timeout=10)
    assert result.status is EnumerationStatus.ERROR
    assert result.error is not None and "different origin" in result.error
    assert mock.methods == []  # nothing was posted anywhere


def test_oversized_http_body_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentcapmap.enumerate.http.MAX_MESSAGE_BYTES", 2000)
    with MockHttpServer(spec={"body_padding": 10_000}) as mock:
        result = enumerate_server(_remote(tmp_path, {"type": "http", "url": mock.url}), timeout=10)
    assert result.status is EnumerationStatus.ERROR
    assert result.error is not None and "larger than 2000 bytes" in result.error


def test_oversized_sse_event_is_refused() -> None:
    with pytest.raises(TransportError, match="SSE event larger than"):
        list(iter_sse(["data: " + "x" * 100, ""], max_event_chars=10))


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/mcp"])
def test_non_http_urls_are_refused(tmp_path: Path, url: str) -> None:
    result = enumerate_server(_remote(tmp_path, {"type": "http", "url": url}), timeout=5)
    assert result.status is EnumerationStatus.ERROR
    assert result.error == "remote server URL must use http or https"


def test_connection_errors_do_not_leak_url_secrets(tmp_path: Path) -> None:
    with MockHttpServer() as mock:
        base = mock.url.rsplit("/", 1)[0]
    url = f"{base}/mcp/{fake_secrets.PATH_SECRET}?api_key={fake_secrets.QUERY_KEY}"
    result = enumerate_server(_remote(tmp_path, {"type": "http", "url": url}), timeout=5)
    assert result.status in (EnumerationStatus.ERROR, EnumerationStatus.TIMEOUT)
    assert result.error is not None
    fake_secrets.assert_no_secrets(result.error)


# --- redaction performance (ReDoS) ---------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "a." * 50_000,
        "token" * 20_000,
        'password="' * 20_000,
        "ab://cd:" * 20_000,
        "-----BEGIN PRIVATE KEY-----" * 2_000,
        "bearer " * 20_000,
    ],
    ids=["dotted", "keyword", "unclosed-quote", "userinfo", "pem", "bearer"],
)
def test_redaction_runs_in_linear_time_on_hostile_input(hostile: str) -> None:
    start = time.perf_counter()
    redact_text(hostile)
    assert time.perf_counter() - start < 2.0


# --- hostile config files and model output -------------------------------------------


def test_deeply_nested_config_is_a_clean_error() -> None:
    with pytest.raises(ConfigError, match="nested too deeply"):
        load_jsonc("[" * 200_000)


def test_oversized_config_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentcapmap.discovery.MAX_CONFIG_BYTES", 100)
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"x": {"command": "x", "args": ["a" * 200]}}}))
    inventory = discover([tmp_path])
    assert inventory.agents == []
    assert "larger than 100 bytes" in inventory.errors[0].message


def test_non_utf8_config_is_a_clean_error(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_bytes(b'{"mcpServers": {"\xff\xfe": {}}}')
    inventory = discover([tmp_path])
    assert inventory.errors[0].message == "cannot read file: not UTF-8 text"


def test_non_utf8_env_file_skips_the_server(mock_stdio_config: MakeConfig, tmp_path: Path) -> None:
    env_file = tmp_path / "bad.env"
    env_file.write_bytes(b"TOKEN=\xff\xfe\n")
    config, call_log = mock_stdio_config(extra={"envFile": str(env_file)})
    result = enumerate_server(_server(config), timeout=10)
    assert result.status is EnumerationStatus.SKIPPED
    assert result.error == "cannot read envFile: not a UTF-8 text file"
    assert not call_log.exists()


def test_deeply_nested_model_output_is_invalid_not_a_crash() -> None:
    tool = ToolDefinition(name="t", definition_hash=tool_definition_hash("t", "", {}))
    with pytest.raises(InvalidOutput, match="nested too deeply"):
        parse_output("[" * 200_000, tool, model="m")

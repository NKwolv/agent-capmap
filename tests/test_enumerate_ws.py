"""WebSocket transport: enumeration, authentication, redirects, limits and pinning."""

import builtins
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.discovery import discover
from agentcapmap.enumerate import enumerate_server
from agentcapmap.enumerate import ws as ws_module
from agentcapmap.models import AuthMethod, EnumerationStatus, Server, Transport
from tests import fake_secrets
from tests.mock_mcp_server import MockWebSocketServer


def _server(tmp_path: Path, url: str, headers: dict[str, str] | None = None) -> Server:
    entry: dict[str, Any] = {"type": "ws", "url": url}
    if headers:
        entry["headers"] = headers
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"live": entry}}))
    inventory = discover([config])
    assert inventory.errors == []
    return inventory.agents[0].servers[0]


def test_enumerates_tools_over_websocket(tmp_path: Path) -> None:
    with MockWebSocketServer(spec={"page_size": 1}) as mock:
        server = _server(tmp_path, mock.url)
        assert server.transport is Transport.WS
        result = enumerate_server(server, timeout=10)
    assert result.status is EnumerationStatus.OK, result.error
    assert [t.name for t in result.tools] == ["read_file", "send_email"]
    # Only the handshake and listings were sent: never a tool call.
    assert mock.methods == ["initialize", "notifications/initialized", "tools/list", "tools/list"]
    assert server.auth.method is AuthMethod.NONE  # it answered without credentials


def test_prompts_and_resources_are_listed_over_websocket(tmp_path: Path) -> None:
    spec = {"prompts": [{"name": "summarize", "description": "Summarize a file"}]}
    with MockWebSocketServer(spec=spec) as mock:
        result = enumerate_server(_server(tmp_path, mock.url), timeout=10)
    assert result.status is EnumerationStatus.OK, result.error
    assert [item.ref for item in result.items] == ["prompt:summarize"]


def test_unauthenticated_handshake_reports_auth_required(tmp_path: Path) -> None:
    with MockWebSocketServer(require_token=fake_secrets.CURSOR_BEARER) as mock:
        server = _server(tmp_path, mock.url)
        result = enumerate_server(server, timeout=10)
    assert result.status is EnumerationStatus.AUTH_REQUIRED
    assert server.auth.method is AuthMethod.OAUTH
    assert mock.methods == []


def test_static_token_is_sent_and_never_printed(tmp_path: Path) -> None:
    with MockWebSocketServer(require_token=fake_secrets.CURSOR_BEARER) as mock:
        server = _server(
            tmp_path, mock.url, {"Authorization": f"Bearer {fake_secrets.CURSOR_BEARER}"}
        )
        result = enumerate_server(server, timeout=10)
    assert result.status is EnumerationStatus.OK, result.error
    assert fake_secrets.CURSOR_BEARER not in server.model_dump_json()
    assert fake_secrets.CURSOR_BEARER not in result.model_dump_json()


def test_redirect_is_refused_and_credentials_are_not_forwarded(tmp_path: Path) -> None:
    with MockWebSocketServer(require_token=fake_secrets.CURSOR_BEARER) as target:
        with MockWebSocketServer(redirect_to=target.url) as mock:
            server = _server(
                tmp_path, mock.url, {"Authorization": f"Bearer {fake_secrets.CURSOR_BEARER}"}
            )
            result = enumerate_server(server, timeout=10)
        assert result.status is EnumerationStatus.ERROR
        assert "redirect" in (result.error or "")
        assert target.handshakes == 0  # nothing followed the redirect


def test_unrelated_messages_are_skipped_but_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with MockWebSocketServer(noise=3) as mock:
        result = enumerate_server(_server(tmp_path, mock.url), timeout=10)
    assert result.status is EnumerationStatus.OK, result.error

    monkeypatch.setattr(ws_module, "MAX_QUEUED_MESSAGES", 5)
    with MockWebSocketServer(noise=50) as mock:
        result = enumerate_server(_server(tmp_path, mock.url), timeout=10)
    assert result.status is EnumerationStatus.ERROR
    assert "too many unrelated messages" in (result.error or "")


def test_oversized_frame_is_an_error_not_a_memory_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ws_module, "MAX_MESSAGE_BYTES", 2000)
    big = [{"name": "t", "description": "x" * 5000, "inputSchema": {}}]
    with MockWebSocketServer(spec={"tools": big}) as mock:
        result = enumerate_server(_server(tmp_path, mock.url), timeout=10)
    assert result.status is EnumerationStatus.ERROR
    assert "x" * 100 not in (result.error or "")


def test_hanging_server_times_out(tmp_path: Path) -> None:
    with MockWebSocketServer(spec={"hang_on": "tools/list"}) as mock:
        result = enumerate_server(_server(tmp_path, mock.url), timeout=1)
    assert result.status is EnumerationStatus.TIMEOUT


@pytest.mark.parametrize("url", ["ws://169.254.169.254/mcp", "wss://metadata.google.internal/x"])
def test_metadata_addresses_are_refused(tmp_path: Path, url: str) -> None:
    result = enumerate_server(_server(tmp_path, url), timeout=5)
    assert result.status is EnumerationStatus.ERROR
    assert "metadata" in (result.error or "")


def test_name_that_rebinds_to_metadata_is_never_connected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lookups = 0

    def getaddrinfo(host: str, *_args: Any, **_kwargs: Any) -> list[Any]:
        nonlocal lookups
        lookups += 1
        address = "127.0.0.1" if lookups == 1 else "169.254.169.254"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]

    with MockWebSocketServer() as mock:
        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        url = mock.url.replace("127.0.0.1", "rebind.test")
        result = enumerate_server(_server(tmp_path, url), timeout=5)
        assert result.status is EnumerationStatus.ERROR
        assert "metadata" in (result.error or "")
        assert mock.handshakes == 0


def test_http_url_on_a_websocket_server_is_refused(tmp_path: Path) -> None:
    result = enumerate_server(_server(tmp_path, "http://127.0.0.1:1/mcp"), timeout=5)
    assert result.status is EnumerationStatus.ERROR
    assert "ws or wss" in (result.error or "")


def test_without_the_optional_package_the_server_is_skipped_with_a_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("websockets"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    with MockWebSocketServer() as mock:
        server = _server(tmp_path, mock.url)
        monkeypatch.setattr(builtins, "__import__", fake_import)
        result = enumerate_server(server, timeout=5)
    assert result.status is EnumerationStatus.SKIPPED
    assert "agent-capmap[ws]" in (result.error or "")

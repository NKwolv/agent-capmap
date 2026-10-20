import json
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.discovery import discover
from agentcapmap.enumerate import enumerate_server
from agentcapmap.enumerate.http import iter_sse
from agentcapmap.models import AuthMethod, EnumerationStatus, Server
from tests import fake_secrets
from tests.mock_mcp_server import MockHttpServer


def _server(tmp_path: Path, entry: dict[str, Any]) -> Server:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"remote": entry}}))
    inventory = discover([config])
    assert inventory.errors == []
    return inventory.agents[0].servers[0]


def test_iter_sse() -> None:
    lines = [": comment", "event: endpoint", "data: /messages", "", "data: a", "data: b", ""]
    assert list(iter_sse(lines)) == [("endpoint", "/messages"), ("message", "a\nb")]


@pytest.mark.parametrize("mode", ["json", "sse"])
def test_streamable_http(tmp_path: Path, mode: str) -> None:
    with MockHttpServer(mode=mode, spec={"page_size": 1}) as mock:
        server = _server(tmp_path, {"type": "http", "url": mock.url})
        result = enumerate_server(server, timeout=10)

    assert result.status is EnumerationStatus.OK, result.error
    assert [t.name for t in result.tools] == ["read_file", "send_email"]
    assert mock.methods == ["initialize", "notifications/initialized", "tools/list", "tools/list"]
    # Session id from initialize is echoed on every later request, and the session is closed.
    assert mock.session_headers == [None, "session-123", "session-123", "session-123"]
    assert mock.deleted
    # A remote server that answers without credentials is unauthenticated.
    assert server.auth.method is AuthMethod.NONE


def test_legacy_sse(tmp_path: Path) -> None:
    with MockHttpServer(mode="legacy-sse") as mock:
        server = _server(tmp_path, {"url": mock.url})  # transport inferred from /sse
        result = enumerate_server(server, timeout=10)
    assert result.status is EnumerationStatus.OK, result.error
    assert [t.name for t in result.tools] == ["read_file", "send_email"]
    assert mock.methods == ["initialize", "notifications/initialized", "tools/list"]


def test_unauthenticated_remote_reports_oauth(tmp_path: Path) -> None:
    with MockHttpServer(require_token=fake_secrets.CURSOR_BEARER) as mock:
        server = _server(tmp_path, {"type": "http", "url": mock.url})
        result = enumerate_server(server, timeout=10)
    assert result.status is EnumerationStatus.AUTH_REQUIRED
    assert server.auth.method is AuthMethod.OAUTH
    assert mock.methods == []


def test_static_bearer_token(tmp_path: Path) -> None:
    with MockHttpServer(require_token=fake_secrets.CURSOR_BEARER) as mock:
        server = _server(
            tmp_path,
            {
                "type": "http",
                "url": mock.url,
                "headers": {"Authorization": f"Bearer {fake_secrets.CURSOR_BEARER}"},
            },
        )
        result = enumerate_server(server, timeout=10)
    assert result.status is EnumerationStatus.OK, result.error
    assert server.auth.method is AuthMethod.STATIC
    fake_secrets.assert_no_secrets(server.model_dump_json())


def test_connection_refused(tmp_path: Path) -> None:
    with MockHttpServer() as mock:
        url = mock.url
    server = _server(tmp_path, {"type": "http", "url": url})
    result = enumerate_server(server, timeout=5)
    assert result.status in (EnumerationStatus.ERROR, EnumerationStatus.TIMEOUT)

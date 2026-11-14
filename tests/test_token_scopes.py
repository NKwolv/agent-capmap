"""--check-token-scopes: reading GitHub token scopes, opt-in, without leaking the token."""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from agentcapmap import cli
from agentcapmap.discovery import discover
from agentcapmap.enumerate import check_credential, scopes
from agentcapmap.models import Inventory, LaunchSpec, Server
from agentcapmap.policy import evaluate, load_policy, parse_policy
from tests.test_chains import _HEAD

CLASSIC = "ghp_FAKEfake0000000000000000000000000001"
OAUTH = "gho_FAKEfake0000000000000000000000000003"
FINE_GRAINED = "github_pat_FAKEfake00000000000000_fake0000000000000000"
APP = "ghs_FAKEfake0000000000000000000000000004"


class FakeGitHub:
    """Stands in for api.github.com: answers with a scope header, records what it received."""

    def __init__(self, scope_header: str | None = "repo, read:org", status: int = 200) -> None:
        self.scope_header = scope_header
        self.status = status
        self.requests: list[dict[str, str]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                fake.requests.append({"path": self.path, **dict(self.headers.items())})
                self.send_response(fake.status)
                if fake.scope_header is not None:
                    self.send_header("X-OAuth-Scopes", fake.scope_header)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host!s}:{port}/rate_limit"

    def __enter__(self) -> "FakeGitHub":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeGitHub]:
    with FakeGitHub() as fake:
        monkeypatch.setattr(scopes, "GITHUB_API", fake.url)
        for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.delenv(name, raising=False)
        yield fake


def _server(tmp_path: Path, entry: dict[str, Any]) -> Server:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"github": entry}}))
    inventory = discover([config])
    assert inventory.errors == []
    return inventory.agents[0].servers[0]


def _stdio(token: str, **env: str) -> dict[str, Any]:
    return {
        "command": "npx",
        "args": ["-y", "@acme/github@1.0.0"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": token, **env},
    }


@pytest.mark.parametrize(
    ("listed", "expected"),
    [
        ([], "read"),
        (["read:org", "read:user", "repo:status"], "read"),
        (["repo"], "write"),
        (["read:org", "workflow"], "write"),
        (["repo", "delete_repo"], "admin"),
        (["admin:org"], "admin"),
        (["read:org", "admin:repo_hook"], "admin"),
    ],
)
def test_breadth(listed: list[str], expected: str) -> None:
    assert scopes.breadth(listed) == expected


def test_classic_token_scopes_are_read_and_the_token_is_never_stored(
    tmp_path: Path, github: FakeGitHub
) -> None:
    github.scope_header = "repo, delete_repo, read:org"
    server = _server(tmp_path, _stdio(CLASSIC))
    check_credential(server, timeout=10)
    credential = server.credential
    assert credential is not None
    assert (credential.status, credential.breadth) == ("checked", "admin")
    assert credential.scopes == ["delete_repo", "read:org", "repo"]
    assert credential.source == "env:GITHUB_PERSONAL_ACCESS_TOKEN"
    (request,) = github.requests
    assert request["Authorization"] == f"Bearer {CLASSIC}"  # sent once, to "GitHub" only
    assert CLASSIC not in server.model_dump_json()


def test_token_in_a_header_or_argument_is_found(tmp_path: Path, github: FakeGitHub) -> None:
    remote = _server(
        tmp_path,
        {
            "type": "http",
            "url": "https://api.githubcopilot.com/mcp/",
            "headers": {"Authorization": f"Bearer {OAUTH}"},
        },
    )
    check_credential(remote, timeout=10)
    assert remote.credential is not None
    assert remote.credential.source == "header:Authorization"
    assert remote.credential.breadth == "write"

    arg = _server(tmp_path, {"command": "gh-mcp", "args": [f"--token={CLASSIC}"]})
    check_credential(arg, timeout=10)
    assert arg.credential is not None and arg.credential.source == "arg:--token"


@pytest.mark.parametrize("token", [FINE_GRAINED, APP])
def test_tokens_without_visible_scopes_are_not_sent(
    tmp_path: Path, github: FakeGitHub, token: str
) -> None:
    server = _server(tmp_path, _stdio(token))
    check_credential(server, timeout=10)
    assert server.credential is not None
    assert (server.credential.status, server.credential.breadth) == ("not_visible", "unknown")
    assert github.requests == []


@pytest.mark.parametrize(
    "entry",
    [
        _stdio(CLASSIC, GITHUB_HOST="github.corp.example"),
        _stdio(CLASSIC, GH_ENTERPRISE_TOKEN="x"),
        {
            "type": "http",
            "url": "https://mcp-proxy.example.net/github",
            "headers": {"Authorization": f"Bearer {CLASSIC}"},
        },
    ],
)
def test_a_token_for_another_host_is_never_sent_to_github(
    tmp_path: Path, github: FakeGitHub, entry: dict[str, Any]
) -> None:
    server = _server(tmp_path, entry)
    check_credential(server, timeout=10)
    assert server.credential is not None
    assert server.credential.status == "not_visible"
    assert "not sent" in server.credential.detail
    assert github.requests == []


def test_no_github_token_means_nothing_is_sent_or_recorded(
    tmp_path: Path, github: FakeGitHub
) -> None:
    server = _server(
        tmp_path, {"command": "npx", "args": ["x@1.0.0"], "env": {"API_KEY": "fake-other-key-123"}}
    )
    check_credential(server, timeout=10)
    assert server.credential is None
    assert github.requests == []


def _status(server: Server) -> str:
    assert server.credential is not None
    return server.credential.status


def test_rejected_token_and_odd_responses(tmp_path: Path, github: FakeGitHub) -> None:
    server = _server(tmp_path, _stdio(CLASSIC))
    github.status = 401
    check_credential(server, timeout=10)
    assert _status(server) == "rejected"

    github.status, github.scope_header = 200, None
    check_credential(server, timeout=10)
    assert _status(server) == "error"

    github.status, github.scope_header = 302, "repo"
    check_credential(server, timeout=10)
    assert _status(server) == "error"  # redirects are never followed
    assert CLASSIC not in server.model_dump_json()


def test_scope_names_from_the_response_are_sanitized_and_bounded(
    tmp_path: Path, github: FakeGitHub
) -> None:
    github.scope_header = "repo, <script>alert(1)</script>, " + ", ".join(
        f"s{i}" for i in range(500)
    )
    server = _server(tmp_path, _stdio(CLASSIC))
    check_credential(server, timeout=10)
    assert server.credential is not None
    assert len(server.credential.scopes) <= 100
    assert all(
        name.replace(":", "").replace("_", "").replace("-", "").isalnum()
        for name in server.credential.scopes
    )


def test_unreachable_api_is_an_error_without_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scopes, "GITHUB_API", "http://127.0.0.1:1/rate_limit")
    server = _server(tmp_path, _stdio(CLASSIC))
    check_credential(server, timeout=2)
    assert server.credential is not None and server.credential.status == "error"
    assert CLASSIC not in server.credential.detail


def test_disabled_servers_and_unresolved_variables_are_skipped(
    tmp_path: Path, github: FakeGitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    off = _server(tmp_path, {**_stdio(CLASSIC), "disabled": True})
    check_credential(off, timeout=10)
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    unresolved = _server(tmp_path, _stdio("${NOT_SET_ANYWHERE}"))
    check_credential(unresolved, timeout=10)
    assert (off.credential, unresolved.credential, github.requests) == (None, None, [])


def test_find_token_ignores_lookalikes() -> None:
    spec = LaunchSpec(
        env={"A": "ghp_tooshort", "B": "prefix ghp_" + "a" * 40, "C": "ghx_" + "a" * 40}
    )
    assert scopes.find_github_token(spec) is None


def test_admin_token_is_reported_by_cap_014(tmp_path: Path, github: FakeGitHub) -> None:
    github.scope_header = "repo, admin:org"
    server = _server(tmp_path, _stdio(CLASSIC))
    inventory = Inventory(agents=discover([tmp_path / "mcp.json"]).agents)
    inventory.agents[0].servers[0] = server
    assert "CAP-014" not in {f.rule_id for f in evaluate(inventory, load_policy()).findings}

    check_credential(server, timeout=10)
    (finding,) = [f for f in evaluate(inventory, load_policy()).findings if f.rule_id == "CAP-014"]
    assert finding.evidence[0].matched == {"token_scope": "admin"}
    phrase = finding.evidence[0].phrases["token_scope"]
    assert "admin:org" in phrase and "env:GITHUB_PERSONAL_ACCESS_TOKEN" in phrase
    assert CLASSIC not in evaluate(inventory, load_policy()).model_dump_json()

    github.scope_header = "read:org"
    check_credential(server, timeout=10)
    assert "CAP-014" not in {f.rule_id for f in evaluate(inventory, load_policy()).findings}


def test_token_scope_in_a_custom_policy_and_schema_rejects_unknown_values() -> None:
    head = _HEAD
    parse_policy(head + "    when_server:\n      token_scope: [admin, write]\n", "t.yaml")
    with pytest.raises(ValueError, match="invalid policy"):
        parse_policy(head + "    when_server:\n      token_scope: godmode\n", "t.yaml")


def test_cli_flag_is_opt_in_and_needs_enumerate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"github": {**_stdio(CLASSIC), "disabled": True}}}))
    assert cli.main(["scan", str(config), "--check-token-scopes"]) == cli.EXIT_ERROR
    assert "--check-token-scopes needs --enumerate" in capsys.readouterr().err
    assert cli.main(["scan", str(config), "--enumerate", "--check-token-scopes"]) == 0
    captured = capsys.readouterr()
    assert cli.SCOPE_CHECK_WARNING in captured.err  # the user is told where tokens go
    assert CLASSIC not in captured.out + captured.err

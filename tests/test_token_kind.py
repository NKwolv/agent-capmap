"""CAP-014: the kind of a GitHub token, recognized from its format without sending it."""

import json
import socket
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.credentials import github_token
from agentcapmap.discovery import discover
from agentcapmap.enumerate import enumerate_server
from agentcapmap.models import Inventory, LaunchSpec, Server
from agentcapmap.policy import PolicyError, evaluate, load_policy, parse_policy
from tests.test_chains import _HEAD

CLASSIC = "ghp_FAKEfake0000000000000000000000000001"
OAUTH = "gho_FAKEfake0000000000000000000000000003"
FINE_GRAINED = "github_pat_FAKEfake00000000000000_fake0000000000000000"
APP = "ghs_FAKEfake0000000000000000000000000004"


def _inventory(tmp_path: Path, entry: dict[str, Any]) -> Inventory:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"github": entry}}))
    inventory = discover([config])
    assert inventory.errors == []
    return inventory


def _server(tmp_path: Path, entry: dict[str, Any]) -> Server:
    return _inventory(tmp_path, entry).agents[0].servers[0]


def _stdio(token: str) -> dict[str, Any]:
    return {
        "command": "npx",
        "args": ["-y", "@acme/github@1.0.0"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": token},
    }


@pytest.mark.parametrize(
    ("token", "kind"),
    [(CLASSIC, "classic"), (FINE_GRAINED, "fine_grained"), (OAUTH, "oauth"), (APP, "app")],
)
def test_kind_is_recognized_from_the_format(tmp_path: Path, token: str, kind: str) -> None:
    server = _server(tmp_path, _stdio(token))
    assert server.credential is not None
    assert server.credential.kind == kind
    assert server.credential.source == "env:GITHUB_PERSONAL_ACCESS_TOKEN"
    assert token not in server.model_dump_json()  # the kind is kept, never the token


def test_token_in_a_header_or_argument_is_recognized(tmp_path: Path) -> None:
    remote = _server(
        tmp_path,
        {
            "type": "http",
            "url": "https://api.githubcopilot.com/mcp/",
            "headers": {"Authorization": f"Bearer {CLASSIC}"},
        },
    )
    assert remote.credential is not None
    assert remote.credential.source == "header:Authorization"
    arg = _server(tmp_path, {"command": "gh-mcp", "args": [f"--token={CLASSIC}"]})
    assert arg.credential is not None and arg.credential.source == "arg:--token"


def test_lookalikes_and_other_secrets_are_not_tokens(tmp_path: Path) -> None:
    spec = LaunchSpec(
        env={"A": "ghp_tooshort", "B": "prefix ghp_" + "a" * 40, "C": "ghx_" + "a" * 40},
        args=["--verbose"],
    )
    assert github_token(spec) is None
    other = _server(
        tmp_path, {"command": "npx", "args": ["x@1.0.0"], "env": {"API_KEY": "fake-other-key-123"}}
    )
    assert other.credential is None


def test_referenced_token_is_recognized_at_enumeration_without_any_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MY_GH_TOKEN", CLASSIC)
    server = _server(
        tmp_path,
        {
            "type": "http",
            "url": "http://127.0.0.1:1/mcp",
            "headers": {"Authorization": "Bearer ${MY_GH_TOKEN}"},
        },
    )
    assert server.credential is None  # the config only names a variable
    connected: list[Any] = []
    real_connect = socket.socket.connect

    def connect(self: socket.socket, address: Any) -> None:
        connected.append(address)
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    enumerate_server(server, timeout=2)  # nothing listens there: enumeration fails
    assert server.credential is not None and server.credential.kind == "classic"
    # The only connection attempted is to the configured server itself.
    assert {address[0] for address in connected} <= {"127.0.0.1"}
    assert CLASSIC not in server.model_dump_json()


def test_classic_token_is_reported_by_cap_014_and_fine_grained_is_not(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path, _stdio(CLASSIC))
    evaluation = evaluate(inventory, load_policy())
    (finding,) = [f for f in evaluation.findings if f.rule_id == "CAP-014"]
    assert finding.severity.value == "low"
    assert finding.evidence[0].matched == {"token_kind": "classic"}
    assert finding.evidence[0].phrases["token_kind"] == (
        "classic github token in env:GITHUB_PERSONAL_ACCESS_TOKEN"
    )
    assert CLASSIC not in evaluation.model_dump_json()

    for token in (FINE_GRAINED, APP):
        other = evaluate(_inventory(tmp_path, _stdio(token)), load_policy())
        assert "CAP-014" not in {f.rule_id for f in other.findings}


def test_token_kind_in_a_custom_policy_and_schema_rejects_unknown_values() -> None:
    parse_policy(_HEAD + "    when_server:\n      token_kind: [classic, oauth]\n", "t.yaml")
    parse_policy(_HEAD + "    when_server:\n      token_kind: none\n", "t.yaml")
    with pytest.raises(PolicyError, match="invalid policy"):
        parse_policy(_HEAD + "    when_server:\n      token_kind: godmode\n", "t.yaml")

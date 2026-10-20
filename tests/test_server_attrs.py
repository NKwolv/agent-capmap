import pytest

from agentcapmap.discovery._common import ConfigError, parse_approval
from agentcapmap.graph.server_attrs import PinStatus, SourceTrust, launch_source, source_trust
from agentcapmap.models import AuthHint, AuthMethod, Server, SourceLocation, Transport


def _stdio(command: str, *args: str) -> Server:
    return Server(
        name="s",
        transport=Transport.STDIO,
        command=command,
        args=list(args),
        auth=AuthHint(method=AuthMethod.NONE),
        location=SourceLocation(path="mcp.json"),
    )


@pytest.mark.parametrize(
    ("command", "args", "pin", "source"),
    [
        ("npx", ["-y", "@scope/server@1.2.3"], PinStatus.PINNED, "npm:@scope/server"),
        ("npx", ["-y", "@scope/server@latest"], PinStatus.UNPINNED, "npm:@scope/server"),
        ("npx", ["-y", "@scope/server"], PinStatus.UNPINNED, "npm:@scope/server"),
        ("npx", ["server@^1.2.0"], PinStatus.UNPINNED, "npm:server"),
        ("npx.cmd", ["-y", "server@2.0.0-beta.1"], PinStatus.PINNED, "npm:server"),
        ("npm", ["exec", "server@1.0.0"], PinStatus.PINNED, "npm:server"),
        ("pnpm", ["dlx", "server@1.0.0"], PinStatus.PINNED, "npm:server"),
        ("uvx", ["mcp-server-time==0.6.2"], PinStatus.PINNED, "pypi:mcp-server-time"),
        ("uvx", ["mcp-server-time@0.6.2"], PinStatus.PINNED, "pypi:mcp-server-time"),
        ("uvx", ["mcp-server-time"], PinStatus.UNPINNED, "pypi:mcp-server-time"),
        ("uvx", ["--from", "Pkg>=1", "cmd"], PinStatus.UNPINNED, "pypi:pkg"),
        ("pipx", ["run", "pkg==1.0"], PinStatus.PINNED, "pypi:pkg"),
        (
            "docker",
            ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/o/img@sha256:" + "a" * 64],
            PinStatus.PINNED,
            "docker:ghcr.io/o/img",
        ),
        ("docker", ["run", "-i", "ghcr.io/o/img:1.2"], PinStatus.UNPINNED, "docker:ghcr.io/o/img"),
        ("docker", ["run", "--name", "x", "img"], PinStatus.UNPINNED, "docker:img"),
        (
            "docker",
            ["run", "-v", "/a:/b", "localhost:5000/img:1"],
            PinStatus.UNPINNED,
            "docker:localhost:5000/img",
        ),
        ("node", ["server.js"], PinStatus.LOCAL, "local:server.js"),
        ("python", ["-u", "tools/srv.py"], PinStatus.LOCAL, "local:tools/srv.py"),
        ("/opt/bin/mcp-server", [], PinStatus.LOCAL, "local:/opt/bin/mcp-server"),
        ("mcp-server-git", [], PinStatus.UNKNOWN, None),
        ("npx", [], PinStatus.UNKNOWN, None),
    ],
)
def test_launch_source(command: str, args: list[str], pin: PinStatus, source: str | None) -> None:
    result = launch_source(_stdio(command, *args))
    assert (result.pin, result.source_id) == (pin, source)


def test_remote_servers_are_not_pinnable_and_identified_by_host() -> None:
    server = Server(
        name="r",
        transport=Transport.HTTP,
        url="https://MCP.Example.com:8443/mcp",
        auth=AuthHint(method=AuthMethod.UNKNOWN),
        location=SourceLocation(path="mcp.json"),
    )
    result = launch_source(server)
    assert (result.pin, result.source_id) == (PinStatus.NOT_APPLICABLE, "url:mcp.example.com")


def test_source_trust() -> None:
    assert source_trust("npm:@mcp/x", None) is SourceTrust.UNKNOWN
    assert source_trust("npm:@mcp/x", ["npm:@mcp/*"]) is SourceTrust.TRUSTED
    assert source_trust("npm:@evil/x", ["npm:@mcp/*"]) is SourceTrust.UNTRUSTED
    assert source_trust(None, ["npm:@mcp/*"]) is SourceTrust.UNTRUSTED
    # Matching is case-sensitive: no lookalike bypass via case folding.
    assert source_trust("npm:@MCP/x", ["npm:@mcp/*"]) is SourceTrust.UNTRUSTED


def test_parse_approval() -> None:
    approval = parse_approval("s", {"alwaysAllow": ["b", "a"], "autoApprove": ["a"]})
    assert approval.auto_approved_tools == ["a", "b"]
    assert approval.sources == ["alwaysAllow", "autoApprove"]
    assert parse_approval("s", {"trust": True}).auto_approve_all
    for bad in ({"alwaysAllow": "read_file"}, {"autoApprove": [1]}, {"trust": "yes"}):
        with pytest.raises(ConfigError):
            parse_approval("s", bad)

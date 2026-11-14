import json
import socket
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.discovery import discover
from agentcapmap.enumerate import enumerate_server
from agentcapmap.enumerate.netguard import check_remote_url, resolve_checked
from agentcapmap.enumerate.transport import TransportError
from agentcapmap.models import EnumerationStatus, Server
from tests.mock_mcp_server import MockHttpServer


def _remote(tmp_path: Path, url: str) -> Server:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"remote": {"type": "http", "url": url}}}))
    return discover([config]).agents[0].servers[0]


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.0.1:8080/mcp",
        "https://[fe80::1]/mcp",
        "http://[fd00:ec2::254]/",
        "http://[::ffff:169.254.169.254]/",
        "http://100.100.100.200/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://METADATA.GOOGLE.INTERNAL./x",
    ],
)
def test_blocks_metadata_and_link_local(url: str) -> None:
    with pytest.raises(TransportError):
        check_remote_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/mcp",
        "http://[::1]:8000/mcp",
        "http://10.0.0.5/mcp",
        "http://192.168.1.2/",
    ],
)
def test_loopback_and_private_stay_allowed(url: str) -> None:
    check_remote_url(url)


def _fake_getaddrinfo(address: str) -> Any:
    def getaddrinfo(host: str, *_args: Any, **_kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]

    return getaddrinfo


def test_blocks_name_that_resolves_to_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    with pytest.raises(TransportError):
        check_remote_url("http://innocent.example/mcp")


def test_allows_name_that_resolves_to_public(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    check_remote_url("https://mcp.example/")


def test_unresolvable_name_is_left_to_the_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    check_remote_url("https://nope.invalid/")


def test_url_without_host_is_refused() -> None:
    with pytest.raises(TransportError):
        check_remote_url("http:///mcp")


# --- pinning: the checked address is the one connected to ----------------------------


def _resolver(answers: dict[str, list[str]], calls: list[str]) -> Any:
    real = socket.getaddrinfo

    def getaddrinfo(host: str, *args: Any, **kwargs: Any) -> list[Any]:
        if host in answers:
            calls.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in answers[host]]
        if host.endswith(".test"):
            raise socket.gaierror("no such host")
        return real(host, *args, **kwargs)  # the pinned connection to an IP literal

    return getaddrinfo


def test_connection_goes_to_the_checked_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "pinned.test" exists only in our resolver, so the request can only have reached
    # the mock server through the address netguard checked.
    calls: list[str] = []
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({"pinned.test": ["127.0.0.1"]}, calls))
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    with MockHttpServer(mode="json") as mock:
        url = mock.url.replace("127.0.0.1", "pinned.test")
        result = enumerate_server(_remote(tmp_path, url), timeout=10)
    assert result.status is EnumerationStatus.OK, result.error
    assert "initialize" in mock.methods
    assert calls and set(calls) == {"pinned.test"}


def test_rebinding_to_metadata_is_refused_before_connecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # First lookup (the early check) is harmless; every later one answers with the
    # metadata address, as a DNS-rebinding server would.
    lookups = 0

    def getaddrinfo(host: str, *_args: Any, **_kwargs: Any) -> list[Any]:
        nonlocal lookups
        lookups += 1
        address = "127.0.0.1" if lookups == 1 else "169.254.169.254"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    with MockHttpServer(mode="json") as mock:
        url = mock.url.replace("127.0.0.1", "rebind.test")
        result = enumerate_server(_remote(tmp_path, url), timeout=10)
    assert result.status is not EnumerationStatus.OK
    assert "metadata" in (result.error or "")
    assert mock.methods == []  # nothing was sent anywhere
    assert lookups >= 2


def test_one_blocked_answer_refuses_the_whole_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket, "getaddrinfo", _resolver({"mixed.test": ["93.184.216.34", "169.254.169.254"]}, [])
    )
    with pytest.raises(TransportError):
        resolve_checked("mixed.test")


def test_resolve_checked_returns_only_checked_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket, "getaddrinfo", _resolver({"ok.test": ["10.0.0.5", "10.0.0.5", "10.0.0.6"]}, [])
    )
    assert resolve_checked("ok.test") == ["10.0.0.5", "10.0.0.6"]
    assert resolve_checked("127.0.0.1") == ["127.0.0.1"]
    assert resolve_checked("nope.test") == []

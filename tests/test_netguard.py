import socket
from typing import Any

import pytest

from agentcapmap.enumerate.netguard import check_remote_url
from agentcapmap.enumerate.transport import TransportError


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

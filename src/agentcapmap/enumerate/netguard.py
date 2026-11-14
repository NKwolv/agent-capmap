"""Refuse remote MCP URLs that point at link-local or cloud-metadata addresses.

Loopback and private ranges are deliberately allowed: local MCP servers commonly
listen on localhost, and a config the user chose to enumerate may name a LAN host.
Link-local space (169.254.0.0/16, fe80::/10) holds the cloud instance-metadata
services, which hand out credentials and are never an MCP server.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from agentcapmap.enumerate.transport import TransportError

_BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/Azure/GCP/OpenStack metadata, link-local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::/32"),  # AWS IPv6 metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
)
_BLOCKED_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data"})


def _blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in network for network in _BLOCKED_NETWORKS)


def resolve_checked(host: str) -> list[str]:
    """Resolve `host` and return its addresses, refusing blocked ones.

    The caller connects to exactly these addresses (see `PinnedTransport` in
    `http.py`), so the address that was checked is the address that is used and a
    DNS-rebinding server cannot switch to a blocked one in between. Returns an empty
    list when the name does not resolve.
    """
    host = host.lower().rstrip(".")
    if not host:
        raise TransportError("remote server URL has no host")
    if host in _BLOCKED_HOSTS:
        raise TransportError("remote server host is a cloud metadata name; refusing to connect")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if _blocked(literal):
            raise TransportError("remote server address is link-local/metadata; refusing")
        return [str(literal)]
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addresses: list[str] = []
    for info in infos:
        try:
            resolved = ipaddress.ip_address(str(info[4][0]))
        except ValueError:
            continue
        # One blocked answer refuses the whole name, even if other answers are fine.
        if _blocked(resolved):
            raise TransportError("remote server host resolves to a link-local/metadata address")
        if str(resolved) not in addresses:
            addresses.append(str(resolved))
    return addresses


def check_remote_url(url: str) -> None:
    """Raise TransportError if the URL's host is, or resolves to, a blocked address.

    An early, clear refusal before any transport is built. The transport repeats the
    check on the addresses it actually connects to; an unresolvable name is left to
    the connection attempt, which fails with its own error.
    """
    resolve_checked(urlsplit(url).hostname or "")

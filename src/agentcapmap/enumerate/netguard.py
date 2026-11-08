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


def check_remote_url(url: str) -> None:
    """Raise TransportError if the URL's host is, or resolves to, a blocked address."""
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
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
        return
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return  # unresolvable: the connection attempt will fail with its own error
    # SECURITY-REVIEW: this resolves the name once to check it, then httpx resolves it
    # again to connect, so a DNS-rebinding server could still switch to a blocked
    # address in between. Pinning the checked IP needs a custom httpx transport.
    for info in infos:
        try:
            resolved = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _blocked(resolved):
            raise TransportError("remote server host resolves to a link-local/metadata address")

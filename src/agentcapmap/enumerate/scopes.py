"""Opt-in check of what a configured GitHub token is allowed to do (`--check-token-scopes`).

A config shows that a server holds a token, not how much the token can do: a read-only
token and one that can delete repositories look the same. GitHub reports the scopes of a
classic token in a response header, so with the user's explicit opt-in the token is
presented to GitHub's own API once and the scope names are recorded.

What keeps this safe:
- Off by default. It is the only place agent-capmap sends a credential anywhere other
  than the server the config already sends it to.
- The token goes to `https://api.github.com` only: a fixed URL, TLS, no redirects, the
  pinned-address client. It is never sent to a host named in a config.
- Only values shaped like GitHub tokens are considered, and nothing is sent when the
  config points at a GitHub Enterprise host (the token would belong to that host).
- Fine-grained and app tokens do not expose their permissions this way: they are
  reported as "not visible" without any request.
- Only scope names are kept. The token itself stays in the unserialized launch spec.
"""

from __future__ import annotations

import re

import httpx

from agentcapmap.enumerate.http import _client
from agentcapmap.enumerate.transport import TransportError
from agentcapmap.models import CredentialInfo, LaunchSpec

# A cheap authenticated endpoint that does not count against the rate limit.
GITHUB_API = "https://api.github.com/rate_limit"
_SCOPED = re.compile(r"^gh[po]_[A-Za-z0-9]{36,251}$")  # classic PAT, OAuth token
_OPAQUE = re.compile(r"^(?:github_pat_[A-Za-z0-9_]{22,251}|gh[usr]_[A-Za-z0-9]{36,251})$")
_HEADER_PREFIX = re.compile(r"^(?:bearer|token)\s+", re.IGNORECASE)
# Variables that point a server at a GitHub Enterprise host instead of github.com.
_ENTERPRISE_VARS = re.compile(
    r"^(GH_HOST|GITHUB_HOST|GITHUB_API_URL|GH_ENTERPRISE_.*|GITHUB_ENTERPRISE_.*)$"
)
_GITHUB_HOSTS = ("github.com", "githubcopilot.com")
_MAX_SCOPES = 100

_ADMIN_SCOPES = frozenset({"delete_repo", "site_admin", "delete:packages"})
_READ_SCOPES = frozenset({"repo:status", "repo:invite", "user:email", "user:follow"})


def breadth(scopes: list[str]) -> str:
    """admin: can delete or administer; write: can change things; read: read-only."""
    if any(s in _ADMIN_SCOPES or s.startswith("admin:") for s in scopes):
        return "admin"
    if all(s.startswith("read:") or s in _READ_SCOPES for s in scopes):
        return "read"  # includes a token with no scopes at all (public data only)
    return "write"


def _candidates(spec: LaunchSpec) -> list[tuple[str, str]]:
    found = [(f"env:{name}", value) for name, value in spec.env.items()]
    found += [
        (f"header:{name}", _HEADER_PREFIX.sub("", value)) for name, value in spec.headers.items()
    ]
    for arg in spec.args:
        flag, _, value = arg.partition("=")
        found.append((f"arg:{flag}" if value else "arg", value or arg))
    return [(source, value.strip()) for source, value in found]


def _enterprise(spec: LaunchSpec) -> bool:
    if any(_ENTERPRISE_VARS.match(name) and value for name, value in spec.env.items()):
        return True
    if not spec.url:
        return False
    host = (httpx.URL(spec.url).host or "").lower()
    return not any(host == known or host.endswith("." + known) for known in _GITHUB_HOSTS)


def find_github_token(spec: LaunchSpec) -> tuple[str, str, bool] | None:
    """(where it is configured, the token, whether its scopes can be read) or None."""
    for source, value in _candidates(spec):
        if _SCOPED.match(value):
            return source, value, True
        if _OPAQUE.match(value):
            return source, value, False
    return None


def _not_visible(source: str, detail: str) -> CredentialInfo:
    return CredentialInfo(provider="github", source=source, status="not_visible", detail=detail)


def check_github_token(spec: LaunchSpec, timeout: float) -> CredentialInfo | None:
    """Scope names of the GitHub token in this launch spec, or None if there is none."""
    found = find_github_token(spec)
    if found is None:
        return None
    source, token, readable = found
    if not readable:
        return _not_visible(source, "fine-grained or app token: permissions are not exposed")
    if _enterprise(spec):
        return _not_visible(source, "server is not on github.com: token not sent anywhere")

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    try:
        with _client(GITHUB_API, headers, timeout) as client:
            response = client.get(GITHUB_API)
    except (httpx.HTTPError, TransportError) as exc:
        # Exception text could embed the request; report only its type.
        return CredentialInfo(
            provider="github", source=source, status="error", detail=type(exc).__name__
        )
    if response.status_code == 401:
        return CredentialInfo(
            provider="github", source=source, status="rejected", detail="GitHub rejected the token"
        )
    listed = response.headers.get("x-oauth-scopes")
    if response.status_code != 200 or listed is None:
        return CredentialInfo(
            provider="github",
            source=source,
            status="error",
            detail=f"HTTP {response.status_code} without a scope list",
        )
    names = (re.sub(r"[^A-Za-z0-9:_-]", "", s)[:64] for s in listed.split(","))
    scopes = sorted({name for name in names if name})[:_MAX_SCOPES]
    return CredentialInfo(
        provider="github", source=source, status="checked", scopes=scopes, breadth=breadth(scopes)
    )

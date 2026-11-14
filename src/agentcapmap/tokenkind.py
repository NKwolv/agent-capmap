"""Recognize what kind of GitHub token a server is configured with, from its shape alone.

A config shows that a server holds a token, not how much the token can do. GitHub token
formats do say one useful thing without asking anyone: a classic personal access token
(`ghp_`) reaches every repository its owner can and cannot be limited to some of them,
while a fine-grained one (`github_pat_`) can. That is enough to recommend the safer kind.

Nothing is sent anywhere and nothing but the kind and where it is configured is kept;
the token itself stays in the unserialized launch spec.
"""

from __future__ import annotations

import re

from agentcapmap.models import CredentialInfo, LaunchSpec, TokenKind

_KINDS: tuple[tuple[re.Pattern[str], TokenKind], ...] = (
    (re.compile(r"^ghp_[A-Za-z0-9]{36,251}$"), "classic"),
    (re.compile(r"^github_pat_[A-Za-z0-9_]{22,251}$"), "fine_grained"),
    (re.compile(r"^gho_[A-Za-z0-9]{36,251}$"), "oauth"),
    (re.compile(r"^gh[usr]_[A-Za-z0-9]{36,251}$"), "app"),
)
_HEADER_PREFIX = re.compile(r"^(?:bearer|token)\s+", re.IGNORECASE)


def _candidates(spec: LaunchSpec) -> list[tuple[str, str]]:
    found = [(f"env:{name}", value) for name, value in spec.env.items()]
    found += [
        (f"header:{name}", _HEADER_PREFIX.sub("", value)) for name, value in spec.headers.items()
    ]
    for arg in spec.args:
        flag, _, value = arg.partition("=")
        found.append((f"arg:{flag}" if value else "arg", value or arg))
    return [(source, value.strip()) for source, value in found]


def github_token(spec: LaunchSpec) -> CredentialInfo | None:
    """The first GitHub token in this launch spec, as its kind and where it is configured."""
    for source, value in _candidates(spec):
        for pattern, kind in _KINDS:
            if pattern.match(value):
                return CredentialInfo(provider="github", source=source, kind=kind)
    return None

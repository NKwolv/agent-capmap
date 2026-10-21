"""Helpers shared by the per-format config parsers."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentcapmap.models import (
    ApprovalConfig,
    AuthHint,
    AuthMethod,
    LaunchSpec,
    Server,
    SourceLocation,
    Transport,
)
from agentcapmap.redact import (
    is_sensitive_name,
    known_secrets,
    redact_args,
    redact_text,
    redact_url,
    redact_value,
    sensitive_arg_names,
)


class ConfigError(ValueError):
    """A config file exists but cannot be parsed into servers."""


@dataclass(frozen=True)
class ConfigFormat:
    """One client config format. Parsers are isolated per format so they can evolve alone."""

    name: str
    client: str
    matches: Callable[[Path], bool]
    # (file text, real path, path to show in output) -> servers
    parse: Callable[[str, Path, str], list[Server]]


def load_jsonc(text: str) -> Any:
    """Parse JSON that may contain // and /* */ comments and trailing commas (VS Code style)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] not in "\r\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise ConfigError("unterminated block comment")
            out.append("\n" * text.count("\n", i, end))  # keep line numbers stable
            i = end + 2
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "]}":
                i += 1  # drop trailing comma
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    try:
        return json.loads("".join(out))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON: {exc.msg} at line {exc.lineno}") from None
    except RecursionError:
        raise ConfigError("invalid JSON: nested too deeply") from None


def find_key_line(text: str, key: str, start: int = 0) -> int | None:
    """1-based line of the first `"key":` at or after offset `start`."""
    m = re.compile(r'"' + re.escape(json.dumps(key)[1:-1]) + r'"\s*:').search(text, start)
    if m is None:
        return None
    return text.count("\n", 0, m.start()) + 1


def section_offset(text: str, key: str, after: int = 0) -> int:
    m = re.compile(r'"' + re.escape(key) + r'"\s*:').search(text, after)
    return m.end() if m else after


_TRANSPORT_ALIASES = {
    "stdio": Transport.STDIO,
    "http": Transport.HTTP,
    "streamable-http": Transport.HTTP,
    "streamablehttp": Transport.HTTP,
    "streamable_http": Transport.HTTP,
    "sse": Transport.SSE,
}


def infer_transport(entry: dict[str, Any], url: str | None) -> Transport:
    declared = entry.get("type") or entry.get("transport")
    if declared is not None and not isinstance(declared, str):
        raise ConfigError(f"transport type must be a string, got {declared!r}")
    if declared:
        transport = _TRANSPORT_ALIASES.get(declared.strip().lower())
        if transport is None:
            raise ConfigError(f"unknown transport type {declared!r}")
        return transport
    if url:
        path = url.split("?", 1)[0].rstrip("/")
        return Transport.SSE if path.endswith("/sse") else Transport.HTTP
    return Transport.STDIO


def _str_dict(value: Any, field: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{field!r} must be an object")
    return {str(k): "" if v is None else str(v) for k, v in value.items()}


def _str_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{field!r} must be an array")
    return [str(v) for v in value]


def infer_auth(
    transport: Transport,
    env: dict[str, str],
    headers: dict[str, str],
    args: list[str],
    url: str | None,
    env_file: str | None,
) -> AuthHint:
    """Best-effort auth classification from config alone. Names only, never values."""
    evidence: list[str] = []
    evidence += [f"header:{k}" for k in headers if is_sensitive_name(k)]
    evidence += [f"env:{k}" for k in env if is_sensitive_name(k)]
    evidence += [f"arg:{name}" for name in sensitive_arg_names(args)]
    if url and redact_url(url) != url:
        evidence.append("url:embedded-credential")
    if evidence:
        return AuthHint(method=AuthMethod.STATIC, evidence=evidence)
    if env_file:
        return AuthHint(method=AuthMethod.UNKNOWN, evidence=["envFile"])
    if transport is Transport.STDIO:
        # Local process: no credential in config, but it inherits the user's ambient identity.
        return AuthHint(method=AuthMethod.NONE)
    # Remote with no credential in config: either open, or OAuth negotiated at connect time.
    return AuthHint(method=AuthMethod.UNKNOWN)


# Keys clients use to skip per-call confirmation: Cline/Roo `alwaysAllow`, `autoApprove`
# (list of tool names), and Gemini CLI `trust: true` (all tools).
_AUTO_APPROVE_LIST_KEYS = ("alwaysAllow", "autoApprove")
_MAX_APPROVAL_ENTRIES = 1000


def parse_approval(name: str, entry: dict[str, Any]) -> ApprovalConfig:
    tools: list[str] = []
    sources: list[str] = []
    for key in _AUTO_APPROVE_LIST_KEYS:
        value = entry.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(t, str) for t in value):
            raise ConfigError(f"server {name!r}: {key!r} must be an array of tool names")
        if len(value) > _MAX_APPROVAL_ENTRIES:
            raise ConfigError(f"server {name!r}: {key!r} has too many entries")
        tools.extend(value)
        sources.append(key)
    trust = entry.get("trust")
    if trust is not None and not isinstance(trust, bool):
        raise ConfigError(f"server {name!r}: 'trust' must be true or false")
    if trust:
        sources.append("trust")
    return ApprovalConfig(
        auto_approve_all=bool(trust), auto_approved_tools=sorted(set(tools)), sources=sources
    )


def build_server(
    name: str,
    entry: Any,
    *,
    config_path: str,
    text: str,
    section_start: int,
    base_dir: Path,
) -> Server:
    """Normalize one server entry. Raw values go to LaunchSpec; everything else is redacted."""
    if not isinstance(entry, dict):
        raise ConfigError(f"server {name!r}: entry must be an object")

    url_value = entry.get("url") or entry.get("serverUrl")
    url = str(url_value) if url_value else None
    command = entry.get("command")
    if command is not None and not isinstance(command, str):
        raise ConfigError(f"server {name!r}: 'command' must be a string")
    if not command and not url:
        raise ConfigError(f"server {name!r}: needs either 'command' or 'url'")

    try:
        transport = infer_transport(entry, url)
        args = _str_list(entry.get("args"), "args")
        env = _str_dict(entry.get("env"), "env")
        headers = _str_dict(entry.get("headers"), "headers")
    except ConfigError as exc:
        raise ConfigError(f"server {name!r}: {exc}") from None
    env_file = entry.get("envFile")
    cwd = entry.get("cwd")

    for value in [*env.values(), *headers.values()]:
        known_secrets.add(value)

    return Server(
        name=name,
        transport=transport,
        command=redact_text(command) if command else None,
        args=redact_args(args),
        url=redact_url(url) if url else None,
        env={k: redact_value(v) for k, v in env.items()},
        headers={k: redact_value(v) for k, v in headers.items()},
        auth=infer_auth(transport, env, headers, args, url, env_file if env_file else None),
        location=SourceLocation(path=config_path, line=find_key_line(text, name, section_start)),
        disabled=bool(entry.get("disabled", False)),
        approval=parse_approval(name, entry),
        launch=LaunchSpec(
            command=command,
            args=args,
            env=env,
            env_file=str(env_file) if env_file else None,
            cwd=str(cwd) if cwd else None,
            url=url,
            headers=headers,
            # Absolute, so ${workspaceFolder} and the server cwd do not depend on how the
            # scan path was written (never serialized, so it does not leak into output).
            base_dir=str(base_dir.resolve()),
        ),
    )


def parse_server_map(
    servers: Any,
    *,
    config_path: str,
    text: str,
    section_key: str,
    base_dir: Path,
    search_from: int = 0,
) -> list[Server]:
    if servers is None:
        return []
    if not isinstance(servers, dict):
        raise ConfigError(f"{section_key!r} must be an object mapping names to servers")
    start = section_offset(text, section_key, search_from)
    return [
        build_server(
            str(name),
            entry,
            config_path=config_path,
            text=text,
            section_start=start,
            base_dir=base_dir,
        )
        for name, entry in servers.items()
    ]

"""Server-level attributes derived from config alone (never from the LLM).

- version pinning: is the launched code fixed to an exact version or digest?
- source id: a stable name for where the code comes from, for trust allowlists.

Parsing uses the redacted command line stored in the inventory, so it works on saved
inventories too. Package names and versions are not secrets and survive redaction.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePath
from urllib.parse import urlsplit

from agentcapmap.models import Server, Transport


class PinStatus(StrEnum):
    PINNED = "pinned"
    UNPINNED = "unpinned"
    LOCAL = "local"  # code in a local file; versioned with the repo or machine
    NOT_APPLICABLE = "not_applicable"  # remote server: nothing to pin client-side
    UNKNOWN = "unknown"


class SourceTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"  # no trusted_sources configured


@dataclass(frozen=True)
class LaunchSource:
    pin: PinStatus
    source_id: str | None  # e.g. "npm:@modelcontextprotocol/server-filesystem"
    spec: str | None = None  # the package/image spec as written


_EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$")
_EXACT_PEP440 = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")
_NPM_RUNNERS = {"npx", "bunx"}
_PYTHON_RUNNERS = {"uvx"}
_CONTAINER_RUNNERS = {"docker", "podman"}
_SCRIPT_RUNNERS = {"node", "python", "python3", "deno", "bun", "tsx", "ts-node"}
_SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".py")
# docker/podman run flags that take a separate value argument.
_CONTAINER_VALUE_FLAGS = frozenset(
    {
        "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish",
        "--network", "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "-l",
        "--label", "--platform", "--pull", "--cpus", "-m", "--memory", "--add-host",
        "--cap-add", "--cap-drop", "--security-opt", "-h", "--hostname", "--ulimit",
        "--tmpfs", "--device", "--dns", "--restart", "--runtime", "--shm-size", "--ipc",
        "--pid", "--userns", "--log-driver", "--log-opt", "--gpus",
    }
)  # fmt: skip


def _program(command: str | None) -> str:
    if not command:
        return ""
    name = PurePath(command.replace("\\", "/")).name.lower()
    return name.removesuffix(".exe").removesuffix(".cmd").removesuffix(".bat")


def _first_positional(args: list[str], value_flags: frozenset[str] = frozenset()) -> int | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return i + 1 if i + 1 < len(args) else None
        if arg.startswith("-"):
            if arg in value_flags and "=" not in arg:
                i += 2
                continue
            i += 1
            continue
        return i
    return None


def _npm_spec(spec: str) -> LaunchSource:
    # "@scope/name@1.2.3", "name@1.2.3", "name@latest", "name"
    at = spec.rfind("@")
    name, version = (spec[:at], spec[at + 1 :]) if at > 0 else (spec, "")
    pin = PinStatus.PINNED if _EXACT_SEMVER.match(version) else PinStatus.UNPINNED
    return LaunchSource(pin=pin, source_id=f"npm:{name}", spec=spec)


def _pypi_spec(spec: str) -> LaunchSource:
    # "name==1.2.3", "name@1.2.3" (uvx), "name@latest", "name>=1", "name"
    if "==" in spec:
        name, version = spec.split("==", 1)
    elif "@" in spec:
        name, version = spec.split("@", 1)
    else:
        name, version = re.split(r"[<>=!~\[]", spec, maxsplit=1)[0], ""
    pin = PinStatus.PINNED if _EXACT_PEP440.match(version) else PinStatus.UNPINNED
    return LaunchSource(pin=pin, source_id=f"pypi:{name.strip().lower()}", spec=spec)


def _image_spec(image: str) -> LaunchSource:
    if "@sha256:" in image:
        name = image.split("@", 1)[0]
        return LaunchSource(pin=PinStatus.PINNED, source_id=f"docker:{name}", spec=image)
    # Tags are mutable, so anything short of a digest is not pinned.
    last = image.rsplit("/", 1)[-1]
    name = image.rsplit(":", 1)[0] if ":" in last else image
    return LaunchSource(pin=PinStatus.UNPINNED, source_id=f"docker:{name}", spec=image)


def launch_source(server: Server) -> LaunchSource:
    if server.transport is not Transport.STDIO:
        host = (urlsplit(server.url or "").hostname or "").lower()
        return LaunchSource(PinStatus.NOT_APPLICABLE, f"url:{host}" if host else None)

    program, args = _program(server.command), server.args
    if program in _NPM_RUNNERS or (program == "npm" and args[:1] == ["exec"]):
        rest = args[1:] if program == "npm" else args
        idx = _first_positional(rest, frozenset({"-p", "--package"}))
        if idx is not None:
            return _npm_spec(rest[idx])
    elif program in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        idx = _first_positional(args[1:])
        if idx is not None:
            return _npm_spec(args[1:][idx])
    elif program in _PYTHON_RUNNERS or (program == "pipx" and args[:1] == ["run"]):
        rest = args[1:] if program == "pipx" else args
        if "--from" in rest and rest.index("--from") + 1 < len(rest):
            return _pypi_spec(rest[rest.index("--from") + 1])
        idx = _first_positional(rest, frozenset({"--python", "--with", "-p"}))
        if idx is not None:
            return _pypi_spec(rest[idx])
    elif program in _CONTAINER_RUNNERS and args[:1] == ["run"]:
        idx = _first_positional(args[1:], _CONTAINER_VALUE_FLAGS)
        if idx is not None:
            return _image_spec(args[1:][idx])
    elif program in _SCRIPT_RUNNERS:
        idx = _first_positional(args)
        if idx is not None and args[idx].lower().endswith(_SCRIPT_SUFFIXES):
            return LaunchSource(PinStatus.LOCAL, f"local:{args[idx]}", spec=args[idx])
    # An explicit path to a script or binary: code already on disk, not fetched at launch.
    if server.command and (
        server.command.lower().endswith(_SCRIPT_SUFFIXES)
        or "/" in server.command
        or "\\" in server.command
    ):
        return LaunchSource(PinStatus.LOCAL, f"local:{server.command}", spec=server.command)
    return LaunchSource(PinStatus.UNKNOWN, None)


def source_trust(source_id: str | None, trusted_sources: list[str] | None) -> SourceTrust:
    if not trusted_sources:
        return SourceTrust.UNKNOWN
    if source_id is None:
        return SourceTrust.UNTRUSTED
    # fnmatchcase: case-sensitive, no filesystem semantics; patterns come from the policy.
    if any(fnmatch.fnmatchcase(source_id, pattern) for pattern in trusted_sources):
        return SourceTrust.TRUSTED
    return SourceTrust.UNTRUSTED

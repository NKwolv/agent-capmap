"""Runtime guard: a Claude Code `PreToolUse` hook that stops a dangerous combination as it
is about to happen.

The scan reports what an agent *could* do. This hook follows what one session has
*actually* done and, when the next MCP tool call would complete a policy rule (for
example send data out after the session read attacker-controllable content and private
data), asks the user or denies the call.

How it decides (no LLM, no network, standard library only so it starts fast):
- The guard map (`agentcapmap guard build`) gives each tool's capability tags and the
  combination rules, split into *sink* steps (egress, mutation, execution, privilege:
  the step that does damage) and *source* steps (what was read).
- A call is flagged when it matches a sink step of a rule and every other step is
  already satisfied. Untrusted content must have been read by an *earlier* call (an
  instruction has to arrive before it can be followed); other steps may also be
  satisfied by the call itself.
- Every call that is not denied is recorded per session: tool name and tags only, never
  arguments or results.

Fail closed: Claude Code lets a call through when a hook exits with an unexpected code,
so every error here ends in exit code 2, which blocks the call. A tool the map does not
know is never treated as safe (`--unknown`, default: ask). The guard never approves a
call: when it has no objection it says nothing and the normal permission flow applies.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

GUARD_MAP_VERSION = 1
AXES = ("data_access", "untrusted_input", "egress", "mutation", "execution", "privilege")
# Axes that act on the world; a rule step naming one of them is a sink.
SINK_AXES = frozenset({"egress", "mutation", "execution", "privilege"})
STATE_DIR_ENV = "AGENTCAPMAP_GUARD_DIR"

MAX_MAP_BYTES = 32 * 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024  # the hook input carries the tool's arguments
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_NAME_CHARS = 512
_STATE_MAX_AGE_SECONDS = 30 * 24 * 3600
_MAX_PRUNED_PER_RUN = 50
_MAX_LISTED = 5

EXIT_BLOCK = 2  # the only exit code Claude Code treats as "block this call"

# Claude Code's own tools, tracked (never blocked) with --track-builtins: what they read
# can taint the session for later MCP calls. A rough table, documented as such.
BUILTIN_SOURCES: dict[str, dict[str, Any]] = {
    "WebFetch": {"untrusted_input": True},
    "WebSearch": {"untrusted_input": True},
    "Read": {"data_access": "private_read"},
    "Grep": {"data_access": "private_read"},
}

Tags = dict[str, Any]
NO_CAPABILITY: Tags = {
    "data_access": "none",
    "untrusted_input": False,
    "egress": "none",
    "mutation": "none",
    "execution": "none",
    "privilege": "none",
}
Step = dict[str, list[Any]]


class GuardError(Exception):
    """Anything that prevents a trustworthy decision. Always ends in a blocked call."""


def clean(text: object, limit: int = 120) -> str:
    """Printable ASCII only: tool names come from MCP servers and are shown to the user."""
    kept = "".join(c if " " <= c <= "~" else "?" for c in str(text))
    return kept if len(kept) <= limit else kept[: limit - 3] + "..."


def default_state_dir() -> Path:
    if env := os.environ.get(STATE_DIR_ENV):
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "agentcapmap" / "guard"


# --- guard map -------------------------------------------------------------------------


def _check_tags(tags: object, where: str) -> Tags:
    if not isinstance(tags, dict) or set(tags) != set(AXES):
        raise GuardError(f"guard map: {where} must have exactly the six capability axes")
    for axis, value in tags.items():
        if not isinstance(value, bool if axis == "untrusted_input" else str):
            raise GuardError(f"guard map: {where} has an invalid value for {axis}")
    return tags


def _check_steps(steps: object, where: str) -> list[Step]:
    if not isinstance(steps, list):
        raise GuardError(f"guard map: {where} must be a list")
    for step in steps:
        if not isinstance(step, dict) or not step or not set(step) <= set(AXES):
            raise GuardError(f"guard map: {where} has an invalid step")
        if not all(isinstance(allowed, list) and allowed for allowed in step.values()):
            raise GuardError(f"guard map: {where} has a step without allowed values")
    return steps


def load_map(path: Path) -> dict[str, Any]:
    """Read and validate a guard map. Any doubt about it is an error (the call is blocked)."""
    try:
        if path.stat().st_size > MAX_MAP_BYTES:
            raise GuardError("guard map is too large")
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GuardError(f"cannot read the guard map: {exc.strerror}") from None
    except (ValueError, RecursionError):
        raise GuardError("guard map is not valid JSON") from None
    if not isinstance(data, dict) or data.get("guard_map_version") != GUARD_MAP_VERSION:
        raise GuardError("guard map has an unsupported version; rebuild it")
    tools, rules, unassessed = data.get("tools"), data.get("rules"), data.get("unassessed")
    if not isinstance(tools, dict) or not isinstance(rules, list):
        raise GuardError("guard map is missing its tools or rules")
    if not isinstance(unassessed, list):
        raise GuardError("guard map is missing its list of unassessed tools")
    for name, entry in tools.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str):
            raise GuardError(f"guard map: tool {clean(name)} is malformed")
        _check_tags(entry.get("tags"), f"tool {clean(name)}")
    for rule in rules:
        if not isinstance(rule, dict) or not all(
            isinstance(rule.get(key), str) for key in ("id", "severity", "message")
        ):
            raise GuardError("guard map: a rule is malformed")
        if not _check_steps(rule.get("sinks"), f"rule {clean(rule['id'])} sinks"):
            raise GuardError(f"guard map: rule {clean(rule['id'])} has no sink step")
        _check_steps(rule.get("sources"), f"rule {clean(rule['id'])} sources")
    return data


# --- session state ---------------------------------------------------------------------


def _state_path(state_dir: Path, session_id: str) -> Path:
    # Hashed: the session id never becomes part of a path.
    digest = hashlib.sha256(session_id.encode("utf-8", "replace")).hexdigest()[:32]
    return state_dir / f"{digest}.jsonl"


def read_seen(path: Path) -> list[dict[str, Any]]:
    """Tools this session has already been allowed to call (name and tags only)."""
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise GuardError(f"guard state is too large ({path})")
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError):
        raise GuardError(f"cannot read the guard state ({path})") from None
    seen: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            raise GuardError(f"guard state is corrupt; delete it to reset ({path})") from None
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str):
            raise GuardError(f"guard state is corrupt; delete it to reset ({path})")
        _check_tags(entry.get("tags"), "a state entry")
        seen.append(entry)
    return seen


def _prune(state_dir: Path) -> None:
    """Drop state files of sessions that ended long ago (best effort, bounded)."""
    cutoff = time.time() - _STATE_MAX_AGE_SECONDS
    removed = 0
    with contextlib.suppress(OSError):
        for entry in os.scandir(state_dir):
            name = entry.name
            if len(name) != 38 or not name.endswith(".jsonl") or not entry.is_file():
                continue  # only files this module names
            if entry.stat().st_mtime < cutoff:
                with contextlib.suppress(OSError):
                    Path(entry.path).unlink()
                removed += 1
                if removed >= _MAX_PRUNED_PER_RUN:
                    return


def record(path: Path, seen: list[dict[str, Any]], ref: str, tags: Tags) -> None:
    """Append one tool to the session record, once. Failing to record blocks the call."""
    if any(entry["ref"] == ref and entry["tags"] == tags for entry in seen):
        return
    line = json.dumps({"ref": ref, "tags": tags}, separators=(",", ":")) + "\n"
    try:
        if not path.parent.is_dir():
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not path.exists():
            _prune(path.parent)
        # O_APPEND: a single small write lands whole even when calls run in parallel.
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as exc:
        raise GuardError(f"cannot record the call in the guard state: {exc.strerror}") from None


# --- decision --------------------------------------------------------------------------


def _matches(step: Step, tags: Tags) -> bool:
    return all(tags.get(axis) in allowed for axis, allowed in step.items())


def violations(
    rules: list[dict[str, Any]], seen: list[dict[str, Any]], current: Tags
) -> list[tuple[dict[str, Any], list[str]]]:
    """Rules this call would complete, each with the earlier tools that set it up."""
    found = []
    for rule in rules:
        sinks, sources = rule["sinks"], rule["sources"]
        for index, sink in enumerate(sinks):
            if not _matches(sink, current):
                continue
            others = [*sources, *(s for i, s in enumerate(sinks) if i != index)]
            earlier: list[str] = []
            for step in others:
                refs = [entry["ref"] for entry in seen if _matches(step, entry["tags"])]
                # An instruction has to be read before it can be followed, so untrusted
                # input counts only from earlier calls; anything else this call may do itself.
                if not refs and ("untrusted_input" in step or not _matches(step, current)):
                    break
                earlier.extend(r for r in refs if r not in earlier)
            else:
                found.append((rule, earlier))
                break
    return found


def _reason(ref: str, found: list[tuple[dict[str, Any], list[str]]]) -> str:
    parts = []
    for rule, earlier in found[:3]:
        rule_id, severity = clean(rule["id"], 40), clean(rule["severity"], 12)
        text = f"{rule_id} ({severity}): {clean(rule['message'], 400)}"
        if earlier:
            listed = ", ".join(clean(r) for r in earlier[:_MAX_LISTED])
            more = f" and {len(earlier) - _MAX_LISTED} more" if len(earlier) > _MAX_LISTED else ""
            text += f" Earlier in this session: {listed}{more}."
        parts.append(text)
    return (
        f"agent-capmap guard: calling {clean(ref)} would complete a risky combination. "
        + " ".join(parts)
    )


def decide(
    guard_map: dict[str, Any],
    seen: list[dict[str, Any]],
    tool_name: str,
    *,
    on_violation: str = "ask",
    unknown: str = "ask",
) -> tuple[str | None, str, tuple[str, Tags] | None]:
    """(decision, reason, what to record). A decision of None means "no objection"."""
    entry = guard_map["tools"].get(tool_name)
    if entry is None:
        why = (
            "is not classified"
            if tool_name in guard_map["unassessed"]
            else "is not in the guard map (rebuild it after changing MCP servers)"
        )
        if unknown == "allow":
            return None, "", None
        return (
            unknown,
            f"agent-capmap guard: {clean(tool_name)} {why}, so it was not assessed.",
            None,
        )
    found = violations(guard_map["rules"], seen, entry["tags"])
    recorded = (entry["ref"], entry["tags"])
    if not found:
        return None, "", recorded
    # Asked calls may be approved by the user, so they are recorded; denied ones never run.
    return on_violation, _reason(entry["ref"], found), recorded if on_violation == "ask" else None


# --- hook entry point ------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentcapmap guard hook",
        description="Claude Code PreToolUse hook: reads the hook input on stdin.",
    )
    parser.add_argument("--map", type=Path, required=True, help="guard map from `guard build`")
    parser.add_argument(
        "--state-dir", type=Path, help=f"session records (default: ${STATE_DIR_ENV})"
    )
    parser.add_argument(
        "--on-violation",
        choices=("ask", "deny"),
        default="ask",
        help="ask the user (default) or deny outright when a call completes a rule",
    )
    parser.add_argument(
        "--unknown",
        choices=("ask", "deny", "allow"),
        default="ask",
        help="MCP tools missing from the map: ask (default), deny, or leave to the normal flow",
    )
    parser.add_argument(
        "--track-builtins",
        action="store_true",
        help="also record what WebFetch, WebSearch, Read and Grep bring into the session",
    )
    return parser


def _read_input() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise GuardError("hook input is too large")
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise GuardError("hook input is not valid JSON") from None
    if not isinstance(data, dict):
        raise GuardError("hook input is not an object")
    return data


def _field(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value or len(value) > MAX_NAME_CHARS:
        raise GuardError(f"hook input has no usable {key}")
    return value


def run(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    data = _read_input()
    if data.get("hook_event_name") != "PreToolUse":
        return 0  # registered for another event by mistake: nothing to decide
    tool_name = _field(data, "tool_name")
    is_mcp = tool_name.startswith("mcp__")
    builtin = BUILTIN_SOURCES.get(tool_name) if args.track_builtins else None
    if not is_mcp and builtin is None:
        return 0

    state = _state_path(args.state_dir or default_state_dir(), _field(data, "session_id"))
    seen = read_seen(state)
    if not is_mcp and builtin is not None:
        record(state, seen, f"builtin/{tool_name}", {**NO_CAPABILITY, **builtin})
        return 0

    decision, reason, recorded = decide(
        load_map(args.map), seen, tool_name, on_violation=args.on_violation, unknown=args.unknown
    )
    if recorded is not None:
        record(state, seen, *recorded)
    if decision is not None:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
        sys.stdout.write(json.dumps(output) + "\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Never returns an exit code Claude Code would read as "let the call through"."""
    try:
        return run(argv)
    except GuardError as exc:
        print(f"agent-capmap guard blocked this call (failing closed): {exc}", file=sys.stderr)
    except SystemExit as exc:  # argparse: bad options are a failure too, --help is not
        if exc.code in (0, None):
            return 0
        print("agent-capmap guard blocked this call: invalid hook options", file=sys.stderr)
    except (Exception, KeyboardInterrupt) as exc:  # bugs and interrupts fail closed too
        print(
            f"agent-capmap guard blocked this call (failing closed): {type(exc).__name__}",
            file=sys.stderr,
        )
    return EXIT_BLOCK


if __name__ == "__main__":
    sys.exit(main())

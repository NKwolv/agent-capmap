"""Capture real tool definitions for the evaluation set.

For each server in eval/catalog.json this starts the pinned server with dummy
credentials, sends only `initialize` + `tools/list` (through agent-capmap's own
enumerator), and writes eval/labeled_servers/<id>.json with the definitions and an
empty label slot per tool.

This RUNS the catalog's third-party server packages. Run it only if you accept that,
ideally in a disposable VM or container. Servers get agent-capmap's minimal environment
plus HOME/USERPROFILE pointed at a throwaway sandbox directory.

    python eval/capture.py                 # capture servers not captured yet
    python eval/capture.py --only fetch    # just one
    python eval/capture.py --force         # re-capture unlabeled files

A file that already contains labels is never overwritten.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from agentcapmap import __version__
from agentcapmap.discovery import parse_config_file
from agentcapmap.enumerate import enumerate_server
from agentcapmap.enumerate.hashing import server_definition_hash, tool_definition_hash
from agentcapmap.models import EnumerationStatus

EVAL_DIR = Path(__file__).resolve().parent
CATALOG = EVAL_DIR / "catalog.json"
OUT_DIR = EVAL_DIR / "labeled_servers"
BACKSLASH = chr(92)
NEWLINE = chr(10)


def _local_paths(sandbox: Path | None) -> list[tuple[str, str]]:
    """Machine-specific paths to replace in captured text, longest first."""
    pairs = [(str(Path(tempfile.gettempdir())), "<TEMP>"), (str(Path.home()), "<HOME>")]
    if sandbox is not None:
        pairs.insert(0, (str(sandbox), "<SANDBOX>"))
    variants = []
    for path, placeholder in pairs:
        for form in {path, path.replace(BACKSLASH, "/"), path.replace("/", BACKSLASH)}:
            variants.append((form, placeholder))
    return sorted(variants, key=lambda pair: len(pair[0]), reverse=True)


def scrub(value: Any, paths: list[tuple[str, str]]) -> Any:
    """Replace local paths (user names, temp dirs) in captured definitions."""
    if isinstance(value, str):
        for path, placeholder in paths:
            value = value.replace(path, placeholder)
        return value
    if isinstance(value, list):
        return [scrub(v, paths) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v, paths) for k, v in value.items()}
    return value


def scrub_file(path: Path, paths: list[tuple[str, str]]) -> bool:
    """Scrub a captured file in place, recomputing hashes. Labels are kept."""
    data = json.loads(path.read_text(encoding="utf-8"))
    changed = False
    for tool in data["tools"]:
        description = scrub(tool["description"], paths)
        schema = scrub(tool["input_schema"], paths)
        if description != tool["description"] or schema != tool["input_schema"]:
            tool["description"], tool["input_schema"] = description, schema
            tool["definition_hash"] = tool_definition_hash(tool["name"], description, schema)
            changed = True
    if changed:
        data["captured"]["definition_hash"] = server_definition_hash(
            t["definition_hash"] for t in data["tools"]
        )
        data["captured"]["paths_scrubbed"] = True
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + NEWLINE, encoding="utf-8")
    return changed


def _resolve_command(command: str) -> str:
    if shutil.which(command):
        return command
    # uv installed into the current environment (dev lockfile) rather than on PATH.
    scripts = Path(sys.executable).parent
    for candidate in (scripts / command, scripts / f"{command}.exe"):
        if candidate.is_file():
            return str(candidate)
    return command


def _entry(spec: dict[str, Any], sandbox: Path) -> dict[str, Any]:
    def fill(value: str) -> str:
        return value.replace("{sandbox}", sandbox.as_posix())

    if "url" in spec:
        return {"url": spec["url"]}
    home = sandbox / "home"
    home.mkdir(parents=True, exist_ok=True)
    for rel, content in spec.get("home_files", {}).items():
        target = home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    env = {k: fill(v) for k, v in spec.get("env", {}).items()}
    env.update({"HOME": str(home), "USERPROFILE": str(home)})
    return {
        "command": _resolve_command(spec["command"]),
        "args": [fill(a) for a in spec["args"]],
        "env": env,
    }


def _has_labels(path: Path) -> bool:
    if not path.is_file():
        return False
    data = json.loads(path.read_text(encoding="utf-8"))
    return any(tool.get("label") for tool in data.get("tools", []))


def capture(spec: dict[str, Any], sandbox: Path, timeout: float) -> dict[str, Any] | str:
    server_sandbox = sandbox / spec["id"]
    server_sandbox.mkdir(parents=True, exist_ok=True)
    config = server_sandbox / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {spec["id"]: _entry(spec, server_sandbox)}}), encoding="utf-8"
    )
    agent, error = parse_config_file(config, root=server_sandbox, explicit=True)
    if error or agent is None:
        return f"config error: {error.message if error else 'unknown'}"
    result = enumerate_server(agent.servers[0], timeout=timeout)
    if result.status is not EnumerationStatus.OK:
        return f"{result.status.value}: {result.error}"
    if not result.tools:
        return "server returned no tools"
    return {
        "id": spec["id"],
        "category": spec["category"],
        "source": spec["source"],
        "version": spec["version"],
        "deprecated": spec.get("deprecated", False),
        "captured": {
            "at": dt.date.today().isoformat(),
            "agentcapmap_version": __version__,
            "protocol_version": result.protocol_version,
            "server_info": result.server_info,
            "definition_hash": result.definition_hash,
        },
        "labeling": {
            "status": "unlabeled",
            "labeled_by": None,
            "labeled_at": None,
            "reviewed_by": None,
            "reviewed_at": None,
        },
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "definition_hash": t.definition_hash,
                "label": None,
            }
            for t in result.tools
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", nargs="*", help="server ids to capture")
    parser.add_argument("--force", action="store_true", help="re-capture unlabeled files")
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--sandbox", type=Path, help="sandbox directory (default: a temp dir)")
    parser.add_argument(
        "--scrub-existing", action="store_true", help="scrub local paths in captured files"
    )
    args = parser.parse_args()

    if args.scrub_existing:
        paths = _local_paths(args.sandbox)
        for path in sorted(OUT_DIR.glob("*.json")):
            if scrub_file(path, paths):
                print(f"scrubbed {path.name}")
        return 0

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))["servers"]
    wanted = [s for s in catalog if not args.only or s["id"] in args.only]
    sandbox = args.sandbox or Path(tempfile.mkdtemp(prefix="capmap-eval-"))
    OUT_DIR.mkdir(exist_ok=True)
    failures: dict[str, str] = {}
    for spec in wanted:
        out = OUT_DIR / f"{spec['id']}.json"
        if _has_labels(out):
            print(f"skip {spec['id']}: already labeled")
            continue
        if out.is_file() and not args.force:
            print(f"skip {spec['id']}: already captured (use --force)")
            continue
        print(f"capturing {spec['id']} ...", flush=True)
        result = capture(spec, sandbox, args.timeout)
        if isinstance(result, str):
            failures[spec["id"]] = result
            print(f"  FAILED: {result}")
            continue
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        scrub_file(out, _local_paths(sandbox))
        print(f"  ok: {len(result['tools'])} tools")
    if failures:
        print("\nfailed:", json.dumps(failures, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

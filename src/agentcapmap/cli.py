"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from agentcapmap import __version__
from agentcapmap.discovery import discover
from agentcapmap.enumerate import DEFAULT_TIMEOUT, enumerate_inventory
from agentcapmap.redact import RedactingFilter, get_logger

log = get_logger("agentcapmap")

ENUMERATE_WARNING = (
    "warning: --enumerate launches the stdio server commands found in these configs and "
    "connects to their URLs. Only enumerate configs you trust."
)


def _setup_logging(verbosity: int) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger("agentcapmap")
    root.handlers[:] = [handler]
    root.setLevel(logging.WARNING - 10 * min(verbosity, 2))
    root.propagate = False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentcapmap",
        description="Inventory MCP servers reachable by AI agents and map their capabilities.",
    )
    parser.add_argument("--version", action="version", version=f"agentcapmap {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="discover MCP configs and output a normalized inventory")
    scan.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="config files or directories to scan (default: current directory, unless --user)",
    )
    scan.add_argument(
        "--user", action="store_true", help="also scan per-user client configs on this machine"
    )
    scan.add_argument(
        "--enumerate",
        action="store_true",
        help="connect to each server and list its tools (initialize + tools/list only)",
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"per-server enumeration timeout in seconds (default {DEFAULT_TIMEOUT:.0f})",
    )
    scan.add_argument(
        "--concurrency", type=int, default=4, help="servers to enumerate in parallel (default 4)"
    )
    scan.add_argument("-o", "--output", type=Path, help="write JSON here instead of stdout")
    scan.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    paths: list[Path] = args.paths or ([] if args.user else [Path.cwd()])
    inventory = discover(paths, user=args.user)
    if args.enumerate:
        print(ENUMERATE_WARNING, file=sys.stderr)
        enumerate_inventory(inventory, timeout=args.timeout, concurrency=args.concurrency)

    payload = inventory.model_dump_json(indent=2)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
        log.info("wrote %s", args.output)
    else:
        sys.stdout.write(payload + "\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(getattr(args, "verbose", 0))
    if args.command == "scan":
        return _cmd_scan(args)
    return 2  # pragma: no cover - argparse enforces a known subcommand

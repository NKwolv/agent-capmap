"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from agentcapmap import __version__
from agentcapmap.classify import Classifier, classify_inventory
from agentcapmap.classify.cache import ClassificationCache
from agentcapmap.classify.provider import AnthropicProvider
from agentcapmap.discovery import discover
from agentcapmap.enumerate import DEFAULT_TIMEOUT, enumerate_inventory
from agentcapmap.models import Inventory
from agentcapmap.redact import RedactingFilter, get_logger, redact_text

log = get_logger("agentcapmap")

ENUMERATE_WARNING = (
    "warning: --enumerate launches the stdio server commands found in these configs and "
    "connects to their URLs. Only enumerate configs you trust."
)


class CliError(Exception):
    pass


def _setup_logging(verbosity: int) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger("agentcapmap")
    root.handlers[:] = [handler]
    root.setLevel(logging.WARNING - 10 * min(verbosity, 2))
    root.propagate = False


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-o", "--output", type=Path, help="write JSON here instead of stdout")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")


def _add_classify_options(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--offline",
        action="store_true",
        help="use cached classifications only; never call the LLM",
    )
    p.add_argument("--cache-dir", type=Path, help="classification cache directory")
    p.add_argument("--model", help="classifier model (default: $AGENTCAPMAP_MODEL or built-in)")
    p.add_argument(
        "--classify-concurrency", type=int, default=4, help="parallel LLM requests (default 4)"
    )


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
    scan.add_argument(
        "--classify", action="store_true", help="classify enumerated tools (needs --enumerate)"
    )
    _add_classify_options(scan)
    _add_common(scan)

    classify = sub.add_parser("classify", help="classify the tools in a saved inventory JSON")
    classify.add_argument("inventory", type=Path, help="inventory JSON from `scan --enumerate`")
    _add_classify_options(classify)
    _add_common(classify)
    return parser


def _classify(inventory: Inventory, args: argparse.Namespace) -> None:
    cache = ClassificationCache(args.cache_dir)
    if args.offline:
        classifier = Classifier(cache, offline=True)
    else:
        try:
            provider = AnthropicProvider(model=args.model)
        except Exception as exc:  # SDK raises various errors when credentials are missing
            raise CliError(f"cannot create the LLM client: {redact_text(str(exc))}") from None
        classifier = Classifier(cache, provider)
    classify_inventory(inventory, classifier, concurrency=args.classify_concurrency)


def _emit(inventory: Inventory, output: Path | None) -> None:
    payload = inventory.model_dump_json(indent=2)
    if output:
        output.write_text(payload + "\n", encoding="utf-8")
        log.info("wrote %s", output)
    else:
        sys.stdout.write(payload + "\n")


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.classify and not args.enumerate:
        raise CliError(
            "--classify needs tool definitions: add --enumerate, "
            "or run `agentcapmap classify` on a saved inventory"
        )
    paths: list[Path] = args.paths or ([] if args.user else [Path.cwd()])
    inventory = discover(paths, user=args.user)
    if args.enumerate:
        print(ENUMERATE_WARNING, file=sys.stderr)
        enumerate_inventory(inventory, timeout=args.timeout, concurrency=args.concurrency)
    if args.classify:
        _classify(inventory, args)
    _emit(inventory, args.output)
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    try:
        inventory = Inventory.model_validate_json(args.inventory.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CliError(f"cannot read {args.inventory}: {exc.strerror}") from None
    except ValidationError as exc:
        raise CliError(
            f"{args.inventory} is not a valid inventory: {exc.error_count()} error(s)"
        ) from None
    _classify(inventory, args)
    _emit(inventory, args.output)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(getattr(args, "verbose", 0))
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "classify":
            return _cmd_classify(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2  # pragma: no cover - argparse enforces a known subcommand

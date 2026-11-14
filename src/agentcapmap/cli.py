"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ValidationError

from agentcapmap import __version__
from agentcapmap.baseline import Baseline, BaselineError, create_baseline, load_baseline
from agentcapmap.classify import Classifier, classify_inventory
from agentcapmap.classify.cache import ClassificationCache
from agentcapmap.classify.provider import AnthropicProvider
from agentcapmap.diff import diff_evaluations, render_markdown, should_fail_diff
from agentcapmap.discovery import discover, user_config_paths
from agentcapmap.discovery.runtime import PsutilSource, RuntimeDiscoveryError, discover_running
from agentcapmap.enumerate import DEFAULT_TIMEOUT, enumerate_inventory
from agentcapmap.findings import Evaluation, Severity
from agentcapmap.guard import hook as guard_hook
from agentcapmap.guard.build import build_guard_map, settings_snippet
from agentcapmap.models import Inventory
from agentcapmap.policy import PolicyError, evaluate, load_policy
from agentcapmap.policy.waivers import WaiverError, apply_waivers, load_waivers
from agentcapmap.redact import RedactingFilter, get_logger, redact_text
from agentcapmap.report import Format, render, should_fail

log = get_logger("agentcapmap")

ENUMERATE_WARNING = (
    "warning: --enumerate launches the stdio server commands found in these configs and "
    "connects to their URLs. Only enumerate configs you trust."
)
SCOPE_CHECK_WARNING = (
    "warning: --check-token-scopes presents each GitHub token found in these configs to "
    "https://api.github.com to read its scopes. Tokens are sent nowhere else and are not "
    "stored."
)
_MAX_INVENTORY_BYTES = 64 * 1024 * 1024

# Exit codes: 0 success; 1 findings met --fail-on (or something was not assessed with
# --fail-on-not-assessed); 2 usage or input error.
EXIT_FINDINGS = 1
EXIT_ERROR = 2


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


def _add_policy_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--policy", type=Path, help="policy YAML (default: built-in default policy)")
    p.add_argument("--baseline", type=Path, help="baseline JSON for rug-pull detection (CAP-006)")
    p.add_argument(
        "--waivers",
        type=Path,
        help="waivers YAML: findings accepted by name, with an owner and an expiry date",
    )


def _add_report_options(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--format",
        choices=[f.value for f in Format],
        default=Format.JSON.value,
        help="output format for findings (default json)",
    )
    p.add_argument(
        "--fail-on",
        choices=[*(s.value for s in Severity), "none"],
        default="none",
        help="exit 1 if any finding is at or above this severity (default none)",
    )
    p.add_argument(
        "--fail-on-not-assessed",
        action="store_true",
        help="exit 1 if any server or tool could not be assessed",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentcapmap",
        description="Inventory MCP servers reachable by AI agents and map their capabilities.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"agentcapmap {__version__} (installed at {Path(__file__).resolve().parent})",
    )
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
        "--running",
        action="store_true",
        help="also find MCP servers running on this machine (needs `agent-capmap[runtime]`); "
        "reads the process table only, never starts or connects to anything",
    )
    scan.add_argument(
        "--enumerate",
        action="store_true",
        help="connect to each server and list its tools (initialize + tools/list only)",
    )
    scan.add_argument(
        "--check-token-scopes",
        action="store_true",
        help="with --enumerate: read the scopes of GitHub tokens found in configs by "
        "presenting each token to api.github.com (and nowhere else)",
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
    scan.add_argument(
        "--evaluate",
        action="store_true",
        help="apply the policy and output findings instead of the inventory",
    )
    scan.add_argument(
        "--save-inventory", type=Path, help="with --evaluate, also write the inventory here"
    )
    _add_classify_options(scan)
    _add_policy_options(scan)
    _add_report_options(scan)
    _add_common(scan)

    classify = sub.add_parser("classify", help="classify the tools in a saved inventory JSON")
    classify.add_argument("inventory", type=Path, help="inventory JSON from `scan --enumerate`")
    _add_classify_options(classify)
    _add_common(classify)

    ev = sub.add_parser("evaluate", help="apply a policy to a saved (classified) inventory")
    ev.add_argument("inventory", type=Path, help="inventory JSON from `scan`")
    _add_policy_options(ev)
    _add_report_options(ev)
    _add_common(ev)

    report = sub.add_parser(
        "report", help="render a saved evaluation (JSON from `evaluate`) in another format"
    )
    report.add_argument("evaluation", type=Path, help="evaluation JSON from `evaluate`")
    _add_report_options(report)
    _add_common(report)

    diff = sub.add_parser(
        "diff", help="compare two evaluations: new and resolved findings, gained capabilities"
    )
    diff.add_argument("old", type=Path, help="earlier evaluation JSON")
    diff.add_argument("new", type=Path, help="later evaluation JSON")
    diff.add_argument(
        "--format", choices=["json", "markdown"], default="json", help="output format"
    )
    diff.add_argument(
        "--fail-on",
        choices=[*(s.value for s in Severity), "none"],
        default="none",
        help="exit 1 if a NEW finding is at or above this severity (default none)",
    )
    diff.add_argument(
        "--fail-on-new-capability",
        action="store_true",
        help="exit 1 if any agent gained a capability it did not have before",
    )
    _add_common(diff)

    baseline = sub.add_parser("baseline", help="manage tool-definition baselines")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    create = baseline_sub.add_parser(
        "create", help="pin the tool definition hashes of an enumerated inventory"
    )
    create.add_argument("inventory", type=Path, help="inventory JSON from `scan --enumerate`")
    _add_common(create)

    guard = sub.add_parser(
        "guard", help="runtime guard for Claude Code: block risky combinations as they happen"
    )
    guard_sub = guard.add_subparsers(dest="guard_command", required=True)
    build = guard_sub.add_parser(
        "build", help="turn a classified inventory and a policy into a guard map"
    )
    build.add_argument("inventory", type=Path, help="classified inventory JSON")
    build.add_argument("--policy", type=Path, help="policy YAML (default: built-in)")
    _add_common(build)
    settings = guard_sub.add_parser(
        "settings", help="print the hooks block to add to Claude Code's settings.json"
    )
    settings.add_argument("--map", type=Path, required=True, help="guard map file")
    settings.add_argument(
        "--on-violation", choices=("ask", "deny"), default="ask", help="default: ask"
    )
    settings.add_argument(
        "--unknown", choices=("ask", "deny", "allow"), default="ask", help="default: ask"
    )
    settings.add_argument("--track-builtins", action="store_true")
    _add_common(settings)
    guard_sub.add_parser(
        "hook",
        add_help=False,
        help="the PreToolUse hook itself (reads the hook input on stdin); see `guard settings`",
    )
    return parser


def _read_json_file(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_INVENTORY_BYTES:
            raise CliError(f"{path} is larger than {_MAX_INVENTORY_BYTES} bytes")
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise CliError(f"{path} is not UTF-8 text") from None


def _load_inventory(path: Path) -> Inventory:
    try:
        return Inventory.model_validate_json(_read_json_file(path))
    except ValidationError as exc:
        raise CliError(f"{path} is not a valid inventory: {exc.error_count()} error(s)") from None


def _load_evaluation(path: Path) -> Evaluation:
    try:
        return Evaluation.model_validate_json(_read_json_file(path))
    except ValidationError as exc:
        raise CliError(f"{path} is not a valid evaluation: {exc.error_count()} error(s)") from None


def _classify(inventory: Inventory, args: argparse.Namespace) -> None:
    cache = ClassificationCache(args.cache_dir)
    if args.offline:
        classifier = Classifier(cache, offline=True)
    else:
        try:
            provider = AnthropicProvider(model=args.model)
        except Exception as exc:  # SDK raises various errors when credentials are missing
            # Fail closed: tools without a reviewed reference label or a cached answer
            # stay unclassified and are reported as not assessed, never as safe.
            print(
                f"warning: no usable LLM client ({type(exc).__name__}); set ANTHROPIC_API_KEY "
                "to classify new tools. Using reviewed reference labels and cached "
                "classifications only; other tools will be reported as not assessed.",
                file=sys.stderr,
            )
            classifier = Classifier(cache, offline=True)
        else:
            classifier = Classifier(cache, provider)
    classify_inventory(inventory, classifier, concurrency=args.classify_concurrency)


def _evaluate(inventory: Inventory, args: argparse.Namespace) -> Evaluation:
    try:
        policy = load_policy(args.policy)
        baseline: Baseline | None = load_baseline(args.baseline) if args.baseline else None
    except (PolicyError, BaselineError) as exc:
        raise CliError(str(exc)) from None
    evaluation = evaluate(inventory, policy, baseline)
    if args.waivers:
        try:
            evaluation = apply_waivers(evaluation, load_waivers(args.waivers))
        except WaiverError as exc:
            raise CliError(str(exc)) from None
        print(
            f"waivers: {len(evaluation.waived)} finding(s) waived, "
            f"{len(evaluation.waiver_issues)} waiver issue(s)",
            file=sys.stderr,
        )
    return evaluation


def _write(payload: str, output: Path | None) -> None:
    if output:
        output.write_text(payload, encoding="utf-8")
        log.info("wrote %s", output)
    else:
        sys.stdout.write(payload)


def _emit(model: BaseModel, output: Path | None) -> None:
    _write(model.model_dump_json(indent=2) + "\n", output)


def _report(evaluation: Evaluation, args: argparse.Namespace) -> int:
    """Write the evaluation in the requested format; return the exit status."""
    _write(render(evaluation, Format(args.format)), args.output)
    fail_on = None if args.fail_on == "none" else Severity(args.fail_on)
    if should_fail(evaluation, fail_on, args.fail_on_not_assessed):
        at_or_above = sum(
            1 for f in evaluation.findings if fail_on and f.severity.rank >= fail_on.rank
        )
        log.warning(
            "failing: %d finding(s) at or above --fail-on %s, %d not assessed",
            at_or_above,
            args.fail_on,
            len(evaluation.not_assessed),
        )
        return EXIT_FINDINGS
    return 0


def _print_scan_summary(inventory: Inventory, args: argparse.Namespace) -> None:
    """One human-readable line on stderr, so an empty result is not a mystery."""
    servers = sum(len(agent.servers) for agent in inventory.agents)
    print(
        f"scanned {len(inventory.agents)} agent config(s): {servers} MCP server(s) found, "
        f"{len(inventory.errors)} error(s)",
        file=sys.stderr,
    )
    if servers == 0:
        places = [str(p) for p in user_config_paths()] if args.user else []
        places += [str(a.config_path) for a in inventory.agents]
        checked = "; ".join(dict.fromkeys(places)) or "no config files found"
        print(redact_text(f"no MCP servers found. Looked at: {checked}"), file=sys.stderr)
    elif not args.enumerate:
        print(
            "tools were not listed. Add --enumerate --classify --evaluate to assess what "
            "each server can do (this starts the configured servers).",
            file=sys.stderr,
        )


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.check_token_scopes and not args.enumerate:
        raise CliError("--check-token-scopes needs --enumerate")
    if args.classify and not args.enumerate:
        raise CliError(
            "--classify needs tool definitions: add --enumerate, "
            "or run `agentcapmap classify` on a saved inventory"
        )
    if not args.evaluate and (
        args.save_inventory
        or args.format != Format.JSON.value
        or args.fail_on != "none"
        or args.fail_on_not_assessed
    ):
        raise CliError(
            "--save-inventory, --format, --fail-on and --fail-on-not-assessed need --evaluate"
        )
    paths: list[Path] = args.paths or ([] if args.user else [Path.cwd()])
    inventory = discover(paths, user=args.user, root=Path.cwd())
    if args.running:
        try:
            runtime = discover_running(inventory, PsutilSource())
        except RuntimeDiscoveryError as exc:
            raise CliError(str(exc)) from None
        print(
            f"running: {runtime.declared} declared and {runtime.undeclared} undeclared MCP "
            f"server process(es) found, {runtime.exposed} listening beyond loopback",
            file=sys.stderr,
        )
        for note in runtime.notes:
            print(f"note: {note}", file=sys.stderr)
        if not args.user:
            print(
                "note: 'declared' means found in the scanned configs; add --user to include "
                "your per-user client configs",
                file=sys.stderr,
            )
    if args.enumerate:
        print(ENUMERATE_WARNING, file=sys.stderr)
        if args.check_token_scopes:
            print(SCOPE_CHECK_WARNING, file=sys.stderr)
        enumerate_inventory(
            inventory,
            timeout=args.timeout,
            concurrency=args.concurrency,
            check_token_scopes=args.check_token_scopes,
        )
    if args.classify:
        _classify(inventory, args)
    if not args.evaluate:
        _print_scan_summary(inventory, args)
        _emit(inventory, args.output)
        return 0
    if args.save_inventory:
        _emit(inventory, args.save_inventory)
    return _report(_evaluate(inventory, args), args)


def _cmd_classify(args: argparse.Namespace) -> int:
    inventory = _load_inventory(args.inventory)
    _classify(inventory, args)
    _emit(inventory, args.output)
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    return _report(_evaluate(_load_inventory(args.inventory), args), args)


def _cmd_report(args: argparse.Namespace) -> int:
    return _report(_load_evaluation(args.evaluation), args)


def _cmd_diff(args: argparse.Namespace) -> int:
    diff = diff_evaluations(_load_evaluation(args.old), _load_evaluation(args.new))
    if args.format == "markdown":
        _write(render_markdown(diff), args.output)
    else:
        _emit(diff, args.output)
    fail_on = None if args.fail_on == "none" else Severity(args.fail_on)
    if should_fail_diff(diff, fail_on, args.fail_on_new_capability):
        log.warning(
            "failing: %d new finding(s), %d gained capabilit(ies)",
            len(diff.new_findings),
            len(diff.gained_capabilities),
        )
        return EXIT_FINDINGS
    return 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    baseline = create_baseline(_load_inventory(args.inventory))
    if not baseline.servers:
        raise CliError("no successfully enumerated servers to pin (run scan with --enumerate)")
    _emit(baseline, args.output)
    return 0


def _cmd_guard(args: argparse.Namespace) -> int:
    if args.guard_command == "settings":
        if not args.map.is_file():
            raise CliError(f"{args.map} does not exist (run `agentcapmap guard build` first)")
        snippet = settings_snippet(
            args.map,
            on_violation=args.on_violation,
            unknown=args.unknown,
            track_builtins=args.track_builtins,
        )
        _write(json.dumps(snippet, indent=2) + "\n", args.output)
        return 0
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        raise CliError(str(exc)) from None
    guard_map = build_guard_map(_load_inventory(args.inventory), policy)
    if not guard_map["tools"]:
        raise CliError(
            "no classified tools in this inventory (run scan with --enumerate --classify)"
        )
    _write(json.dumps(guard_map, indent=2) + "\n", args.output)
    print(
        f"guard map: {len(guard_map['tools'])} tool name(s), "
        f"{len(guard_map['rules'])} rule(s) enforced "
        f"({', '.join(r['id'] for r in guard_map['rules']) or 'none'}), "
        f"{len(guard_map['unassessed'])} not assessed",
        file=sys.stderr,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw[:2] == ["guard", "hook"]:
        # The hook has its own options and must fail closed, never with a usage error.
        return guard_hook.main(raw[2:])
    args = _build_parser().parse_args(raw)
    _setup_logging(getattr(args, "verbose", 0))
    commands = {
        "scan": _cmd_scan,
        "classify": _cmd_classify,
        "evaluate": _cmd_evaluate,
        "report": _cmd_report,
        "diff": _cmd_diff,
        "baseline": _cmd_baseline,
        "guard": _cmd_guard,
    }
    try:
        return commands[args.command](args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

"""Run the project's required checks locally, in one command.

    python scripts/check.py            # everything that can run here
    python scripts/check.py --strict   # also fail when a tool is not installed

Python tools run as `python -m <tool>` so this works even when a security policy blocks
their .exe launchers. `gitleaks` is a separate binary; when it is missing the check is
reported as skipped (CI always runs it over the full history).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def _sibling_tool(name: str) -> str | None:
    """A console script installed next to this interpreter, else on PATH."""
    for candidate in (Path(PY).parent / name, Path(PY).parent / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


def _checks() -> list[tuple[str, list[str] | None]]:
    zizmor, gitleaks = _sibling_tool("zizmor"), _sibling_tool("gitleaks")
    return [
        ("ruff check", [PY, "-m", "ruff", "check", "."]),
        ("ruff format", [PY, "-m", "ruff", "format", "--check", "."]),
        ("mypy", [PY, "-m", "mypy"]),
        ("pytest", [PY, "-m", "pytest", "-q"]),
        ("bandit", [PY, "-m", "bandit", "-c", "pyproject.toml", "-r", "src", "-q"]),
        (
            "pip-audit",
            [PY, "-m", "pip_audit", "--strict", "--require-hashes", "-r", "requirements/dev.lock"],
        ),
        (
            "zizmor",
            zizmor
            and [zizmor, "--offline", "--persona", "auditor", "action.yml", ".github/workflows/"],
        ),
        (
            "gitleaks",
            gitleaks
            and [gitleaks, "git", ".", "--config", ".gitleaks.toml", "--redact", "--no-banner"],
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--strict", action="store_true", help="fail if a tool is not installed")
    args = parser.parse_args()

    results: list[tuple[str, str]] = []
    for name, command in _checks():
        if command is None:
            print(f"--- {name}: not installed, skipped", flush=True)
            results.append((name, "skipped"))
            continue
        print(f"--- {name}", flush=True)
        # Fixed argument lists built above, no shell, no user input.
        code = subprocess.run(command, cwd=ROOT, check=False).returncode  # noqa: S603  # nosec B603
        results.append((name, "ok" if code == 0 else "FAILED"))

    print("\nSummary")
    for name, status in results:
        print(f"  {status:8} {name}")
    failed = any(s == "FAILED" for _, s in results)
    skipped = any(s == "skipped" for _, s in results)
    return 1 if failed or (args.strict and skipped) else 0


if __name__ == "__main__":
    sys.exit(main())

"""Prepare a release: bump the version everywhere and date the changelog.

    python scripts/prepare_release.py 0.1.1            # edit the files
    python scripts/prepare_release.py 0.1.1 --dry-run  # only report what would change

It refuses to run unless the working tree is clean, the version is a plain X.Y.Z that
is higher than the current one, `[Unreleased]` in CHANGELOG.md has entries, and the
bundled reference labels match `eval/labeled_servers/`. It never commits, tags or
pushes: it prints the remaining steps for you to run.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "src" / "agentcapmap" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"

_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_PYPROJECT_VERSION = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)
_INIT_VERSION = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)
_UNRELEASED = "## [Unreleased]\n"


class ReleaseError(ValueError):
    pass


def parse_version(text: str) -> tuple[int, int, int]:
    match = _SEMVER.match(text)
    if not match:
        raise ReleaseError(f"{text!r} is not a plain X.Y.Z version")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def current_version(pyproject: str, init: str) -> str:
    in_pyproject = _PYPROJECT_VERSION.search(pyproject)
    in_init = _INIT_VERSION.search(init)
    if not in_pyproject or not in_init:
        raise ReleaseError("cannot find the version in pyproject.toml or __init__.py")
    if in_pyproject.group(1) != in_init.group(1):
        raise ReleaseError(
            f"pyproject.toml says {in_pyproject.group(1)} but __init__.py says "
            f"{in_init.group(1)}: fix that first"
        )
    return in_pyproject.group(1)


def unreleased_entries(changelog: str) -> str:
    """The text under `## [Unreleased]`, up to the next `## ` heading."""
    start = changelog.find(_UNRELEASED)
    if start == -1:
        raise ReleaseError("CHANGELOG.md has no '## [Unreleased]' heading")
    body = changelog[start + len(_UNRELEASED) :]
    end = body.find("\n## ")
    return (body if end == -1 else body[:end]).strip()


def bump(
    version: str, date: str, pyproject: str, init: str, changelog: str
) -> tuple[str, str, str]:
    """Return the new text of (pyproject.toml, __init__.py, CHANGELOG.md)."""
    old = current_version(pyproject, init)
    if parse_version(version) <= parse_version(old):
        raise ReleaseError(f"{version} is not higher than the current version {old}")
    if not unreleased_entries(changelog):
        raise ReleaseError("nothing under '## [Unreleased]' in CHANGELOG.md: describe the changes")
    if f"## [{version}]" in changelog:
        raise ReleaseError(f"CHANGELOG.md already has a section for {version}")
    return (
        _PYPROJECT_VERSION.sub(f'version = "{version}"', pyproject, count=1),
        _INIT_VERSION.sub(f'__version__ = "{version}"', init, count=1),
        changelog.replace(_UNRELEASED, f"{_UNRELEASED}\n## [{version}] - {date}\n", 1),
    )


def _git(*args: str) -> str:
    # Fixed argument lists, no shell, no user input.
    result = subprocess.run(  # noqa: S603  # nosec B603
        ["git", *args],  # noqa: S607  # nosec B607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _reference_labels_stale() -> bool:
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_reference_labels as build  # type: ignore[import-not-found]

    from agentcapmap.classify.reference import dump_bundle
    from agentcapmap.evaluation import load_labeled_servers

    expected = dump_bundle(build.build_bundle(load_labeled_servers(build.LABELS_DIR)))
    current = build.BUNDLE_PATH.read_text(encoding="utf-8") if build.BUNDLE_PATH.is_file() else ""
    return bool(current != expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("version", help="new version, X.Y.Z")
    parser.add_argument("--date", default=datetime.date.today().isoformat(), help="YYYY-MM-DD")
    parser.add_argument("--dry-run", action="store_true", help="report only; change nothing")
    args = parser.parse_args()

    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
            raise ReleaseError("--date must be YYYY-MM-DD")
        if _git("status", "--porcelain").strip():
            raise ReleaseError("the working tree is not clean: commit or stash first")
        if _reference_labels_stale():
            raise ReleaseError(
                "reference_labels.json is out of date: run scripts/build_reference_labels.py"
            )
        new = bump(
            args.version,
            args.date,
            PYPROJECT.read_text(encoding="utf-8"),
            INIT.read_text(encoding="utf-8"),
            CHANGELOG.read_text(encoding="utf-8"),
        )
    except (ReleaseError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(
            f"would release {args.version} ({args.date}): pyproject.toml, __init__.py, CHANGELOG.md"
        )
        return 0
    for path, text in zip((PYPROJECT, INIT, CHANGELOG), new, strict=True):
        path.write_text(text, encoding="utf-8", newline="\n")
    print(
        f"Prepared {args.version}. Next:\n"
        "  1. python scripts/check.py\n"
        f'  2. git commit -am "Release {args.version}" && git push origin main\n'
        "  3. wait for CI on that commit to pass\n"
        f'  4. git tag -a v{args.version} -m "agent-capmap {args.version}" '
        f"&& git push origin v{args.version}\n"
        "  5. approve the 'pypi' deployment, then confirm the release on PyPI\n"
        "  6. update the NKwolv/agent-capmap@<sha> pin in docs/examples/agentcapmap.yml"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

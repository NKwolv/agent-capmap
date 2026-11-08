"""The release helper, and a guard that the version is the same everywhere."""

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

from agentcapmap import __version__

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "prepare_release", ROOT / "scripts" / "prepare_release.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


release = _load()

PYPROJECT = '[project]\nname = "x"\nversion = "0.1.0"\n'
INIT = '"""doc"""\n\n__version__ = "0.1.0"\n'
CHANGELOG = (
    "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- a bug\n\n## [0.1.0] - 2026-11-08\n\n- first\n"
)


def test_version_is_the_same_in_pyproject_and_the_package() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
    assert match and match.group(1) == __version__


def test_changelog_has_a_section_for_the_current_version() -> None:
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_bump_updates_all_three_files() -> None:
    pyproject, init, changelog = release.bump("0.1.1", "2026-12-01", PYPROJECT, INIT, CHANGELOG)
    assert 'version = "0.1.1"' in pyproject and 'version = "0.1.0"' not in pyproject
    assert '__version__ = "0.1.1"' in init
    assert "## [Unreleased]\n\n## [0.1.1] - 2026-12-01\n\n### Fixed" in changelog
    assert "## [0.1.0] - 2026-11-08" in changelog  # old section untouched


@pytest.mark.parametrize("bad", ["1.0", "v0.1.1", "0.1.1-rc1", "0.1.01", "0.1.1 ", ""])
def test_rejects_non_semver(bad: str) -> None:
    with pytest.raises(release.ReleaseError):
        release.bump(bad, "2026-12-01", PYPROJECT, INIT, CHANGELOG)


@pytest.mark.parametrize("not_higher", ["0.1.0", "0.0.9"])
def test_rejects_a_version_that_is_not_higher(not_higher: str) -> None:
    with pytest.raises(release.ReleaseError, match="not higher"):
        release.bump(not_higher, "2026-12-01", PYPROJECT, INIT, CHANGELOG)


def test_rejects_an_empty_unreleased_section() -> None:
    empty = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-08\n\n- first\n"
    with pytest.raises(release.ReleaseError, match="nothing under"):
        release.bump("0.1.1", "2026-12-01", PYPROJECT, INIT, empty)


def test_rejects_mismatched_versions_and_missing_markers() -> None:
    with pytest.raises(release.ReleaseError, match="fix that first"):
        release.bump("0.2.0", "2026-12-01", PYPROJECT, INIT.replace("0.1.0", "0.0.9"), CHANGELOG)
    with pytest.raises(release.ReleaseError, match="no '## \\[Unreleased\\]'"):
        release.bump("0.1.1", "2026-12-01", PYPROJECT, INIT, "# Changelog\n")


def test_rejects_a_version_already_in_the_changelog() -> None:
    changelog = CHANGELOG.replace(
        "## [Unreleased]\n", "## [Unreleased]\n\n## [0.1.1] - 2026-12-01\n"
    )
    with pytest.raises(release.ReleaseError):
        release.bump("0.1.1", "2026-12-02", PYPROJECT, INIT, changelog)

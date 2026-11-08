"""The label review helper: ranking, hints, worksheets and recording a human review."""

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

from agentcapmap.evaluation import load_labeled_servers

ROOT = Path(__file__).resolve().parent.parent
REAL_LABELS = ROOT / "eval" / "labeled_servers"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("eval_review", ROOT / "eval" / "review.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


review = _load()


@pytest.fixture
def labels(tmp_path: Path) -> Path:
    directory = tmp_path / "labels"
    directory.mkdir()
    for name in ("fetch", "commands", "time", "github"):
        shutil.copy(REAL_LABELS / f"{name}.json", directory / f"{name}.json")
    return directory


def test_ranking_puts_risky_unreviewed_files_first(labels: Path) -> None:
    order = [r.server_id for r in review.ranked(load_labeled_servers(labels))]
    assert order[0] == "github"  # many high-impact tools and judgment calls
    assert order[-1] == "time"  # nothing high-impact, nothing to decide


def test_human_reviewed_files_move_to_the_end(labels: Path) -> None:
    review.mark(labels, ["github"], "Pat Reviewer")
    order = [r.server_id for r in review.ranked(load_labeled_servers(labels))]
    assert order[-1] == "github"


def test_hints_flag_capabilities_the_tags_miss() -> None:
    none = {"mutation": "none", "egress": "none", "execution": "none", "data_access": "none"}
    found = review.hints("Permanently delete the record", "{}", none)
    assert any("delete" in h and "mutation is none" in h for h in found)
    assert (
        review.hints("Permanently delete the record", "{}", {**none, "mutation": "destructive"})
        == []
    )
    assert review.hints("Returns the current time", "{}", none) == []


def test_worksheet_lists_every_tool_with_flags(labels: Path) -> None:
    text = review.sheet(load_labeled_servers(labels), ["fetch"])
    assert "- [ ] `fetch`" in text and "**SUSPICIOUS**" in text and "**HIGH-IMPACT**" in text
    assert "evidence for egress" in text
    assert 'review.py mark <id> --by "Your Name"' in text


def test_worksheet_rejects_unknown_files(labels: Path) -> None:
    with pytest.raises(ValueError, match="unknown label file"):
        review.sheet(load_labeled_servers(labels), ["nope"])


def test_long_descriptions_are_shortened(labels: Path) -> None:
    servers = load_labeled_servers(labels)
    line = next(
        row for row in review.sheet(servers, ["github"]).splitlines() if "description:" in row
    )
    assert len(line) < 600


def test_mark_records_a_person_and_touches_nothing_else(labels: Path) -> None:
    before = json.loads((labels / "fetch.json").read_text(encoding="utf-8"))
    review.mark(labels, ["fetch"], "Pat Reviewer")
    after = json.loads((labels / "fetch.json").read_text(encoding="utf-8"))
    assert after["labeling"]["reviewed_by"] == "Pat Reviewer"
    assert after["labeling"]["status"] == "reviewed" and after["labeling"]["reviewed_at"]
    before["labeling"] = after["labeling"] = None
    assert before == after  # tools, tags, evidence and hashes are untouched
    other = json.loads((labels / "time.json").read_text(encoding="utf-8"))
    assert other["labeling"]["reviewed_by"].startswith("AI:")  # other files are not touched
    load_labeled_servers(labels)  # and everything still validates


@pytest.mark.parametrize("name", ["", "   ", "AI: some model", "ai: lowercase", "x" * 101])
def test_mark_refuses_names_that_are_not_a_person(labels: Path, name: str) -> None:
    with pytest.raises(ValueError, match="your name"):
        review.mark(labels, ["fetch"], name)


def test_mark_rejects_unknown_files_before_changing_any(labels: Path) -> None:
    snapshot = (labels / "fetch.json").read_bytes()
    with pytest.raises(ValueError, match="unknown label file"):
        review.mark(labels, ["fetch", "nope"], "Pat Reviewer")
    assert (labels / "fetch.json").read_bytes() == snapshot


def test_files_stay_byte_stable_apart_from_the_labeling_block(labels: Path) -> None:
    """Re-saving must not reformat the file (that would bury the real change in a diff)."""
    review.mark(labels, ["time"], "Pat Reviewer")
    original = (REAL_LABELS / "time.json").read_text(encoding="utf-8").splitlines()
    changed = (labels / "time.json").read_text(encoding="utf-8").splitlines()
    assert len(original) == len(changed)
    assert [i for i, (a, b) in enumerate(zip(original, changed, strict=True)) if a != b]


def test_cli_list_sheet_and_mark(
    labels: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = ["--labels", str(labels)]
    assert review.main([*base, "list"]) == 0
    assert "0 of" in capsys.readouterr().out
    out = tmp_path / "sheet.md"
    assert review.main([*base, "sheet", "--top", "2", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").count("## ") == 2
    assert review.main([*base, "mark", "commands", "--by", "Pat Reviewer"]) == 0
    assert "marked reviewed" in capsys.readouterr().out
    assert review.main([*base, "mark", "commands", "--by", "AI: sneaky"]) == 1
    assert "your name" in capsys.readouterr().err


def test_the_real_labels_rank_without_error() -> None:
    rows = review.ranked(load_labeled_servers(REAL_LABELS))
    assert sum(r.tools for r in rows) == 381
    assert not any(r.human_reviewed for r in rows)  # as of now, no file has a human reviewer

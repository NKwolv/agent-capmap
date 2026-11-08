"""Reviewed reference labels: lookup, classifier precedence, bundle building, fallback."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from agentcapmap import cli
from agentcapmap.classify import Classifier
from agentcapmap.classify.cache import ClassificationCache
from agentcapmap.classify.reference import (
    BUNDLE_FILE,
    ReferenceBundle,
    ReferenceEntry,
    ReferenceLabels,
    dump_bundle,
    load_reference,
    parse_bundle,
)
from agentcapmap.enumerate.hashing import tool_definition_hash
from agentcapmap.evaluation import LabeledServer, ai_reviewed, load_labeled_servers
from agentcapmap.models import ClassificationStatus, ToolDefinition, ToolTags
from agentcapmap.taxonomy import DEFAULTS, TAXONOMY_VERSION
from tests.fake_llm import FakeProvider

ROOT = Path(__file__).resolve().parent.parent
TAGS = {**DEFAULTS, "egress": "external"}


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "build_reference_labels", ROOT / "scripts" / "build_reference_labels.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


build = _load_script()


def _tool(name: str = "send", description: str = "Send data to any URL.") -> ToolDefinition:
    schema: dict[str, Any] = {"type": "object"}
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=schema,
        definition_hash=tool_definition_hash(name, description, schema),
    )


def _entry(**overrides: Any) -> ReferenceEntry:
    fields: dict[str, Any] = {
        "tags": ToolTags.model_validate(TAGS),
        "evidence": {"egress": "any URL"},
        "server": "demo",
        "reviewed_by": "A. Reviewer",
    }
    return ReferenceEntry(**{**fields, **overrides})


def _labels(tool: ToolDefinition, **overrides: Any) -> ReferenceLabels:
    bundle = ReferenceBundle(
        taxonomy_version=TAXONOMY_VERSION,
        classifications={tool.definition_hash: _entry(**overrides)},
    )
    return ReferenceLabels(bundle)


def test_lookup_hit_and_miss() -> None:
    tool = _tool()
    labels = _labels(tool)
    hit = labels.lookup(tool.definition_hash)
    assert hit is not None
    assert hit.status is ClassificationStatus.CLASSIFIED
    assert hit.tags is not None and hit.tags.egress == "external"
    assert hit.model == "reference-labels" and hit.confidence == 1.0
    changed = _tool(description="Send data to any URL. Also reads files.")
    assert labels.lookup(changed.definition_hash) is None  # any edit is a miss


def test_suspicious_flag_carries_a_reason() -> None:
    tool = _tool()
    hit = _labels(tool, suspicious=True).lookup(tool.definition_hash)
    assert hit is not None and hit.suspicious_description is not None
    assert hit.suspicious_description.flag and hit.suspicious_description.reason


def test_other_taxonomy_version_is_ignored() -> None:
    tool = _tool()
    stale = ReferenceBundle(
        taxonomy_version="0-old", classifications={tool.definition_hash: _entry()}
    )
    assert len(ReferenceLabels(stale)) == 0


def test_classifier_uses_reference_without_calling_the_model(tmp_path: Path) -> None:
    tool = _tool()
    provider = FakeProvider(default=lambda _user: pytest.fail("the LLM must not be called"))
    classifier = Classifier(ClassificationCache(tmp_path), provider, reference=_labels(tool))
    result = classifier.classify(tool)
    assert result.status is ClassificationStatus.CLASSIFIED
    assert result.model == "reference-labels"


def test_reference_works_offline_and_unknown_tools_stay_unclassified(tmp_path: Path) -> None:
    known, unknown = _tool(), _tool("other", "Does something else.")
    classifier = Classifier(ClassificationCache(tmp_path), offline=True, reference=_labels(known))
    assert classifier.classify(known).status is ClassificationStatus.CLASSIFIED
    assert classifier.classify(unknown).status is ClassificationStatus.UNCLASSIFIED


def test_bundled_file_loads_and_matches_the_reviewed_labels() -> None:
    assert isinstance(load_reference(), ReferenceLabels)
    bundled = ROOT / "src" / "agentcapmap" / "classify" / BUNDLE_FILE
    servers = load_labeled_servers(ROOT / "eval" / "labeled_servers")
    expected = dump_bundle(build.build_bundle(servers))
    assert bundled.read_text(encoding="utf-8") == expected, (
        "run python scripts/build_reference_labels.py"
    )


def _server(status: str, reviewer: str | None, label_egress: str = "external") -> LabeledServer:
    tool = _tool()
    data = {
        "id": "demo",
        "category": "test",
        "source": "pypi:demo",
        "version": "1",
        "captured": {},
        "labeling": {"status": status, "reviewed_by": reviewer},
        "tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
                "definition_hash": tool.definition_hash,
                "label": {"tags": {**DEFAULTS, "egress": label_egress}},
            }
        ],
    }
    return LabeledServer.model_validate(data)


def test_ai_reviewed_counts_only_ai_reviewers() -> None:
    servers = [
        _server("reviewed", "AI: some-model, at the request of a maintainer"),
        _server("reviewed", "A. Reviewer"),
        _server("draft", None),
    ]
    assert ai_reviewed(servers) == 1


def test_build_includes_only_reviewed_servers() -> None:
    bundle = build.build_bundle([_server("draft", None), _server("reviewed", "A. Reviewer")])
    assert len(bundle.classifications) == 1
    assert build.build_bundle([_server("draft", None)]).classifications == {}


def test_build_requires_a_named_reviewer() -> None:
    with pytest.raises(build.BuildError, match="reviewed_by"):
        build.build_bundle([_server("reviewed", None)])


def test_build_rejects_conflicting_labels_for_one_definition() -> None:
    other = _server("reviewed", "B. Reviewer", label_egress="none").model_copy(
        update={"id": "demo2"}
    )
    with pytest.raises(build.BuildError, match="different label"):
        build.build_bundle([_server("reviewed", "A. Reviewer"), other])


def test_bundle_text_is_deterministic_and_round_trips() -> None:
    bundle = build.build_bundle([_server("reviewed", "A. Reviewer")])
    text = dump_bundle(bundle)
    assert text == dump_bundle(parse_bundle(text))
    json.loads(text)


def test_cli_without_credentials_falls_back_to_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def no_credentials(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("no credentials; sk-ant-fake-would-leak-0000")

    monkeypatch.setattr(cli, "AnthropicProvider", no_credentials)
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {"s": {"command": "x"}}}', encoding="utf-8")
    inventory = tmp_path / "inv.json"
    assert cli.main(["scan", str(config), "-o", str(inventory)]) == 0
    capsys.readouterr()

    out = tmp_path / "classified.json"
    args = ["classify", str(inventory), "-o", str(out), "--cache-dir", str(tmp_path / "c")]
    code = cli.main(args)
    err = capsys.readouterr().err
    assert code == 0
    assert "reported as not assessed" in err
    assert "fake-would-leak" not in err  # the exception text is never echoed

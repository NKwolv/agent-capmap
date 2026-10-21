"""Classifier evaluation against hand-labeled real MCP servers (eval/).

Metrics:
- per axis: accuracy, per-value precision/recall/F1, macro-F1, and capability detection
  (any non-default value vs default) precision/recall/F1;
- exact match: all six tags right;
- confusion matrices (egress and execution are reported in results.md);
- suspicious-description precision/recall;
- rule-level agreement: the default policy run on realistic agent setups with
  predicted tags vs ground-truth tags (gives the false-positive rate on clean agents);
- planted-risk recall: classifier-dependent findings planted in fixtures/.

Ground truth is never produced by the LLM. Labels marked "draft" (pre-filled, not yet
human-reviewed) make every result PROVISIONAL.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentcapmap.enumerate.hashing import server_definition_hash, tool_definition_hash
from agentcapmap.findings import Severity
from agentcapmap.models import (
    Agent,
    AuthHint,
    AuthMethod,
    ClassificationStatus,
    EnumerationResult,
    EnumerationStatus,
    Inventory,
    Server,
    SourceLocation,
    ToolClassification,
    ToolDefinition,
    ToolTags,
    Transport,
)
from agentcapmap.policy import Policy, evaluate
from agentcapmap.taxonomy import AXES, DEFAULTS, axis_values

UNCLASSIFIED = "unclassified"
LabelStatus = Literal["unlabeled", "draft", "reviewed"]


class EvalDataError(ValueError):
    pass


# --- label files -----------------------------------------------------------------------


class ToolLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tags: ToolTags
    evidence: dict[str, str] = Field(default_factory=dict)
    suspicious: bool = False
    notes: str = ""


class LabeledTool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    definition_hash: str
    label: ToolLabel | None = None

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name=self.name,
            description=self.description,
            input_schema=self.input_schema,
            definition_hash=self.definition_hash,
        )


class Labeling(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: LabelStatus
    labeled_by: str | None = None
    labeled_at: str | None = None
    reviewed_by: str | None = None
    reviewed_at: str | None = None


class LabeledServer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    source: str
    version: str
    deprecated: bool = False
    captured: dict[str, Any]
    labeling: Labeling
    tools: list[LabeledTool]


def load_labeled_servers(directory: Path) -> list[LabeledServer]:
    servers: list[LabeledServer] = []
    for path in sorted(directory.glob("*.json")):
        server = LabeledServer.model_validate_json(path.read_text(encoding="utf-8"))
        for tool in server.tools:
            expected = tool_definition_hash(tool.name, tool.description, tool.input_schema)
            if expected != tool.definition_hash:
                raise EvalDataError(f"{path.name}: definition of {tool.name!r} was edited")
            if server.labeling.status != "unlabeled" and tool.label is None:
                raise EvalDataError(f"{path.name}: {tool.name!r} has no label")
        servers.append(server)
    return servers


def label_manifest(directory: Path) -> dict[str, str]:
    """sha256 of each label file, for freezing the label set."""
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.glob("*.json"))
    }


def manifest_digest(manifest: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


# --- per-axis metrics --------------------------------------------------------------------


@dataclass
class ClassMetrics:
    precision: float | None
    recall: float | None
    f1: float | None
    support: int


@dataclass
class AxisMetrics:
    axis: str
    accuracy: float
    macro_f1: float | None
    detection: ClassMetrics  # non-default vs default
    per_value: dict[str, ClassMetrics]
    confusion: dict[str, dict[str, int]]  # truth -> predicted -> count


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _prf(tp: int, fp: int, fn: int) -> ClassMetrics:
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else (0.0 if precision is not None and recall is not None else None)
    )
    return ClassMetrics(precision, recall, f1, tp + fn)


def _key(value: Any) -> str:
    return str(value).lower()


def axis_metrics(axis: str, pairs: list[tuple[Any, Any]]) -> AxisMetrics:
    """`pairs` are (truth, predicted); predicted may be UNCLASSIFIED."""
    values = [_key(v) for v in axis_values(axis)]
    default = _key(DEFAULTS[axis])
    confusion = {v: dict.fromkeys([*values, UNCLASSIFIED], 0) for v in values}
    for truth, pred in pairs:
        confusion[_key(truth)][_key(pred)] += 1
    total = len(pairs)
    correct = sum(confusion[v][v] for v in values)
    per_value = {}
    for v in values:
        tp = confusion[v][v]
        fp = sum(confusion[t][v] for t in values if t != v)
        fn = sum(confusion[v].values()) - tp
        per_value[v] = _prf(tp, fp, fn)
    f1s = [m.f1 for m in per_value.values() if m.support and m.f1 is not None]
    det_tp = sum(
        1 for t, p in pairs if _key(t) != default and _key(p) not in (default, UNCLASSIFIED)
    )
    det_fp = sum(
        1 for t, p in pairs if _key(t) == default and _key(p) not in (default, UNCLASSIFIED)
    )
    det_fn = sum(1 for t, p in pairs if _key(t) != default and _key(p) in (default, UNCLASSIFIED))
    return AxisMetrics(
        axis=axis,
        accuracy=correct / total if total else 0.0,
        macro_f1=sum(f1s) / len(f1s) if f1s else None,
        detection=_prf(det_tp, det_fp, det_fn),
        per_value=per_value,
        confusion=confusion,
    )


@dataclass
class Disagreement:
    server: str
    tool: str
    axis: str
    truth: str
    predicted: str
    evidence: str


@dataclass
class ClassifierReport:
    tools: int
    unclassified: int
    exact_match: float
    axes: dict[str, AxisMetrics]
    suspicious: ClassMetrics
    disagreements: list[Disagreement] = field(default_factory=list)


def score_classifier(
    servers: Iterable[LabeledServer], predictions: dict[str, ToolClassification]
) -> ClassifierReport:
    """Compare predictions (by definition hash) with labels."""
    pairs: dict[str, list[tuple[Any, Any]]] = {axis: [] for axis in AXES}
    exact = unclassified = total = 0
    sus_tp = sus_fp = sus_fn = 0
    disagreements: list[Disagreement] = []
    for server in servers:
        for tool in server.tools:
            if tool.label is None:
                continue
            total += 1
            pred = predictions.get(tool.definition_hash)
            pred_tags = (
                pred.tags if pred and pred.status is ClassificationStatus.CLASSIFIED else None
            )
            if pred_tags is None:
                unclassified += 1
            all_right = pred_tags is not None
            for axis in AXES:
                truth = getattr(tool.label.tags, axis)
                predicted = getattr(pred_tags, axis) if pred_tags is not None else UNCLASSIFIED
                pairs[axis].append((truth, predicted))
                if _key(truth) != _key(predicted):
                    all_right = False
                    evidence = pred.evidence.get(axis, "") if pred else ""
                    disagreements.append(
                        Disagreement(
                            server.id, tool.name, axis, _key(truth), _key(predicted), evidence
                        )
                    )
            exact += all_right
            flagged = bool(
                pred and pred.suspicious_description and pred.suspicious_description.flag
            )
            sus_tp += tool.label.suspicious and flagged
            sus_fp += (not tool.label.suspicious) and flagged
            sus_fn += tool.label.suspicious and not flagged
    return ClassifierReport(
        tools=total,
        unclassified=unclassified,
        exact_match=exact / total if total else 0.0,
        axes={axis: axis_metrics(axis, pairs[axis]) for axis in AXES},
        suspicious=_prf(sus_tp, sus_fp, sus_fn),
        disagreements=disagreements,
    )


# --- rule-level agreement on realistic agents --------------------------------------------

Classify = Callable[[ToolDefinition], ToolClassification]


def truth_classification(label: ToolLabel) -> ToolClassification:
    return ToolClassification(
        status=ClassificationStatus.CLASSIFIED,
        tags=label.tags,
        confidence=1.0,
        evidence=label.evidence,
        suspicious_description=None if not label.suspicious else _suspicious("labeled"),
        model="ground-truth",
        taxonomy_version="1",
        prompt_version="labels",
    )


def _suspicious(reason: str) -> Any:
    from agentcapmap.models import SuspiciousDescription

    return SuspiciousDescription(flag=True, reason=reason)


def build_agent(
    agent_id: str,
    servers: list[LabeledServer],
    catalog: dict[str, dict[str, Any]],
    classification_for: Callable[[LabeledTool], ToolClassification],
) -> Agent:
    built: list[Server] = []
    for line, server in enumerate(servers, start=1):
        spec = catalog[server.id]
        tools = []
        for tool in server.tools:
            definition = tool.definition()
            definition.classification = classification_for(tool)
            tools.append(definition)
        remote = "url" in spec
        built.append(
            Server(
                name=server.id,
                transport=Transport.HTTP if remote else Transport.STDIO,
                command=None if remote else spec["command"],
                args=[] if remote else list(spec["args"]),
                url=spec.get("url"),
                auth=AuthHint(method=AuthMethod.STATIC if spec.get("env") else AuthMethod.NONE),
                location=SourceLocation(path=f"{agent_id}.json", line=line),
                enumeration=EnumerationResult(
                    status=EnumerationStatus.OK,
                    tools=tools,
                    definition_hash=server_definition_hash(t.definition_hash for t in tools),
                ),
            )
        )
    return Agent(id=agent_id, client="eval", config_path=f"{agent_id}.json", servers=built)


@dataclass
class RuleAgreement:
    agents: int
    truth_findings: int
    predicted_findings: int
    matched: int
    precision: float | None
    recall: float | None
    clean_agents: int  # no critical/high finding under ground truth
    false_alarm_agents: int  # of those, agents with a predicted critical/high finding
    per_agent: list[dict[str, Any]] = field(default_factory=list)

    @property
    def false_positive_rate(self) -> float | None:
        return _ratio(self.false_alarm_agents, self.clean_agents)


def _severe(rules: set[tuple[str, str]], policy: Policy) -> set[str]:
    severity = {r.id: r.severity for r in policy.rules}
    return {rule for rule, _sev in rules if severity[rule].rank >= Severity.HIGH.rank}


def rule_agreement(
    agents: dict[str, list[str]],
    servers: dict[str, LabeledServer],
    catalog: dict[str, dict[str, Any]],
    predictions: dict[str, ToolClassification],
    policy: Policy,
) -> RuleAgreement:
    def predicted(tool: LabeledTool) -> ToolClassification:
        return predictions.get(tool.definition_hash) or ToolClassification(
            status=ClassificationStatus.UNCLASSIFIED,
            error="no prediction",
            taxonomy_version="1",
            prompt_version="?",
        )

    def truth(tool: LabeledTool) -> ToolClassification:
        if tool.label is None:  # callers skip agents with unlabeled tools
            raise EvalDataError(f"{tool.name!r} has no label")
        return truth_classification(tool.label)

    truth_total = pred_total = matched = clean = false_alarms = 0
    per_agent = []
    for agent_id, server_ids in sorted(agents.items()):
        members = [servers[s] for s in server_ids if s in servers]
        if len(members) != len(server_ids) or any(
            t.label is None for m in members for t in m.tools
        ):
            continue  # skip agents whose servers are missing or unlabeled
        found = {}
        for kind, fn in (("truth", truth), ("predicted", predicted)):
            agent = build_agent(agent_id, members, catalog, fn)
            evaluation = evaluate(Inventory(agents=[agent]), policy)
            found[kind] = {(f.rule_id, f.severity.value) for f in evaluation.findings}
        t_rules, p_rules = {r for r, _ in found["truth"]}, {r for r, _ in found["predicted"]}
        truth_total += len(t_rules)
        pred_total += len(p_rules)
        matched += len(t_rules & p_rules)
        if not _severe(found["truth"], policy):
            clean += 1
            false_alarms += bool(_severe(found["predicted"], policy))
        per_agent.append(
            {
                "agent": agent_id,
                "servers": server_ids,
                "truth": sorted(t_rules),
                "predicted": sorted(p_rules),
            }
        )
    return RuleAgreement(
        agents=len(per_agent),
        truth_findings=truth_total,
        predicted_findings=pred_total,
        matched=matched,
        precision=_ratio(matched, pred_total),
        recall=_ratio(matched, truth_total),
        clean_agents=clean,
        false_alarm_agents=false_alarms,
        per_agent=per_agent,
    )


# --- planted risks in fixtures/ ------------------------------------------------------------

# Findings in fixtures/ that depend on the classifier's tags (CAP-006 and CAP-009 do not).
PLANTED = {
    "trifecta": {"CAP-001"},
    "exec-injection": {"CAP-002", "CAP-003"},
    "no-approval-destructive": {"CAP-003"},
    "poisoned-description": {"CAP-008"},
    "overscoped-token": {"CAP-005"},
    "rug-pull": {"CAP-008"},
}


@dataclass
class PlantedRecall:
    planted: int
    detected: int
    per_fixture: dict[str, dict[str, list[str]]]

    @property
    def recall(self) -> float | None:
        return _ratio(self.detected, self.planted)


def fixture_inventory(directory: Path, classify: Classify) -> Inventory:
    """A fixture's config + tool definitions, classified by `classify` (not by its tags)."""
    from agentcapmap.discovery import parse_config_file

    agent, error = parse_config_file(directory / "mcp.json", root=directory, explicit=True)
    if error or agent is None:
        raise EvalDataError(f"{directory.name}: {error.message if error else 'no agent'}")
    spec = json.loads((directory / "tools.json").read_text(encoding="utf-8"))
    for server in agent.servers:
        server_spec = spec["servers"][server.name]
        tools = []
        for t in server_spec["tools"]:
            schema = t.get("inputSchema", {"type": "object"})
            definition = ToolDefinition(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=schema,
                definition_hash=tool_definition_hash(t["name"], t.get("description", ""), schema),
            )
            definition.classification = classify(definition)
            tools.append(definition)
        server.enumeration = EnumerationResult(status=EnumerationStatus.OK, tools=tools)
        if auth := server_spec.get("auth"):
            server.auth = AuthHint(method=AuthMethod(auth))
    return Inventory(agents=[agent])


def planted_recall(fixtures: Path, classify: Classify, policy: Policy) -> PlantedRecall:
    planted = detected = 0
    per_fixture = {}
    for name, rules in sorted(PLANTED.items()):
        found = {
            f.rule_id
            for f in evaluate(fixture_inventory(fixtures / name, classify), policy).findings
        }
        hits = rules & found
        planted += len(rules)
        detected += len(hits)
        per_fixture[name] = {
            "planted": sorted(rules),
            "detected": sorted(hits),
            "all": sorted(found),
        }
    return PlantedRecall(planted, detected, per_fixture)


def label_status(servers: Iterable[LabeledServer]) -> Counter[str]:
    return Counter(s.labeling.status for s in servers)

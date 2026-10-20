"""Load and validate policy files.

Policy files may come from a repository being scanned, so they are untrusted input:
- size-capped before parsing;
- parsed with PyYAML's safe loader only (no arbitrary object construction);
- anchors and aliases rejected (no "billion laughs" expansion, no merge-key tricks);
- duplicate keys rejected (YAML would otherwise silently keep the last one);
- validated against schemas/policy.schema.json, with unknown fields rejected;
- checked for duplicate rule ids and contradictory condition combinations.
"""

from __future__ import annotations

import functools
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from agentcapmap.findings import PolicyInfo, Severity
from agentcapmap.taxonomy import TAXONOMY_VERSION, data_file

DEFAULT_POLICY_NAME = "builtin:default.yaml"
# Policies are small (the default is ~4 KB); a tight cap also bounds parser work.
_MAX_POLICY_BYTES = 256 * 1024
_MAX_FLOW_DEPTH = 32


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Predicate:
    """Field -> allowed values. Every field must match on the same tool or server."""

    fields: tuple[tuple[str, frozenset[str | bool]], ...]

    def matches(self, view: Any) -> bool:
        return all(view.field(name) in allowed for name, allowed in self.fields)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.fields)

    def describe(self) -> dict[str, Any]:
        return {
            name: sorted(allowed, key=str) if len(allowed) > 1 else next(iter(allowed))
            for name, allowed in self.fields
        }


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    message: str
    maps_to: tuple[str, ...]
    enabled: bool
    has_all: tuple[Predicate, ...]
    has_any: tuple[Predicate, ...]
    server_filter: tuple[Predicate, ...] | None
    hash_changed: bool
    shadowed: bool

    @property
    def tag_based(self) -> bool:
        return bool(self.has_all or self.has_any)


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    trusted_sources: tuple[str, ...]
    info: PolicyInfo


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError:
                raise PolicyError(
                    f"unsupported mapping key at line {key_node.start_mark.line + 1}"
                ) from None
            if duplicate:
                raise PolicyError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _check_flow_depth(text: str) -> None:
    """Reject deep [ / { nesting before PyYAML sees it.

    PyYAML's parser is super-linear in flow-collection depth (8,000 nested brackets take
    ~50 s), so a small hostile file could stall a scan. Brackets inside quoted strings
    are counted too: that is conservative (it can only reject, never let through), and
    no sensible policy comes close to the limit.
    """
    depth = 0
    for index, char in enumerate(text):
        if char in "[{":
            depth += 1
            if depth > _MAX_FLOW_DEPTH:
                line = text.count("\n", 0, index) + 1
                raise PolicyError(f"YAML nested more than {_MAX_FLOW_DEPTH} levels (line {line})")
        elif char in "]}" and depth:
            depth -= 1


def _parse_yaml(text: str) -> Any:
    _check_flow_depth(text)
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                line = event.start_mark.line + 1 if event.start_mark else "?"
                raise PolicyError(f"YAML anchors and aliases are not allowed (line {line})")
        loader = _StrictSafeLoader(text)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise PolicyError(f"invalid YAML{where}") from None
    except RecursionError:
        raise PolicyError("YAML nested too deeply") from None


@functools.cache
def _validator() -> Draft202012Validator:
    schema = json.loads(data_file("schemas", "policy.schema.json"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _predicates(raw: Any) -> tuple[Predicate, ...]:
    if raw is None:
        return ()
    items = raw if isinstance(raw, list) else [raw]
    return tuple(
        Predicate(
            fields=tuple(
                (name, frozenset(value if isinstance(value, list) else [value]))
                for name, value in sorted(item.items())
            )
        )
        for item in items
    )


def _build_rule(raw: dict[str, Any]) -> Rule:
    rule = Rule(
        id=raw["id"],
        severity=Severity(raw["severity"]),
        message=" ".join(raw["message"].split()),
        maps_to=tuple(raw.get("maps_to", [])),
        enabled=raw.get("enabled", True),
        has_all=_predicates(raw.get("when_agent_has_all")),
        has_any=_predicates(raw.get("when_agent_has_any")),
        server_filter=_predicates(raw["when_server"]) if "when_server" in raw else None,
        hash_changed=raw.get("when_hash_changed", False),
        shadowed=raw.get("when_tool_name_shadowed", False),
    )
    special = [flag for flag in (rule.hash_changed, rule.shadowed) if flag]
    if len(special) > 1 or (special and rule.tag_based):
        raise PolicyError(
            f"rule {rule.id}: when_hash_changed / when_tool_name_shadowed cannot be combined "
            "with each other or with when_agent_has_* conditions"
        )
    return rule


def parse_policy(text: str, source: str) -> Policy:
    data = _parse_yaml(text)
    error = best_match(_validator().iter_errors(data))
    if error is not None:
        where = "/".join(str(p) for p in error.absolute_path) or "(root)"
        raise PolicyError(f"{source}: invalid policy at {where}: {error.message}")
    if data["taxonomy_version"] != TAXONOMY_VERSION:
        raise PolicyError(f"{source}: policy targets taxonomy {data['taxonomy_version']!r}")

    rules = tuple(_build_rule(raw) for raw in data["rules"])
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise PolicyError(f"{source}: duplicate rule id(s): {', '.join(dupes)}")
    return Policy(
        rules=rules,
        trusted_sources=tuple(data.get("trusted_sources", [])),
        info=PolicyInfo(
            source=source,
            version=data["version"],
            taxonomy_version=data["taxonomy_version"],
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        ),
    )


def load_policy(path: Path | None = None) -> Policy:
    """Load a policy file, or the built-in default policy when `path` is None."""
    if path is None:
        return parse_policy(data_file("policies", "default.yaml"), DEFAULT_POLICY_NAME)
    try:
        if path.stat().st_size > _MAX_POLICY_BYTES:
            raise PolicyError(f"{path}: policy file larger than {_MAX_POLICY_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise PolicyError(f"{path}: policy is not UTF-8 text") from None
    return parse_policy(text, path.as_posix())

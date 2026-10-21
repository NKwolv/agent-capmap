"""Write labels into eval/labeled_servers/<id>.json from a compact JSON spec.

    python eval/apply_labels.py SPEC.json --by "draft: <model or person>"

SPEC maps server id -> tool name -> {"tags": {...non-default only...},
"evidence": {axis: phrase}, "suspicious": false, "notes": ""}. Every tool of a server
must be labeled. Evidence phrases must appear in the tool's description or input schema
(case-insensitive), so labels cannot cite text that is not there. Status becomes
"draft"; a person sets "reviewed" after checking (see eval/README.md).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

from agentcapmap.taxonomy import AXES, DEFAULTS

LABELS = Path(__file__).resolve().parent / "labeled_servers"


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("spec", type=Path)
    parser.add_argument("--by", required=True, help='who labeled, e.g. "draft: claude-opus-5-5"')
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    problems: list[str] = []
    for server_id, tools in spec.items():
        path = LABELS / f"{server_id}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["labeling"]["status"] == "reviewed":
            problems.append(f"{server_id}: already reviewed, not overwriting")
            continue
        names = {t["name"] for t in data["tools"]}
        if missing := names - set(tools):
            problems.append(f"{server_id}: unlabeled tools {sorted(missing)}")
            continue
        if extra := set(tools) - names:
            problems.append(f"{server_id}: unknown tools {sorted(extra)}")
            continue
        for tool in data["tools"]:
            entry = tools[tool["name"]]
            tags = {**DEFAULTS, **entry.get("tags", {})}
            haystack = _norm(tool["description"] + " " + json.dumps(tool["input_schema"]))
            evidence = entry.get("evidence", {})
            for axis in AXES:
                if tags[axis] != DEFAULTS[axis] and axis not in evidence:
                    problems.append(f"{server_id}/{tool['name']}: no evidence for {axis}")
            for phrase in evidence.values():
                if _norm(phrase) not in haystack:
                    problems.append(f"{server_id}/{tool['name']}: evidence not found: {phrase!r}")
            tool["label"] = {
                "tags": tags,
                "evidence": evidence,
                "suspicious": entry.get("suspicious", False),
                "notes": entry.get("notes", ""),
            }
        data["labeling"] = {
            "status": "draft",
            "labeled_by": args.by,
            "labeled_at": dt.date.today().isoformat(),
            "reviewed_by": None,
            "reviewed_at": None,
        }
        if not any(p.startswith(f"{server_id}") for p in problems):
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())

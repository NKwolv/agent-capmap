"""Help a person review the eval labels, file by file, riskiest first.

    python eval/review.py list                       # files ranked by how much they matter
    python eval/review.py sheet --top 3 -o sheet.md   # a worksheet for the 3 riskiest files
    python eval/review.py sheet --files github,fetch  # or for named files
    python eval/review.py mark github fetch --by "Your Name"   # record a finished review

A label file counts as human-reviewed only when you have been through EVERY tool in it, so
work file by file. Files you have not reviewed stay AI-reviewed (`reviewed_by` starts with
"AI:"), and evaluation results say how many. `mark` refuses a name that starts with "AI:"
and never edits tool definitions or tags: fix a tag first by editing the JSON by hand.

After marking, run `python scripts/build_reference_labels.py` and commit both changes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentcapmap.evaluation import LabeledServer, load_labeled_servers
from agentcapmap.taxonomy import AXES, DEFAULTS

LABELS = Path(__file__).resolve().parent / "labeled_servers"
# Non-default values that decide the most serious findings (CAP-001 to CAP-005).
_HIGH_IMPACT = {
    "data_access": {"secrets_read"},
    "egress": {"external"},
    "mutation": {"destructive"},
    "execution": {"host"},
    "privilege": {"identity_admin"},
}
_MAX_DESCRIPTION = 500

# Words in a definition that suggest a capability the tags do not show. Only hints: the
# reviewer decides.
_HINT_WORDS: dict[str, tuple[str, str, re.Pattern[str]]] = {
    "mutation": (
        "none",
        "deletes or overwrites",
        re.compile(
            r"\b(delet\w*|destroy\w*|terminat\w*|revok\w*|purge\w*|overwrit\w*|wipe)\b", re.I
        ),
    ),
    "egress": (
        "none",
        "sends data out",
        re.compile(r"\b(webhook\w*|email|upload\w*|publish\w*|post to)\b", re.I),
    ),
    "execution": (
        "none",
        "runs code or commands",
        re.compile(
            r"\b(shell|bash|subprocess|arbitrary code|run (?:a )?(?:command|script))\b", re.I
        ),
    ),
    "data_access": (
        "none",
        "touches private data",
        re.compile(r"\b(private|password|credential\w*|secret\w*|token\w*|api key)\b", re.I),
    ),
}


@dataclass(frozen=True)
class FileSummary:
    server_id: str
    tools: int
    high_impact: int
    notes: int
    suspicious: int
    reviewer: str

    @property
    def score(self) -> int:
        return self.high_impact * 3 + self.notes + self.suspicious * 5

    @property
    def human_reviewed(self) -> bool:
        return not self.reviewer.startswith("AI:") and self.reviewer != ""


def _non_default(tags: dict[str, Any]) -> dict[str, Any]:
    return {axis: tags[axis] for axis in AXES if tags[axis] != DEFAULTS[axis]}


def _is_high_impact(tags: dict[str, Any]) -> bool:
    return any(tags.get(axis) in values for axis, values in _HIGH_IMPACT.items())


def summarize(server: LabeledServer) -> FileSummary:
    high = notes = suspicious = 0
    for tool in server.tools:
        if tool.label is None:
            continue
        tags = tool.label.tags.model_dump()
        high += int(_is_high_impact(tags))
        notes += int(bool(tool.label.notes.strip()))
        suspicious += int(tool.label.suspicious)
    return FileSummary(
        server.id, len(server.tools), high, notes, suspicious, server.labeling.reviewed_by or ""
    )


def ranked(servers: list[LabeledServer]) -> list[FileSummary]:
    """Files worth a person's time first: many high-impact tools, judgment calls, flags."""
    return sorted(
        (summarize(s) for s in servers), key=lambda f: (f.human_reviewed, -f.score, f.server_id)
    )


def hints(tool_description: str, schema_text: str, tags: dict[str, Any]) -> list[str]:
    found = []
    text = f"{tool_description} {schema_text}"
    for axis, (default, meaning, pattern) in _HINT_WORDS.items():
        if tags.get(axis) == default and (match := pattern.search(text)):
            found.append(f'mentions "{match.group(0)}" ({meaning}) but {axis} is {default}')
    return found


def _one_line(text: str, limit: int) -> str:
    flat = re.sub(r"\s+", " ", text).strip()
    return flat if len(flat) <= limit else flat[: limit - 1] + "..."


def sheet(servers: list[LabeledServer], ids: list[str]) -> str:
    by_id = {s.id: s for s in servers}
    unknown = [i for i in ids if i not in by_id]
    if unknown:
        raise ValueError(f"unknown label file(s): {', '.join(unknown)}")
    out = [
        "# Label review worksheet",
        "",
        "For each tool: read the description, check the tags against `docs/taxonomy.md`, and",
        "fix any tag you disagree with by editing `eval/labeled_servers/<id>.json` (change the",
        "tag, and the `evidence` phrase to text copied from the description). Do not edit",
        "names, descriptions or hashes. A file counts as human-reviewed only when you have",
        "been through every tool in it; then run",
        '`python eval/review.py mark <id> --by "Your Name"`.',
        "",
        "Defaults (not listed below): "
        + ", ".join(f"{a}={str(DEFAULTS[a]).lower()}" for a in AXES),
        "",
    ]
    for server_id in ids:
        server = by_id[server_id]
        info = summarize(server)
        heading = f"## {server.id} ({info.tools} tool(s); {info.high_impact} high-impact"
        heading += f"; {info.notes} with notes)"
        current = info.reviewer or "unreviewed"
        out += [heading, f"File: `eval/labeled_servers/{server.id}.json` | now: `{current}`", ""]
        for tool in server.tools:
            if tool.label is None:
                continue
            tags = tool.label.tags.model_dump()
            shown = _non_default(tags)
            tag_text = (
                ", ".join(f"{k}={str(v).lower()}" for k, v in shown.items()) or "(all defaults)"
            )
            flag = " **HIGH-IMPACT**" if _is_high_impact(tags) else ""
            flag += " **SUSPICIOUS**" if tool.label.suspicious else ""
            out.append(f"- [ ] `{tool.name}`: **{tag_text}**{flag}")
            for axis, phrase in tool.label.evidence.items():
                out.append(f'  - evidence for {axis}: "{_one_line(phrase, 160)}"')
            if tool.label.notes.strip():
                out.append(f"  - note: {_one_line(tool.label.notes, 300)}")
            schema_text = json.dumps(tool.input_schema, ensure_ascii=False)
            for hint in hints(tool.description, schema_text, tags):
                out.append(f"  - CHECK: {hint}")
            out.append(f"  - description: {_one_line(tool.description, _MAX_DESCRIPTION)}")
        out.append("")
    return "\n".join(out)


def mark(directory: Path, ids: list[str], reviewer: str, today: dt.date | None = None) -> list[str]:
    """Record a person's completed review. Touches only the `labeling` block."""
    name = reviewer.strip()
    if not name or name.upper().startswith("AI:") or len(name) > 100:
        raise ValueError("--by must be your name (1-100 characters, not starting with 'AI:')")
    servers = {s.id: s for s in load_labeled_servers(directory)}
    unknown = [i for i in ids if i not in servers]
    if unknown:
        raise ValueError(f"unknown label file(s): {', '.join(unknown)}")
    date = (today or dt.date.today()).isoformat()
    changed = []
    for server_id in ids:
        path = directory / f"{server_id}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["labeling"]["status"] = "reviewed"
        data["labeling"]["reviewed_by"] = name
        data["labeling"]["reviewed_at"] = date
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
        )
        changed.append(server_id)
    load_labeled_servers(directory)  # still valid after the edit
    return changed


def _print_list(servers: list[LabeledServer]) -> None:
    rows = ranked(servers)
    total = sum(r.tools for r in rows)
    print(f"{'file':22} {'tools':>5} {'high':>5} {'notes':>5} {'susp':>4}  reviewer")
    for r in rows:
        who = r.reviewer if len(r.reviewer) <= 40 else r.reviewer[:37] + "..."
        counts = f"{r.tools:>5} {r.high_impact:>5} {r.notes:>5} {r.suspicious:>4}"
        print(f"{r.server_id:22} {counts}  {who}")
    done = sum(r.tools for r in rows if r.human_reviewed)
    print()
    print(f"{done} of {total} tools are in human-reviewed files. Review from the top of the list.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--labels", type=Path, default=LABELS, help="label directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="files ranked by how much a review of each matters")
    p_sheet = sub.add_parser("sheet", help="print a review worksheet")
    p_sheet.add_argument("--top", type=int, default=3, help="the N riskiest unreviewed files")
    p_sheet.add_argument("--files", help="comma-separated file ids instead of --top")
    p_sheet.add_argument("-o", "--output", type=Path, help="write here instead of stdout")
    p_mark = sub.add_parser("mark", help="record that you reviewed whole files")
    p_mark.add_argument("ids", nargs="+", help="label file ids, e.g. github fetch")
    p_mark.add_argument("--by", required=True, help="your name")
    args = parser.parse_args(argv)

    try:
        if args.command == "mark":
            done = mark(args.labels, args.ids, args.by)
            print(f"marked reviewed by {args.by!r}: {', '.join(done)}")
            print("next: python scripts/build_reference_labels.py, then commit both changes")
            return 0
        servers = load_labeled_servers(args.labels)
        if args.command == "list":
            _print_list(servers)
            return 0
        ids = (
            [i.strip() for i in args.files.split(",") if i.strip()]
            if args.files
            else [r.server_id for r in ranked(servers)][: max(1, args.top)]
        )
        text = sheet(servers, ids)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {args.output} ({len(ids)} file(s))")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

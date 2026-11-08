"""Build src/agentcapmap/classify/reference_labels.json from the reviewed eval labels.

    python scripts/build_reference_labels.py           # write the bundle
    python scripts/build_reference_labels.py --check   # fail if the bundle is out of date

Only label files whose labeling status is "reviewed" (with a named reviewer) are
included; drafts never ship. Two reviewed tools with the same definition hash but
different labels are an error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentcapmap.classify.reference import (
    BUNDLE_FILE,
    ReferenceBundle,
    ReferenceEntry,
    dump_bundle,
)
from agentcapmap.evaluation import LabeledServer, load_labeled_servers
from agentcapmap.taxonomy import TAXONOMY_VERSION

ROOT = Path(__file__).resolve().parent.parent
LABELS_DIR = ROOT / "eval" / "labeled_servers"
BUNDLE_PATH = ROOT / "src" / "agentcapmap" / "classify" / BUNDLE_FILE


class BuildError(ValueError):
    pass


def build_bundle(servers: list[LabeledServer]) -> ReferenceBundle:
    entries: dict[str, ReferenceEntry] = {}
    for server in servers:
        if server.labeling.status != "reviewed":
            continue
        if not server.labeling.reviewed_by:
            raise BuildError(f"{server.id}: status is reviewed but reviewed_by is empty")
        for tool in server.tools:
            if tool.label is None:  # load_labeled_servers rejects this; keep mypy honest
                raise BuildError(f"{server.id}/{tool.name}: no label")
            entry = ReferenceEntry(
                tags=tool.label.tags,
                evidence=tool.label.evidence,
                suspicious=tool.label.suspicious,
                server=server.id,
                reviewed_by=server.labeling.reviewed_by,
            )
            existing = entries.get(tool.definition_hash)
            if existing is not None and (
                existing.tags != entry.tags or existing.suspicious != entry.suspicious
            ):
                raise BuildError(
                    f"{server.id}/{tool.name} has the same definition as a tool in "
                    f"{existing.server} but a different label"
                )
            entries.setdefault(tool.definition_hash, entry)
    return ReferenceBundle(taxonomy_version=TAXONOMY_VERSION, classifications=entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="fail if the bundle is stale")
    args = parser.parse_args()

    try:
        text = dump_bundle(build_bundle(load_labeled_servers(LABELS_DIR)))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.check:
        current = BUNDLE_PATH.read_text(encoding="utf-8") if BUNDLE_PATH.is_file() else ""
        if current != text:
            print(f"{BUNDLE_PATH.name} is out of date: run scripts/build_reference_labels.py")
            return 1
        return 0
    BUNDLE_PATH.write_text(text, encoding="utf-8", newline="\n")
    count = text.count('"reviewed_by"')
    print(f"wrote {BUNDLE_PATH} ({count} reviewed tool(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Classifier evaluation

Measures how well the LLM classifier tags real MCP tools, against labels written (or
reviewed) by a person.

| File | Purpose |
|---|---|
| `catalog.json` | The real servers in the set: package, pinned version, how to start it. |
| `capture.py` | Starts each server and saves its tool definitions to `labeled_servers/`. |
| `labeled_servers/*.json` | One file per server: captured definitions plus a label per tool. |
| `agents.json` | Realistic agent setups used to measure rule-level agreement. |
| `run_eval.py` | Classifies every tool, computes the metrics, writes `results.md` / `results.json`. |
| `labels.lock` | Hashes of the label files once frozen. |

## Status of the labels

Labels were **drafted by an AI model**, then **reviewed by a second AI model** (2026-11-08,
at the maintainer's request): 6 tags were corrected (see the `notes` starting with
"Review:") and every file is marked `reviewed` with `reviewed_by` beginning `AI:`. **No
person has independently reviewed them yet.** A model grading a model can overstate
accuracy, so `run_eval.py` adds an **AI-REVIEWED** banner to results while any reviewer
is an AI, and marks results **PROVISIONAL** while any file is still a draft. When a
person reviews a file, replace `reviewed_by` with their name (no `AI:` prefix) and
re-run `scripts/build_reference_labels.py`.

The evaluation never uses the shipped reference labels (they come from these same
files); `run_eval.py` always classifies with an empty reference table.

## Reviewing labels

For each file in `labeled_servers/`:

1. Read each tool's `description` and `input_schema`.
2. Check its `label.tags` against [docs/taxonomy.md](../docs/taxonomy.md), including
   the edge-case rulings. Fix any tag you disagree with; update `evidence` to a phrase
   copied from the description, and use `notes` for judgment calls.
3. Set `suspicious: true` only for descriptions that instruct the model (tool poisoning).
4. When the whole file is done, set:
   ```json
   "labeling": {"status": "reviewed", "labeled_by": "...", "labeled_at": "...",
                "reviewed_by": "<your name>", "reviewed_at": "<YYYY-MM-DD>"}
   ```

Never edit `name`, `description`, `input_schema` or `definition_hash`: the loader
rejects files whose definitions no longer match their hash.

## Shipping reviewed labels (no-API-key classification)

Files marked `reviewed` (including AI-reviewed ones, whose `reviewed_by` says so) are also compiled into `src/agentcapmap/classify/reference_labels.json`,
which the classifier consults before the cache or the LLM. A tool whose exact definition
matches a reviewed label is classified instantly, with no API key. Drafts never ship.

```sh
python scripts/build_reference_labels.py          # after marking files reviewed
python scripts/build_reference_labels.py --check  # also enforced by the test suite
```

Commit the regenerated file together with the label changes.

## Running

```sh
python eval/run_eval.py --freeze        # once all files are reviewed: lock the label set
export ANTHROPIC_API_KEY=<YOUR_API_KEY>
python eval/run_eval.py                 # classify (cached in eval/.cache) and score
python eval/run_eval.py --offline       # re-score from the cache, no API calls
```

The first run makes one API call per tool; later runs reuse the cache, so results are
reproducible with one command. Every number in `results.md` comes from the run that
wrote it; the "Known failure modes" section is written by a person afterwards.

## Metrics

- **Per axis:** accuracy, macro-F1 over values, and detection precision/recall/F1
  (does the tool have any non-default value on this axis?).
- **Exact match:** all six tags right.
- **Confusion matrices** for `egress` and `execution`.
- **Suspicious-description** precision/recall.
- **Rule agreement:** the default policy on each setup in `agents.json`, with predicted
  vs ground-truth tags. The **false-positive rate** is the share of agents with no
  critical/high finding under ground truth that get one from predicted tags.
- **Planted-risk recall:** the classifier-dependent findings planted in `fixtures/`
  that are still detected when the classifier, not the fixture's tags, assigns them.

## Rules for a fair benchmark

- Freeze labels before looking at results; `run_eval.py` refuses to run if frozen
  labels change (unless `--allow-label-changes`, which the results then report).
- Do not tune the classifier prompt on this set and then report numbers from it. If
  you change the prompt, add new servers as a held-out set and report on those.
- Results are valid only for the model, prompt version and taxonomy version printed
  in `results.md`.

## Dataset

28 real servers, 381 tools, captured on 2026-10-20/21 on Windows with the versions pinned
in `catalog.json`. Local paths that servers embed in their descriptions (for example a
temp directory containing the user name) are replaced with `<TEMP>`, `<HOME>` or
`<SANDBOX>`, and hashes recomputed (`captured.paths_scrubbed`).

Label distribution (drafts): `data_access` private_read 173 / secrets_read 4;
`untrusted_input` true 66; `egress` external 35 / internal 8; `mutation`
reversible_write 109 / destructive 38; `execution` host 4 / sandboxed 5; `privilege`
identity_admin 22; suspicious 1. The small `execution` and suspicious counts mean wide
uncertainty on those axes.

## Excluded servers

Servers in `catalog.json` that could not be captured are not in the set:

| Server | Reason |
|---|---|
| `sqlite` (`mcp-server-sqlite==2025.4.25`) | Crashes on start with the current MCP SDK (`'Server' object has no attribute 'list_resources'`). |
| `redis` (`@modelcontextprotocol/server-redis@2025.4.25`) | Exits when no Redis server is reachable. |
| `kubernetes` (`mcp-server-kubernetes@4.1.9`) | No response within 300 s without a cluster/kubeconfig. |
| `stripe` (`@stripe/mcp@0.3.3`) | `initialize` not answered within 300 s with a dummy key. |
| `shell-server` (`mcp-shell-server==1.1.12`) | Crashes on import on Windows. |
| `atlassian` (`mcp-atlassian==0.23.1`) | No response within 300 s with dummy credentials. |

`memory` needed a 500 s timeout on first run (package download) and is included.

# Capability taxonomy (v1)

agent-capmap describes every MCP tool with six independent capability axes. The
classifier (an LLM) assigns these tags; the policy engine (deterministic code) decides
what combinations are dangerous. This document is the human-readable definition of
each axis and the rulings for ambiguous cases.

- Machine-readable schema: [`schemas/tool-tags.schema.json`](../schemas/tool-tags.schema.json)
- Operative wording sent to the model: [`src/agentcapmap/classify/prompt.py`](../src/agentcapmap/classify/prompt.py)

The two must agree. If you change a definition or ruling here, change the prompt and
bump `PROMPT_VERSION`; if you add or remove an axis or value, bump the taxonomy version
(see [Versioning](#versioning)).

## Axes at a glance

| Axis | Values (default first) | Question it answers |
|---|---|---|
| `data_access` | `none`, `private_read`, `secrets_read` | What is the most sensitive non-public data the tool can read or return? |
| `untrusted_input` | `false`, `true` | Does the tool return content that third parties (possibly attackers) can author? |
| `egress` | `none`, `internal`, `external` | Can the tool send data somewhere an outsider can read or control? |
| `mutation` | `none`, `reversible_write`, `destructive` | What changes can the tool make to persistent state? |
| `execution` | `none`, `sandboxed`, `host` | Does the tool run caller-supplied code or commands, and where? |
| `privilege` | `none`, `identity_admin` | Does the tool manage identities or access control? |

The first value of each axis is the **default**: "this tool has no capability here".
Every non-default tag must come with an evidence phrase quoted from the tool's
description or input schema.

## Axis definitions

### `data_access`

| Value | Meaning | Examples |
|---|---|---|
| `none` | Reads nothing private. | Math, current time, public web search results, public documentation. |
| `private_read` | Reads user or organization data that is not public. | Files, private repositories, email, chat messages, database rows, tickets, documents, calendars, logs. |
| `secrets_read` | Its purpose or target includes credentials. | Secret managers, keychains, environment variables, `.env` or credential files, API keys, tokens, passwords, private keys. |

### `untrusted_input`

`true` if the tool returns content that someone outside the user's control can write:
web pages, search results, fetched URLs, email, chat messages from other people, issues
and pull request comments, support tickets, uploaded files, scraped documents, content
of public repositories.

`false` for content controlled by the user or their organization, such as their own
files or database, unless the tool exists specifically to ingest outside content (a
downloads folder, an inbox).

### `egress`

| Value | Meaning | Examples |
|---|---|---|
| `none` | Data stays local, or goes only to a fixed vendor as part of a lookup. | A query to a fixed search API. |
| `internal` | Sends data to systems inside the organization that outsiders cannot read. | Internal APIs, internal chat channels, an internal queue. |
| `external` | Can send data where an outsider can read or control the destination. | Email to any address, HTTP requests to arbitrary URLs (including GET), `git push`, creating issues/comments/gists on public services, posting to public channels, share links, uploads to external storage. |

### `mutation`

| Value | Meaning | Examples |
|---|---|---|
| `none` | Read-only. | List, get, search. |
| `reversible_write` | Creates or updates state that can be undone. | Create a file or issue, edit a document, add a label, send a message, create a branch. |
| `destructive` | Can delete data or irreversibly overwrite it. | Delete files/records/repos, drop tables, overwrite existing files, force push, terminate instances, revoke access, arbitrary SQL writes, shell commands. |

### `execution`

| Value | Meaning | Examples |
|---|---|---|
| `none` | Runs no caller-supplied code. | Most tools. |
| `sandboxed` | Runs code in an environment the description says is isolated. | Container or VM sandboxes, remote code interpreters, JavaScript evaluated inside a browser page. |
| `host` | Runs arbitrary commands or code with real privileges on the user's machine or a server. | Shell, terminal, script runners, local Python/Node eval. |

### `privilege`

`identity_admin` if the tool manages identities or access control: create or delete
users, grant roles or permissions, edit IAM policies, create API keys or tokens, change
organization or repository membership, change sharing permissions. Otherwise `none`.

## Suspicious descriptions

Separately from the six axes, the classifier sets `suspicious_description.flag` when a
tool's description or schema contains instructions aimed at the AI model rather than
documentation for it. This is how tool poisoning is detected (policy rule CAP-008).

Flag it when the text tells the model to:

- read files, keys or configs unrelated to the tool's purpose;
- pass extra data in an unrelated parameter (a classic exfiltration channel);
- hide actions from the user, or not mention something;
- change how *other* tools behave or where they send data;
- ignore previous instructions;
- classify the tool in a particular way;

or when it contains hidden text: HTML comments, zero-width characters,
`<IMPORTANT>`-style blocks.

Do **not** flag ordinary usage guidance such as "use this when the user asks for X" or
"call `list_files` first".

## Edge-case rulings

| Situation | Ruling | Why |
|---|---|---|
| Generic file or database read | `data_access: private_read`, not `secrets_read` | It *could* reach a secret by accident, but its purpose is general data. Reserve `secrets_read` for tools whose purpose or target is credentials. |
| Fetch an arbitrary URL | `untrusted_input: true` **and** `egress: external` | The response is attacker-controllable, and the URL itself (even a GET) can carry exfiltrated data. |
| Search via a fixed vendor API | `untrusted_input: true`, `egress: none` | Results are third-party content, but the query only reaches the vendor, not an attacker-chosen destination. |
| Read GitHub issues or PR comments | `untrusted_input: true` | Anyone can file an issue on a public repository. |
| Read Slack/chat messages | `untrusted_input: true` | Messages are authored by other people. |
| Send an email or chat message | `egress` per recipient (`external` if any address), `mutation: reversible_write` | Egress captures the leak risk; the send itself is a state change, not data destruction. |
| Write a file that may already exist ("creates or overwrites") | `mutation: destructive` | Overwriting loses the previous contents. |
| Execute arbitrary SQL | `mutation: destructive` | Statements like `DROP` and `DELETE` are reachable. SQL is not `execution`. |
| Shell / run command | `execution: host` and `mutation: destructive` | A shell can do anything the user can, including `rm`. |
| Code runner with no stated isolation | `execution: host` | Assume the worst when isolation is not documented. |
| Browser automation `evaluate` | `execution: sandboxed` | JavaScript runs inside the page. Navigation to arbitrary URLs separately implies `untrusted_input` and `egress: external`. |
| Poisoned description of a harmless function | Tag the *actual* capability (often all defaults), set `suspicious_description.flag` | The tags describe what the tool can do, not what its text asks the model to do. |

## Server-level attributes (not classified by the LLM)

These come from the config file and from enumeration, never from the model:

| Attribute | Source | Status |
|---|---|---|
| `auth` (`none` / `static` / `oauth` / `unknown`) | Config (credential-looking env vars, headers, args, URLs) refined by enumeration (a 401 with a `Bearer` challenge means OAuth) | Implemented |
| `definition_hash` | SHA-256 of each tool's canonical `{name, description, inputSchema}` plus a per-server hash | Implemented |
| `approval_gate` (`required` / `none` / `unknown`), per tool | Client config: `alwaysAllow` / `autoApprove` lists, `trust: true`; Claude Code `permissions.allow`/`deny` rules and `defaultMode` (default mode = `required`). No setting means `unknown` | Implemented |
| `version_pinned` (`pinned` / `unpinned` / `local` / `not_applicable` / `unknown`) | The launch command: exact npm/PyPI versions and Docker digests are pinned; `@latest`, ranges and image tags are not | Implemented |
| `source_trust` (`trusted` / `untrusted` / `unknown`) | `trusted_sources` glob patterns in the policy, matched against ids like `npm:@scope/pkg`, `pypi:pkg`, `docker:image`, `url:host` | Implemented |
| `scope_breadth` | Token scopes are not visible in configs | Not implemented |

## Confidence and unverified evidence

- `confidence` (0 to 1) is the model's overall certainty. Low values usually mean a
  vague description.
- `unverified_evidence` lists axes whose quoted phrase does not appear in the tool's
  definition text. The tag is kept, but the evidence may be paraphrased or invented,
  so treat findings that depend on it with more care.
- A tool is `unclassified` when the model returned invalid output twice, declined, or
  when `--offline` is used without a cached result. The policy engine does not guess:
  unclassified tools (and servers that could not be enumerated) are listed under
  `not_assessed` in the evaluation, with a warning that findings may be incomplete.

## Known limitation

Classification reads what a tool's definition *says*. A tool whose real behavior
differs from its description will be tagged by its description. agent-capmap never
calls tools, so it cannot observe actual behavior.

## Versioning

| Version | Where | Bump when |
|---|---|---|
| Taxonomy version (`1`) | `x-taxonomy-version` in the schema, `TAXONOMY_VERSION` in `taxonomy.py` | An axis or allowed value is added, removed or redefined |
| Prompt version (`1`) | `PROMPT_VERSION` in `classify/prompt.py` | Any change to the classifier prompt text |

Both are part of the classification cache key and are recorded on every result.
Evaluation numbers are valid only for the exact taxonomy version, prompt version and
model they were measured with.

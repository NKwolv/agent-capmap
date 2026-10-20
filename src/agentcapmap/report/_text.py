"""Helpers for putting untrusted text (tool names, descriptions, evidence, policy
messages) into reports.

Everything that came from an MCP server, a config file or a policy file is treated as
hostile: redacted again (defense in depth), stripped of control characters, collapsed
to one line, and truncated. In Markdown it is rendered only inside code spans, where
links, HTML and emphasis are inert.
"""

from __future__ import annotations

import re

from agentcapmap.redact import redact_text

# C0/C1 controls, line/paragraph separators, zero-width and bidi-override characters
# ("Trojan Source"). Built from code points so this source file stays ASCII.
_INVISIBLE_RANGES = (
    (0x00, 0x1F),
    (0x7F, 0x9F),
    (0x200B, 0x200F),
    (0x2028, 0x2029),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
_CONTROL = re.compile(
    "["
    + "".join(f"{re.escape(chr(lo))}-{re.escape(chr(hi))}" for lo, hi in _INVISIBLE_RANGES)
    + "]"
)
_SPACE = re.compile(r"\s+")
_BACKTICKS = re.compile(r"`+")
ELLIPSIS = chr(0x2026)  # horizontal ellipsis


def clean(text: object, limit: int = 300) -> str:
    """One line of plain text: redacted, no control or bidi characters, bounded length."""
    value = redact_text(str(text))
    value = _CONTROL.sub(" ", value)
    value = _SPACE.sub(" ", value).strip()
    if len(value) > limit:
        value = value[: limit - 1].rstrip() + ELLIPSIS
    return value


def md_code(text: object, limit: int = 300, *, in_table: bool = False) -> str:
    """Render untrusted text as an inline code span.

    The fence is one backtick longer than the longest backtick run inside, so the text
    cannot close the span early. In tables `|` is escaped, which GFM honours even inside
    code spans.
    """
    value = clean(text, limit)
    if not value:
        return "-"
    longest = max((len(m.group(0)) for m in _BACKTICKS.finditer(value)), default=0)
    fence = "`" * (longest + 1)
    if value.startswith("`") or value.endswith("`"):
        value = f" {value} "
    if in_table:
        value = value.replace("|", "\\|")
    return f"{fence}{value}{fence}"

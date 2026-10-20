"""Resource limits for untrusted input (config files, MCP server output).

A hostile MCP server or config file must not be able to exhaust memory or CPU, or
crash a reader thread. Everything read from outside goes through these bounds.
"""

from __future__ import annotations

import json
from typing import Any, Final

# One JSON-RPC message (stdio line, HTTP body, SSE event).
MAX_MESSAGE_BYTES: Final = 8 * 1024 * 1024
# One config file.
MAX_CONFIG_BYTES: Final = 4 * 1024 * 1024
# Tools accepted from a single server across all tools/list pages.
MAX_TOOLS_PER_SERVER: Final = 5000
# Unanswered server-to-client messages buffered while waiting for a response.
MAX_QUEUED_MESSAGES: Final = 1000
# Longest stderr line kept for diagnostics.
MAX_STDERR_LINE_CHARS: Final = 2000


class UntrustedJSONError(ValueError):
    pass


def loads_untrusted(text: str | bytes) -> Any:
    """json.loads that turns pathological input (e.g. deep nesting) into a ValueError."""
    try:
        return json.loads(text)
    except RecursionError:
        raise UntrustedJSONError("JSON nested too deeply") from None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UntrustedJSONError(f"invalid JSON: {exc}") from None

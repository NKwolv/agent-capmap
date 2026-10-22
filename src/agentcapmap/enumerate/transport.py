"""JSON-RPC transport interface and the method allowlist.

Design rule: agent-capmap never executes tools on enumerated servers. Every outgoing
request goes through `check_allowed`, so a `tools/call` (or anything else) cannot be
sent even by mistake.
"""

from __future__ import annotations

import itertools
from typing import Any, Protocol

ALLOWED_REQUESTS = frozenset({"initialize", "tools/list"})
ALLOWED_NOTIFICATIONS = frozenset({"notifications/initialized"})

JSONRPC_METHOD_NOT_FOUND = -32601


class TransportError(Exception):
    """The connection failed or the server misbehaved at the protocol level."""


class RequestTimeout(TransportError):
    pass


class AuthRequired(TransportError):
    def __init__(self, message: str, www_authenticate: str | None = None) -> None:
        super().__init__(message)
        self.www_authenticate = www_authenticate


class ForbiddenMethod(RuntimeError):
    """Raised before sending anything outside the allowlist. A bug, not a server problem."""


class MCPError(Exception):
    """The server returned a JSON-RPC error object."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code


def check_allowed(method: str, *, notification: bool = False) -> None:
    allowed = ALLOWED_NOTIFICATIONS if notification else ALLOWED_REQUESTS
    if method not in allowed:
        raise ForbiddenMethod(f"refusing to send {method!r}: agent-capmap never invokes tools")


class Transport(Protocol):
    def request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        """Send a request and return its `result`; raise MCPError on a JSON-RPC error."""

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a notification (no response expected)."""

    def close(self) -> None:
        """Release the connection or terminate the server process."""


class IdCounter:
    def __init__(self) -> None:
        self._it = itertools.count(1)

    def next(self) -> int:
        return next(self._it)


def unwrap_response(message: dict[str, Any]) -> dict[str, Any]:
    if "error" in message:
        err = message["error"] if isinstance(message["error"], dict) else {}
        raise MCPError(int(err.get("code", 0)), str(err.get("message", "unknown error")))
    result = message.get("result")
    if not isinstance(result, dict):
        raise TransportError("response 'result' is not an object")
    return result


def is_response_to(message: Any, request_id: int) -> bool:
    return (
        isinstance(message, dict)
        and message.get("id") == request_id
        and "method" not in message
        and ("result" in message or "error" in message)
    )

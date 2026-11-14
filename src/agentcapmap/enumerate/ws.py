"""WebSocket transport (`"type": "ws"`, used by Claude Code): one JSON-RPC message per frame.

Needs the optional `websockets` package (`pip install "agent-capmap[ws]"`).

Security properties, matching the HTTP transports:
- The TCP connection is made here, to an address that passed the netguard check, and
  handed to the library, so there is no second DNS lookup to rebind. TLS verifies the
  certificate against the host name.
- Redirects are not followed: the library cannot redirect a connection made on a
  socket it did not open, and that refusal is reported as such. Credentials in the
  configured headers therefore never reach another location. No proxy is used.
- Frames are size-bounded, compression is off (no decompression bombs), and unrelated
  messages read while waiting for a response are counted and capped.
"""

from __future__ import annotations

import contextlib
import json
import socket
import ssl
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import certifi

from agentcapmap import __version__
from agentcapmap.enumerate.netguard import resolve_checked
from agentcapmap.enumerate.transport import (
    AuthRequired,
    IdCounter,
    RequestTimeout,
    TransportError,
    check_allowed,
    is_response_to,
    unwrap_response,
)
from agentcapmap.limits import (
    MAX_CONNECT_ADDRESSES,
    MAX_MESSAGE_BYTES,
    MAX_QUEUED_MESSAGES,
    loads_untrusted,
)
from agentcapmap.limits import UntrustedJSONError as _BadJSON
from agentcapmap.redact import redact_url

if TYPE_CHECKING:
    from websockets.sync.client import ClientConnection

_USER_AGENT = f"agent-capmap/{__version__}"
_DEFAULT_PORTS = {"ws": 80, "wss": 443}
MISSING_DEPENDENCY = (
    'WebSocket servers need the optional dependency: pip install "agent-capmap[ws]"'
)


class WebSocketUnavailable(TransportError):
    """The optional `websockets` package is not installed."""


def _connect_checked(host: str, port: int, timeout: float, url: str) -> socket.socket:
    addresses = resolve_checked(host)[:MAX_CONNECT_ADDRESSES]
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError:
            continue  # try the next checked address
    raise TransportError(f"cannot connect to {redact_url(url)}")


class WebSocketTransport:
    def __init__(self, url: str, headers: dict[str, str], timeout: float) -> None:
        try:
            from websockets.exceptions import InvalidStatus, WebSocketException
            from websockets.sync.client import connect
            from websockets.typing import Subprotocol
        except ImportError:
            raise WebSocketUnavailable(MISSING_DEPENDENCY) from None
        self._errors: tuple[type[Exception], ...] = (WebSocketException, OSError)
        self._url = url
        self._ids = IdCounter()

        parts = urlsplit(url)
        scheme, host = parts.scheme.lower(), parts.hostname or ""
        sock = _connect_checked(host, parts.port or _DEFAULT_PORTS[scheme], timeout, url)
        context = ssl.create_default_context(cafile=certifi.where()) if scheme == "wss" else None
        try:
            self._ws: ClientConnection = connect(
                url,
                sock=sock,
                ssl=context,
                server_hostname=host if context else None,
                subprotocols=[Subprotocol("mcp")],
                additional_headers=headers,
                user_agent_header=_USER_AGENT,
                proxy=None,
                compression=None,
                open_timeout=timeout,
                ping_interval=None,
                close_timeout=2,
                max_size=MAX_MESSAGE_BYTES,
                legacy=True,  # return the connection itself, not a reconnecting wrapper
            )
        except InvalidStatus as exc:
            sock.close()
            raise self._status_error(exc.response) from None
        except ValueError as exc:
            # The library follows redirects itself, except with a socket we opened: then
            # it raises ValueError from the 3xx response. That refusal is what we want.
            sock.close()
            if isinstance(exc.__cause__, InvalidStatus):
                raise self._status_error(exc.__cause__.response) from None
            raise self._error(exc) from None
        except TimeoutError:
            sock.close()
            raise RequestTimeout(f"WebSocket handshake timed out after {timeout:.0f}s") from None
        except self._errors as exc:
            sock.close()
            raise self._error(exc) from None

    def _status_error(self, response: Any) -> TransportError:
        status = response.status_code
        if status == 401:
            return AuthRequired(
                f"HTTP 401 from {redact_url(self._url)}: authentication required",
                response.headers.get("WWW-Authenticate"),
            )
        if 300 <= status < 400:
            return TransportError(
                f"HTTP {status} redirect from {redact_url(self._url)} refused "
                "(credentials are never forwarded to another location)"
            )
        return TransportError(f"HTTP {status} from {redact_url(self._url)}")

    def _error(self, exc: Exception) -> TransportError:
        # Exception text can embed the URL or response headers; report only its type.
        return TransportError(
            f"WebSocket error contacting {redact_url(self._url)}: {type(exc).__name__}"
        )

    def _send(self, body: dict[str, Any]) -> None:
        try:
            self._ws.send(json.dumps(body))
        except self._errors as exc:
            raise self._error(exc) from None

    def request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        check_allowed(method)
        request_id = self._ids.next()
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        for _ in range(MAX_QUEUED_MESSAGES):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                frame = self._ws.recv(timeout=remaining)
            except TimeoutError:
                break
            except self._errors as exc:
                raise self._error(exc) from None
            try:
                message = loads_untrusted(frame)
            except _BadJSON:
                continue  # not JSON-RPC: ignore, as the other transports do
            if is_response_to(message, request_id):
                return unwrap_response(message)
        else:
            raise TransportError(f"too many unrelated messages while waiting for {method}")
        raise RequestTimeout(f"{method} timed out after {timeout:.0f}s")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        check_allowed(method, notification=True)
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        self._send(body)

    def close(self) -> None:
        with contextlib.suppress(*self._errors):
            self._ws.close()

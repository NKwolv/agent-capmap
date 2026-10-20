"""HTTP transports: Streamable HTTP (current spec) and legacy HTTP+SSE.

Security properties:
- Redirects are never followed, so configured credentials (Authorization, API-key
  headers) cannot be forwarded to another host.
- The legacy SSE `endpoint` must be same-origin as the configured URL, for the same
  reason.
- Response bodies, lines and SSE events are size-bounded.
"""

from __future__ import annotations

import contextlib
import queue
import threading
import time
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from agentcapmap import __version__
from agentcapmap.enumerate.transport import (
    AuthRequired,
    IdCounter,
    RequestTimeout,
    TransportError,
    check_allowed,
    is_response_to,
    unwrap_response,
)
from agentcapmap.limits import MAX_MESSAGE_BYTES, MAX_QUEUED_MESSAGES, loads_untrusted
from agentcapmap.limits import UntrustedJSONError as _BadJSON
from agentcapmap.redact import get_logger, redact_url

log = get_logger(__name__)

_USER_AGENT = f"agent-capmap/{__version__}"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def iter_sse(lines: Iterable[str], max_event_chars: int | None = None) -> Iterator[tuple[str, str]]:
    """Yield (event, data) pairs from a text/event-stream line iterator."""
    max_event_chars = max_event_chars or MAX_MESSAGE_BYTES
    event, data, size = "message", list[str](), 0
    for line in lines:
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data, size = "message", [], 0
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if field == "event":
            event = value
        elif field == "data":
            size += len(value) + 1
            if size > max_event_chars:
                raise TransportError(f"SSE event larger than {max_event_chars} bytes")
            data.append(value)
    if data:
        yield event, "\n".join(data)


def _bounded_lines(response: httpx.Response) -> Iterator[str]:
    """Decode a streamed body into lines, refusing any line longer than the limit."""
    max_line = MAX_MESSAGE_BYTES
    buffer = ""
    for chunk in response.iter_text():
        buffer += chunk
        while (newline := buffer.find("\n")) != -1:
            yield buffer[:newline].removesuffix("\r")
            buffer = buffer[newline + 1 :]
        if len(buffer) > max_line:
            raise TransportError(f"response line longer than {max_line} bytes")
    if buffer:
        yield buffer.removesuffix("\r")


def _read_body(response: httpx.Response) -> bytes:
    limit = MAX_MESSAGE_BYTES
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise TransportError(f"response body larger than {limit} bytes")
    body = bytearray()
    for chunk in response.iter_bytes():
        body += chunk
        if len(body) > limit:
            raise TransportError(f"response body larger than {limit} bytes")
    return bytes(body)


def _raise_for_status(response: httpx.Response, url: str) -> None:
    status = response.status_code
    if status == 401:
        raise AuthRequired(
            f"HTTP 401 from {redact_url(url)}: authentication required",
            response.headers.get("www-authenticate"),
        )
    if 300 <= status < 400:
        raise TransportError(
            f"HTTP {status} redirect from {redact_url(url)} refused "
            "(credentials are never forwarded to another location)"
        )
    if status >= 400:
        raise TransportError(f"HTTP {status} from {redact_url(url)}")


def _http_error(url: str, exc: httpx.HTTPError) -> TransportError:
    # The exception text can embed the full URL (including secrets); report only its type.
    return TransportError(f"HTTP error contacting {redact_url(url)}: {type(exc).__name__}")


def _parse_json_messages(body: bytes) -> list[Any]:
    try:
        parsed = loads_untrusted(body)
    except _BadJSON as exc:
        raise TransportError(f"server returned invalid JSON ({exc})") from None
    return parsed if isinstance(parsed, list) else [parsed]


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or "").lower(), parts.port or _DEFAULT_PORTS.get(scheme)


def _client(headers: dict[str, str], timeout: float) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": _USER_AGENT, **headers},
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
    )


class StreamableHttpTransport:
    """POST each JSON-RPC message; responses come back as JSON or as an SSE stream."""

    def __init__(self, url: str, headers: dict[str, str], timeout: float) -> None:
        self._url = url
        self._http = _client(headers, timeout)
        self._ids = IdCounter()
        self._session_id: str | None = None
        self._protocol_version: str | None = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if self._protocol_version:
            headers["MCP-Protocol-Version"] = self._protocol_version
        return headers

    def _find_response(
        self, response: httpx.Response, method: str, request_id: int, deadline: float
    ) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "").split(";")[0].strip()
        if content_type == "text/event-stream":
            for _event, data in iter_sse(_bounded_lines(response)):
                if time.monotonic() > deadline:
                    raise RequestTimeout(f"{method} timed out")
                try:
                    message = loads_untrusted(data)
                except _BadJSON:
                    continue
                if is_response_to(message, request_id):
                    return unwrap_response(message)
            raise TransportError(f"SSE stream ended without a response to {method}")
        for message in _parse_json_messages(_read_body(response)):
            if is_response_to(message, request_id):
                return unwrap_response(message)
        raise TransportError(f"no response to {method} in HTTP body")

    def request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        check_allowed(method)
        request_id = self._ids.next()
        body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        deadline = time.monotonic() + timeout
        try:
            with self._http.stream(
                "POST", self._url, json=body, headers=self._headers(), timeout=timeout
            ) as response:
                _raise_for_status(response, self._url)
                if session_id := response.headers.get("mcp-session-id"):
                    self._session_id = session_id
                result = self._find_response(response, method, request_id, deadline)
        except httpx.TimeoutException:
            raise RequestTimeout(f"{method} timed out after {timeout:.0f}s") from None
        except httpx.HTTPError as exc:
            raise _http_error(self._url, exc) from None

        if method == "initialize":
            version = result.get("protocolVersion")
            self._protocol_version = version if isinstance(version, str) else None
        return result

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        check_allowed(method, notification=True)
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        try:
            response = self._http.post(self._url, json=body, headers=self._headers())
        except httpx.HTTPError as exc:
            raise _http_error(self._url, exc) from None
        _raise_for_status(response, self._url)

    def close(self) -> None:
        if self._session_id:
            with contextlib.suppress(httpx.HTTPError):
                self._http.delete(self._url, headers=self._headers(), timeout=5)
        self._http.close()


class LegacySseTransport:
    """Deprecated 2024-11-05 transport: GET an SSE stream, POST to the advertised endpoint."""

    def __init__(self, url: str, headers: dict[str, str], timeout: float) -> None:
        self._url = url
        self._http = _client(headers, timeout)
        self._ids = IdCounter()
        self._messages: queue.Queue[Any] = queue.Queue(maxsize=MAX_QUEUED_MESSAGES)
        self._endpoint: queue.Queue[str | BaseException] = queue.Queue()
        self._closed = threading.Event()
        threading.Thread(target=self._listen, daemon=True).start()
        try:
            item = self._endpoint.get(timeout=timeout)
        except queue.Empty:
            self.close()
            raise RequestTimeout(f"no SSE endpoint event within {timeout:.0f}s") from None
        if isinstance(item, BaseException):
            self.close()
            raise item
        self._post_url: str = item

    def _endpoint_url(self, data: str) -> str:
        endpoint = urljoin(self._url, data.strip())
        if _origin(endpoint) != _origin(self._url):
            raise TransportError(
                "SSE endpoint is on a different origin than the configured URL; refusing to "
                "send requests (and credentials) there"
            )
        return endpoint

    def _listen(self) -> None:
        try:
            with self._http.stream(
                "GET",
                self._url,
                headers={"Accept": "text/event-stream"},
                timeout=httpx.Timeout(10.0, read=None),
            ) as response:
                _raise_for_status(response, self._url)
                for event, data in iter_sse(_bounded_lines(response)):
                    if self._closed.is_set():
                        return
                    if event == "endpoint":
                        self._endpoint.put(self._endpoint_url(data))
                    elif event == "message":
                        with contextlib.suppress(_BadJSON):
                            self._messages.put(loads_untrusted(data))
        except TransportError as exc:
            self._endpoint.put(exc)
        except httpx.HTTPError as exc:
            if not self._closed.is_set():
                self._endpoint.put(_http_error(self._url, exc))
        finally:
            with contextlib.suppress(queue.Full):
                self._messages.put_nowait(None)

    def _post(self, body: dict[str, Any]) -> None:
        try:
            response = self._http.post(
                self._post_url, json=body, headers={"Content-Type": "application/json"}
            )
        except httpx.HTTPError as exc:
            raise _http_error(self._url, exc) from None
        _raise_for_status(response, self._post_url)

    def request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        check_allowed(method)
        request_id = self._ids.next()
        self._post({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RequestTimeout(f"{method} timed out after {timeout:.0f}s")
            try:
                message = self._messages.get(timeout=remaining)
            except queue.Empty:
                continue
            if message is None:
                raise TransportError("SSE stream closed before response")
            if is_response_to(message, request_id):
                return unwrap_response(message)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        check_allowed(method, notification=True)
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        self._post(body)

    def close(self) -> None:
        self._closed.set()
        self._http.close()

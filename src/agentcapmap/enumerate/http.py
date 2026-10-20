"""HTTP transports: Streamable HTTP (current spec) and legacy HTTP+SSE."""

from __future__ import annotations

import contextlib
import json
import queue
import threading
import time
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urljoin

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
from agentcapmap.redact import get_logger, redact_url

log = get_logger(__name__)

_USER_AGENT = f"agent-capmap/{__version__}"


def iter_sse(lines: Iterable[str]) -> Iterator[tuple[str, str]]:
    """Yield (event, data) pairs from a text/event-stream line iterator."""
    event, data = "message", list[str]()
    for line in lines:
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data = "message", []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if field == "event":
            event = value
        elif field == "data":
            data.append(value)
    if data:
        yield event, "\n".join(data)


def _raise_for_status(response: httpx.Response, url: str) -> None:
    if response.status_code == 401:
        raise AuthRequired(
            f"HTTP 401 from {redact_url(url)}: authentication required",
            response.headers.get("www-authenticate"),
        )
    if response.status_code >= 400:
        raise TransportError(f"HTTP {response.status_code} from {redact_url(url)}")


def _parse_json_messages(body: str) -> list[Any]:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        raise TransportError("server returned invalid JSON") from None
    return parsed if isinstance(parsed, list) else [parsed]


def _client(headers: dict[str, str], timeout: float) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": _USER_AGENT, **headers},
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
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
                content_type = response.headers.get("content-type", "").split(";")[0].strip()
                if content_type == "text/event-stream":
                    for _event, data in iter_sse(response.iter_lines()):
                        if time.monotonic() > deadline:
                            raise RequestTimeout(f"{method} timed out after {timeout:.0f}s")
                        try:
                            message = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if is_response_to(message, request_id):
                            result = unwrap_response(message)
                            break
                    else:
                        raise TransportError(f"SSE stream ended without a response to {method}")
                else:
                    response.read()
                    for message in _parse_json_messages(response.text):
                        if is_response_to(message, request_id):
                            result = unwrap_response(message)
                            break
                    else:
                        raise TransportError(f"no response to {method} in HTTP body")
        except httpx.TimeoutException:
            raise RequestTimeout(f"{method} timed out after {timeout:.0f}s") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"HTTP error contacting {redact_url(self._url)}: {exc}") from None

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
            raise TransportError(f"HTTP error contacting {redact_url(self._url)}: {exc}") from None
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
        self._messages: queue.Queue[Any] = queue.Queue()
        self._endpoint: queue.Queue[str | BaseException] = queue.Queue()
        self._closed = threading.Event()
        self._post_url: str | None = None
        threading.Thread(target=self._listen, daemon=True).start()
        try:
            item = self._endpoint.get(timeout=timeout)
        except queue.Empty:
            self.close()
            raise RequestTimeout(f"no SSE endpoint event within {timeout:.0f}s") from None
        if isinstance(item, BaseException):
            self.close()
            raise item
        self._post_url = item

    def _listen(self) -> None:
        try:
            with self._http.stream(
                "GET",
                self._url,
                headers={"Accept": "text/event-stream"},
                timeout=httpx.Timeout(10.0, read=None),
            ) as response:
                _raise_for_status(response, self._url)
                for event, data in iter_sse(response.iter_lines()):
                    if self._closed.is_set():
                        return
                    if event == "endpoint":
                        self._endpoint.put(urljoin(self._url, data.strip()))
                    elif event == "message":
                        with contextlib.suppress(json.JSONDecodeError):
                            self._messages.put(json.loads(data))
        except TransportError as exc:
            self._endpoint.put(exc)
        except httpx.HTTPError as exc:
            if not self._closed.is_set():
                self._endpoint.put(
                    TransportError(f"SSE connection to {redact_url(self._url)} failed: {exc}")
                )
        finally:
            self._messages.put(None)

    def _post(self, body: dict[str, Any]) -> None:
        assert self._post_url is not None
        try:
            response = self._http.post(
                self._post_url, json=body, headers={"Content-Type": "application/json"}
            )
        except httpx.HTTPError as exc:
            raise TransportError(f"HTTP error contacting {redact_url(self._url)}: {exc}") from None
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

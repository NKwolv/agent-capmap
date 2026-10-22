"""Mock MCP server for tests: stdio (run as a script) and HTTP (in-process).

Every received method is recorded so tests can prove the client only ever sends
`initialize`, `notifications/initialized` and `tools/list`.

stdio usage: python mock_mcp_server.py SPEC.json
Spec keys (all optional):
  tools: list of tool dicts            page_size: int (paginate tools/list)
  call_log: path to append methods     noise: print non-JSON lines to stdout
  ping_first: send a ping request before answering initialize
  hang_on: method name to never answer no_tools_capability: omit "tools" capability
  stderr_env: env var to print to stderr, then exit 1 (simulates a leaky crash)
  report_env: env var names; serverInfo.env reports which ones the server can see
  junk_before_init: raw text written to stdout before the initialize response
  tool_count: generate this many trivial tools

HTTP mock extras (spec): redirect_to (POST answers 307 to this URL),
  endpoint (legacy SSE endpoint event value), body_padding (extra bytes in JSON body)
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read a file from the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email to any address.",
        "inputSchema": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
        },
        "annotations": {"destructiveHint": False, "openWorldHint": True},
    },
]


def handle(spec: dict[str, Any], message: dict[str, Any]) -> dict[str, Any] | None:
    """Return the JSON-RPC response for a request, or None for notifications/hangs."""
    method = message.get("method")
    if "id" not in message or method is None:
        return None
    if method == spec.get("hang_on"):
        return None
    request_id = message["id"]
    if method == "initialize":
        capabilities: dict[str, Any] = {} if spec.get("no_tools_capability") else {"tools": {}}
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": message.get("params", {}).get("protocolVersion"),
                "capabilities": capabilities,
                "serverInfo": {
                    "name": "mock-mcp",
                    "version": "1.0.0",
                    **(
                        {"env": {n: n in os.environ for n in spec["report_env"]}}
                        if spec.get("report_env")
                        else {}
                    ),
                },
            },
        }
    if method == "tools/list":
        tools = spec.get("tools", DEFAULT_TOOLS)
        if count := spec.get("tool_count"):
            tools = [{"name": f"t{i}", "inputSchema": {}} for i in range(int(count))]
        page_size = int(spec.get("page_size") or len(tools) or 1)
        start = int(message.get("params", {}).get("cursor") or 0)
        result: dict[str, Any] = {"tools": tools[start : start + page_size]}
        if start + page_size < len(tools):
            result["nextCursor"] = str(start + page_size)
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def _record(spec: dict[str, Any], entry: str) -> None:
    if log_path := spec.get("call_log"):
        with Path(log_path).open("a", encoding="utf-8") as f:
            f.write(entry + "\n")


def run_stdio(spec: dict[str, Any]) -> None:
    if name := spec.get("stderr_env"):
        print(f"fatal: authentication failed using {os.environ.get(name, '')}", file=sys.stderr)
        sys.exit(1)

    def send(obj: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    pinged = False
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        message = json.loads(line)
        if "method" not in message:
            _record(spec, f"response:{message.get('id')}")
            continue
        _record(spec, message["method"])
        if spec.get("noise"):
            sys.stdout.write("mock server log line, not JSON\n")
        if spec.get("ping_first") and not pinged:
            pinged = True
            send({"jsonrpc": "2.0", "id": "ping-1", "method": "ping"})
            send({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "hi"}})
        if message["method"] == "initialize" and (junk := spec.get("junk_before_init")):
            sys.stdout.write(junk)
            sys.stdout.flush()
        response = handle(spec, message)
        if response is not None:
            send(response)


class MockHttpServer:
    """In-process MCP server on 127.0.0.1.

    mode: "json" | "sse" (Streamable HTTP response styles) or "legacy-sse".
    require_token: if set, requests without `Authorization: Bearer <token>` get 401.
    """

    def __init__(
        self,
        mode: str = "json",
        spec: dict[str, Any] | None = None,
        require_token: str | None = None,
    ) -> None:
        self.mode = mode
        self.spec = spec or {}
        self.require_token = require_token
        self.methods: list[str] = []
        self.session_headers: list[str | None] = []
        # Every POST's headers, so tests can check credentials never reach a host.
        self.received_headers: list[dict[str, str]] = []
        self.deleted = False
        self._legacy_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stop = threading.Event()
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler_class())
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        path = "/sse" if self.mode == "legacy-sse" else "/mcp"
        return f"http://{host!s}:{port}{path}"

    def __enter__(self) -> MockHttpServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._httpd.shutdown()
        self._httpd.server_close()

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                pass

            def _authorized(self) -> bool:
                if server.require_token is None:
                    return True
                if self.headers.get("Authorization") == f"Bearer {server.require_token}":
                    return True
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate",
                    'Bearer resource_metadata="http://127.0.0.1/.well-known/oauth"',
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False

            def _send(self, status: int, body: bytes = b"", ctype: str | None = None) -> None:
                self.send_response(status)
                if ctype:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if server.mode != "legacy-sse" or not self._authorized():
                    if server.mode != "legacy-sse":
                        self._send(405)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                try:
                    endpoint = server.spec.get("endpoint", "/messages?session=abc")
                    self.wfile.write(f"event: endpoint\ndata: {endpoint}\n\n".encode())
                    self.wfile.flush()
                    while not server._stop.is_set():
                        try:
                            msg = server._legacy_queue.get(timeout=0.1)
                        except queue.Empty:
                            continue
                        self.wfile.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
                        self.wfile.flush()
                except OSError:
                    pass  # client disconnected: end the event stream
                self.close_connection = True

            def do_DELETE(self) -> None:
                server.deleted = True
                self._send(200)

            def do_POST(self) -> None:
                server.received_headers.append(dict(self.headers.items()))
                if redirect := server.spec.get("redirect_to"):
                    self.send_response(307)
                    self.send_header("Location", redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if not self._authorized():
                    return
                length = int(self.headers.get("Content-Length", 0))
                message = json.loads(self.rfile.read(length))
                server.methods.append(message.get("method", ""))
                server.session_headers.append(self.headers.get("Mcp-Session-Id"))
                response = handle(server.spec, message)

                if server.mode == "legacy-sse":
                    if response is not None:
                        server._legacy_queue.put(response)
                    self._send(202)
                    return
                if response is None:
                    self._send(202)
                    return
                if message.get("method") != "initialize" and not self.headers.get("Mcp-Session-Id"):
                    self._send(400, b"missing session")
                    return
                if server.mode == "sse":
                    note = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
                    body = (
                        f": keepalive\n\nevent: message\ndata: {json.dumps(note)}\n\n"
                        f"event: message\ndata: {json.dumps(response)}\n\n"
                    ).encode()
                    ctype = "text/event-stream"
                else:
                    padding = " " * int(server.spec.get("body_padding", 0))
                    body, ctype = (json.dumps(response) + padding).encode(), "application/json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                if message.get("method") == "initialize":
                    self.send_header("Mcp-Session-Id", "session-123")
                self.end_headers()
                self.wfile.write(body)

        return Handler


if __name__ == "__main__":
    run_stdio(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))

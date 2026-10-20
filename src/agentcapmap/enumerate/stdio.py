"""stdio transport: launch the server as a subprocess, newline-delimited JSON-RPC."""

from __future__ import annotations

import collections
import contextlib
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import IO, Any

from agentcapmap.enumerate.transport import (
    JSONRPC_METHOD_NOT_FOUND,
    IdCounter,
    RequestTimeout,
    TransportError,
    check_allowed,
    is_response_to,
    unwrap_response,
)
from agentcapmap.redact import get_logger, redact_text

log = get_logger(__name__)

_EOF = object()
_STDERR_TAIL_LINES = 20


class StdioTransport:
    def __init__(
        self,
        command: str,
        args: list[str],
        env: dict[str, str],
        cwd: str | None = None,
    ) -> None:
        full_env = {**os.environ, **env}
        executable = shutil.which(command, path=full_env.get("PATH")) or command
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True
        try:
            self._proc = subprocess.Popen(
                [executable, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=full_env,
                cwd=cwd,
                **kwargs,
            )
        except OSError as exc:
            raise TransportError(f"failed to start {command!r}: {exc.strerror or exc}") from None

        self._ids = IdCounter()
        self._messages: queue.Queue[Any] = queue.Queue()
        self._stderr_tail: collections.deque[str] = collections.deque(maxlen=_STDERR_TAIL_LINES)
        assert self._proc.stdout is not None and self._proc.stderr is not None
        threading.Thread(target=self._read_stdout, args=(self._proc.stdout,), daemon=True).start()
        threading.Thread(target=self._read_stderr, args=(self._proc.stderr,), daemon=True).start()

    def _read_stdout(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                self._messages.put(json.loads(line))
            except json.JSONDecodeError:
                log.debug("ignoring non-JSON stdout line: %s", line[:200])
        self._messages.put(_EOF)

    def _read_stderr(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            line = redact_text(raw.decode("utf-8", errors="replace").rstrip())
            if line:
                self._stderr_tail.append(line)
                log.debug("server stderr: %s", line)

    def _write(self, message: dict[str, Any]) -> None:
        assert self._proc.stdin is not None
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self._proc.stdin.write(data)
            self._proc.stdin.flush()
        except OSError:
            raise self._exited_error() from None

    def _exited_error(self) -> TransportError:
        with contextlib.suppress(subprocess.TimeoutExpired):
            self._proc.wait(timeout=1)
        code = self._proc.returncode
        detail = f"server exited (code {code})" if code is not None else "server closed stdout"
        if self._stderr_tail:
            detail += "; stderr: " + " | ".join(list(self._stderr_tail)[-5:])
        return TransportError(redact_text(detail))

    def _reply_to_server_request(self, message: dict[str, Any]) -> None:
        # Servers may ping or ask for roots/sampling. We answer pings, decline the rest.
        if message.get("method") == "ping":
            self._write({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            self._write(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": JSONRPC_METHOD_NOT_FOUND, "message": "not supported"},
                }
            )

    def request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        check_allowed(method)
        request_id = self._ids.next()
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RequestTimeout(f"{method} timed out after {timeout:.0f}s")
            try:
                message = self._messages.get(timeout=remaining)
            except queue.Empty:
                continue
            if message is _EOF:
                raise self._exited_error()
            if is_response_to(message, request_id):
                return unwrap_response(message)
            if isinstance(message, dict) and "method" in message and "id" in message:
                self._reply_to_server_request(message)
            # Anything else (notifications, stray responses) is ignored.

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        check_allowed(method, notification=True)
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)

    def close(self) -> None:
        # Spec shutdown: close stdin, give the server a moment, then terminate the tree.
        if self._proc.stdin is not None:
            with contextlib.suppress(OSError):
                self._proc.stdin.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self._proc.wait(timeout=2)
        # Always kill the tree: children (e.g. npx -> node) may outlive the parent.
        _kill_tree(self._proc)


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=2)

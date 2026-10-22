"""stdio transport: launch the server as a subprocess, newline-delimited JSON-RPC.

Launching the configured server command is this module's purpose, which is why it
imports `subprocess` (bandit B404). It is reached only through the warned, opt-in
`--enumerate` flag.
"""

from __future__ import annotations

import collections
import contextlib
import json
import os
import queue
import shutil
import signal
import subprocess  # nosec B404
import sys
import threading
import time
from pathlib import Path
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
from agentcapmap.limits import (
    MAX_MESSAGE_BYTES,
    MAX_QUEUED_MESSAGES,
    MAX_STDERR_LINE_CHARS,
    UntrustedJSONError,
    loads_untrusted,
)
from agentcapmap.redact import get_logger, redact_text

log = get_logger(__name__)

_EOF = object()
_OVERLONG = object()
_STDERR_TAIL_LINES = 20

# Only these variables are inherited from our own environment, mirroring the official
# MCP SDK. Everything else (ANTHROPIC_API_KEY, cloud credentials, tokens) stays with us;
# a server gets extra variables only if its config sets them explicitly.
_INHERITED_ENV_WINDOWS = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
)
_INHERITED_ENV_POSIX = frozenset(
    {"HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "SHELL", "TERM", "TMPDIR", "USER"}
)


def default_environment() -> dict[str, str]:
    """The minimal environment a launched server inherits from agent-capmap."""
    allowed = _INHERITED_ENV_WINDOWS if sys.platform == "win32" else _INHERITED_ENV_POSIX
    return {
        key: value
        for key, value in os.environ.items()
        # Skip exported shell functions ("() { ...") as the MCP SDK does.
        if key.upper() in allowed and not value.startswith("()")
    }


def _read_bounded_line(stream: IO[bytes], limit: int) -> bytes | object | None:
    """Next line (None at EOF), or _OVERLONG after discarding a line longer than `limit`."""
    chunk = stream.readline(limit)
    if not chunk:
        return None
    if chunk.endswith(b"\n") or len(chunk) < limit:
        return chunk
    while True:  # discard the rest of the oversized line
        more = stream.readline(limit)
        if not more or more.endswith(b"\n"):
            return _OVERLONG


class StdioTransport:
    def __init__(
        self,
        command: str,
        args: list[str],
        env: dict[str, str],
        cwd: str | None = None,
    ) -> None:
        full_env = {**default_environment(), **env}
        executable = shutil.which(command, path=full_env.get("PATH")) or command
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True
        try:
            # Launching the configured server command is this transport's purpose, and is
            # only reached via the explicit, warned --enumerate opt-in. The command comes
            # from a config the user chose to enumerate; no shell is involved (argv list,
            # shell=False), so arguments cannot be reinterpreted as shell syntax.
            self._proc = subprocess.Popen(  # noqa: S603  # nosec B603
                [executable, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=full_env,
                cwd=cwd,
                shell=False,
                **kwargs,
            )
        except OSError as exc:
            raise TransportError(f"failed to start {command!r}: {exc.strerror or exc}") from None

        if self._proc.stdin is None or self._proc.stdout is None or self._proc.stderr is None:
            _kill_tree(self._proc)
            raise TransportError("failed to open pipes to the server process")
        self._stdin = self._proc.stdin
        self._ids = IdCounter()
        self._messages: queue.Queue[Any] = queue.Queue(maxsize=MAX_QUEUED_MESSAGES)
        self._stderr_tail: collections.deque[str] = collections.deque(maxlen=_STDERR_TAIL_LINES)
        threading.Thread(target=self._read_stdout, args=(self._proc.stdout,), daemon=True).start()
        threading.Thread(target=self._read_stderr, args=(self._proc.stderr,), daemon=True).start()

    def _read_stdout(self, stream: IO[bytes]) -> None:
        try:
            while (raw := _read_bounded_line(stream, MAX_MESSAGE_BYTES)) is not None:
                if not isinstance(raw, bytes):  # _OVERLONG
                    log.debug("dropping stdout line longer than %d bytes", MAX_MESSAGE_BYTES)
                    continue
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    message = loads_untrusted(line)
                except UntrustedJSONError:
                    log.debug("ignoring non-JSON stdout line: %s", line[:200])
                    continue
                self._messages.put(message)
        except (OSError, ValueError):
            pass  # pipe closed underneath us
        finally:
            self._messages.put(_EOF)

    def _read_stderr(self, stream: IO[bytes]) -> None:
        try:
            while (raw := _read_bounded_line(stream, MAX_MESSAGE_BYTES)) is not None:
                if not isinstance(raw, bytes):  # _OVERLONG
                    continue
                text = raw.decode("utf-8", errors="replace").rstrip()[:MAX_STDERR_LINE_CHARS]
                line = redact_text(text)
                if line:
                    self._stderr_tail.append(line)
                    log.debug("server stderr: %s", line)
        except (OSError, ValueError):
            pass  # pipe closed underneath us; stderr is diagnostic only

    def _write(self, message: dict[str, Any]) -> None:
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self._stdin.write(data)
            self._stdin.flush()
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
        with contextlib.suppress(OSError):
            self._stdin.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self._proc.wait(timeout=2)
        # Always kill the tree: children (e.g. npx -> node) may outlive the parent.
        _kill_tree(self._proc)


def _taskkill_path() -> str:
    system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
    return str(Path(system_root) / "System32" / "taskkill.exe")


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    if sys.platform == "win32":
        # Fixed system binary by absolute path; the only variable argument is our own
        # child's integer PID.
        subprocess.run(  # noqa: S603  # nosec B603
            [_taskkill_path(), "/F", "/T", "/PID", str(int(proc.pid))],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
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

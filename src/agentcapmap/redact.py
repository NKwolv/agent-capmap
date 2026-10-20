"""Secret redaction for everything agent-capmap prints or logs.

Config files routinely embed credentials (env values, headers, CLI flags, connection
strings). Nothing derived from a config may reach output or logs without passing
through this module. Redaction is deliberately aggressive: a false positive costs a
little readability, a false negative leaks a credential.
"""

from __future__ import annotations

import logging
import re
import threading
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "<redacted>"

# Shortest value we register as a known secret. Shorter values ("1", "true") would
# scrub unrelated text without protecting anything meaningful.
_MIN_KNOWN_SECRET_LEN = 6

_TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p)
    for p in (
        r"gh[pousr]_[A-Za-z0-9]{20,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"glpat-[A-Za-z0-9_\-]{20,}",
        r"sk-ant-[A-Za-z0-9_\-]{10,}",
        r"sk-[A-Za-z0-9_\-]{20,}",
        r"xox[abposr]-[A-Za-z0-9\-]{10,}",
        r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z_\-]{35}",
        r"npm_[A-Za-z0-9]{36}",
        r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",  # JWT
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    )
]
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=\-]{8,}")
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^/\s:@]+):[^@\s/]+@")
_NAMED_VALUE = re.compile(
    r"(?i)\b([A-Za-z0-9_.\-]*(?:token|secret|passw(?:or)?d|api[_\-]?key|apikey|"
    r"authorization|credential|private[_\-]?key|access[_\-]?key)[A-Za-z0-9_.\-]*)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"
)

_SENSITIVE_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "apikey",
    "api_key",
    "api-key",
    "auth",
    "credential",
    "privatekey",
    "private_key",
    "private-key",
    "accesskey",
    "access_key",
    "access-key",
    "cookie",
    "session",
    "signature",
    "dsn",
)
_SENSITIVE_WORDS = re.compile(r"(?i)(?:^|[_\-.])(?:pat|key|pass|sig|jwt)(?:$|[_\-.])")
_VAR_REFERENCE = re.compile(r"^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^%[A-Za-z_][A-Za-z0-9_]*%$")
_ANY_VAR_REFERENCE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%")


class _KnownSecrets:
    """Raw secret values seen in configs, scrubbed verbatim from any text."""

    def __init__(self) -> None:
        self._values: set[str] = set()
        self._lock = threading.Lock()

    def add(self, value: str) -> None:
        if len(value) >= _MIN_KNOWN_SECRET_LEN and not is_variable_reference(value):
            with self._lock:
                self._values.add(value)

    def scrub(self, text: str) -> str:
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for value in values:
            if value in text:
                text = text.replace(value, REDACTED)
        return text

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


known_secrets = _KnownSecrets()


def is_sensitive_name(name: str) -> bool:
    """Whether a key, header, flag or parameter name likely holds a credential."""
    lowered = name.strip().lstrip("-").lower()
    if not lowered:
        return False
    return any(s in lowered for s in _SENSITIVE_SUBSTRINGS) or bool(
        _SENSITIVE_WORDS.search(lowered)
    )


def is_variable_reference(value: str) -> bool:
    """`${VAR}`, `${env:VAR}`, `${input:id}`, `$VAR` or `%VAR%`: a pointer, not a secret."""
    return bool(_VAR_REFERENCE.match(value.strip()))


def looks_like_secret(value: str) -> bool:
    """High-entropy-looking opaque string (long, mixes letters and digits)."""
    if len(value) < 24 or any(c in value for c in " ./\\"):
        return False
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def redact_text(text: str) -> str:
    """Scrub known secrets and secret-shaped substrings from free text."""
    if not text:
        return text
    text = known_secrets.scrub(text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _URL_USERINFO.sub(lambda m: f"{m.group(1)}:{REDACTED}@", text)
    text = _NAMED_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return text


def redact_value(value: str) -> str:
    """Redact a value whose key is already known (env var, header): keep only references.

    `Bearer ${input:pat}` is kept too: an auth scheme plus a reference holds no secret.
    """
    remainder = _ANY_VAR_REFERENCE.sub("", value).strip().lower()
    if remainder in ("", "bearer", "basic", "token"):
        return value
    return REDACTED


def redact_url(url: str) -> str:
    """Redact userinfo passwords, sensitive query params and opaque path segments."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_text(url)
    if not parts.scheme or not parts.netloc:
        return redact_text(url)

    netloc = parts.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:{REDACTED}@{host}" if ":" in userinfo else f"{REDACTED}@{host}"

    path = "/".join(REDACTED if looks_like_secret(seg) else seg for seg in parts.path.split("/"))
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = urlencode(
        [
            (k, REDACTED if is_sensitive_name(k) or looks_like_secret(v) else v)
            for k, v in query_pairs
        ],
        safe="<>",
    )
    return redact_text(urlunsplit((parts.scheme, netloc, path, query, parts.fragment)))


_FLAG_WITH_VALUE = re.compile(r"^(--?[A-Za-z0-9_.\-]+)=(.*)$", re.DOTALL)
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)


def redact_args(args: list[str]) -> list[str]:
    """Redact a command line: values of sensitive flags, KEY=VALUE pairs, URLs, tokens."""
    out: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            out.append(redact_value(arg))
            redact_next = False
            continue
        if m := _FLAG_WITH_VALUE.match(arg):
            flag, value = m.groups()
            if is_sensitive_name(flag):
                out.append(f"{flag}={redact_value(value)}")
            else:
                out.append(f"{flag}={_redact_free_value(value)}")
            continue
        if arg.startswith("-") and is_sensitive_name(arg):
            out.append(arg)
            redact_next = True
            continue
        if (m := _ASSIGNMENT.match(arg)) and is_sensitive_name(m.group(1)):
            out.append(f"{m.group(1)}={redact_value(m.group(2))}")
            continue
        out.append(_redact_free_value(arg))
    return out


def sensitive_arg_names(args: list[str]) -> list[str]:
    """Names of credential-carrying args, for auth evidence (never values)."""
    names: list[str] = []
    for i, arg in enumerate(args):
        if m := _FLAG_WITH_VALUE.match(arg):
            if is_sensitive_name(m.group(1)):
                names.append(m.group(1))
        elif arg.startswith("-") and is_sensitive_name(arg) and i + 1 < len(args):
            names.append(arg)
        elif (m := _ASSIGNMENT.match(arg)) and is_sensitive_name(m.group(1)):
            names.append(m.group(1))
        elif redact_text(arg) != arg or ("://" in arg and redact_url(arg) != arg):
            names.append(f"arg[{i}]")
    return names


def _redact_free_value(value: str) -> str:
    if "://" in value:
        return redact_url(value)
    return redact_text(value)


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs the fully formatted message before any handler sees it."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = None
        if record.exc_info and record.exc_info[1] is not None:
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


def get_logger(name: str) -> logging.Logger:
    """Logger with redaction attached at the logger level, so every handler is covered."""
    logger = logging.getLogger(name)
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger

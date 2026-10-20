"""On-disk classification cache.

Key: SHA-256 over (tool definition hash, taxonomy version, prompt version, model). Any
change to the tool, the taxonomy, the prompt or the model is a cache miss.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

from pydantic import ValidationError

from agentcapmap.models import ToolClassification
from agentcapmap.redact import get_logger

log = get_logger(__name__)

CACHE_DIR_ENV = "AGENTCAPMAP_CACHE_DIR"


def default_cache_dir() -> Path:
    if env := os.environ.get(CACHE_DIR_ENV):
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "agentcapmap" / "classifications"


def cache_key(definition_hash: str, taxonomy_version: str, prompt_version: str, model: str) -> str:
    material = "\n".join((definition_hash, taxonomy_version, prompt_version, model))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ClassificationCache:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or default_cache_dir()

    def _path(self, key: str) -> Path:
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str) -> ToolClassification | None:
        path = self._path(key)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            log.warning("cannot read cache entry %s: %s", path, exc)
            return None
        try:
            return ToolClassification.model_validate_json(text)
        except ValidationError:
            log.warning("ignoring corrupt cache entry %s", path)
            return None

    def put(self, key: str, classification: ToolClassification) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = classification.model_dump_json(exclude={"from_cache"}, indent=2)
        # Write-then-rename so concurrent scans never read a half-written entry.
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
            Path(tmp).replace(path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

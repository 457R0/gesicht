"""Small JSON-backed state store for a workspace (``.gesicht/state.json``).

Holds things that are cheap to lose and expensive to recompute:
  * ``tool_versions``  - last detected version per external tool
  * ``seen``           - de-dup sets keyed by stream name (subdomains, urls, ...)
  * ``cursors``        - "last processed" markers for incremental re-runs
  * ``last_run``       - ISO timestamp per gesicht subcommand
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class State:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self.path.is_file():
            try:
                self._data = json.loads(self.path.read_text()) or {}
            except json.JSONDecodeError:
                self._data = {"_corrupt": True}
        self._data.setdefault("tool_versions", {})
        self._data.setdefault("seen", {})
        self._data.setdefault("cursors", {})
        self._data.setdefault("last_run", {})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True))
        tmp.replace(self.path)

    # -- typed helpers --------------------------------------------------- #
    def tool_version(self, tool: str, value: str | None = None) -> str | None:
        if value is not None:
            self._data["tool_versions"][tool] = value
        return self._data["tool_versions"].get(tool)

    def mark_run(self, command: str, ts: str) -> None:
        self._data["last_run"][command] = ts

    def last_run(self, command: str) -> str | None:
        return self._data["last_run"].get(command)

    def add_seen(self, stream: str, items: list[str]) -> list[str]:
        """Add ``items`` to a stream's seen-set; return only the ones that are new."""
        bucket = set(self._data["seen"].setdefault(stream, []))
        fresh = [i for i in items if i not in bucket]
        bucket.update(fresh)
        self._data["seen"][stream] = sorted(bucket)
        return fresh

    def cursor(self, key: str, value: str | None = None) -> str | None:
        if value is not None:
            self._data["cursors"][key] = value
        return self._data["cursors"].get(key)

    @property
    def raw(self) -> dict[str, Any]:
        return self._data

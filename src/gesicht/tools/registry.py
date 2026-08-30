"""Adapter registry + binary discovery.

Binary lookup order for a name:
  1. explicit override in the global config's ``tool_paths``
  2. gesicht's managed bin dir (``~/.local/share/gesicht/bin``) - where the auto
     installer drops things
  3. the normal ``$PATH``
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from ..core.config import MANAGED_BIN, load_config
from .base import Availability, ToolAdapter

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def find_binary(name: str, *, tool_paths: dict[str, str] | None = None) -> str | None:
    tool_paths = tool_paths or {}
    override = tool_paths.get(name)
    if override and Path(override).is_file() and os.access(override, os.X_OK):
        return override
    managed = MANAGED_BIN / name
    if managed.is_file() and os.access(managed, os.X_OK):
        return str(managed)
    return shutil.which(name)


def _run_version(path: str, args: list[str]) -> str:
    try:
        p = subprocess.run(
            [path, *args], capture_output=True, text=True, timeout=8
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return f"{p.stdout}\n{p.stderr}".strip()


#: substrings in a version probe that mean the wrapper can't run unattended
_BROKEN_MARKERS = (
    "terminal is required",
    "password is required",
    "sudo:",
    "askpass",
    "permission denied",
)


def probe(path: str) -> tuple[str | None, str]:
    """Return (version, combined_probe_output) trying several version flags."""
    combined = ""
    for args in (["-version"], ["--version"], ["version"], ["-V"]):
        out = _run_version(path, args)
        if not out:
            continue
        combined = out
        m = _VERSION_RE.search(out)
        if m:
            return m.group(1), out
    return None, combined


def detect_version(path: str) -> str | None:
    return probe(path)[0]


def looks_like_pd_httpx(path: str) -> bool:
    """Distinguish ProjectDiscovery httpx from the Python ``httpx`` library CLI.

    pd-httpx prints a version banner to ``-version``; the Python lib prints a
    usage/error message and mentions "Usage: httpx".
    """
    out = _run_version(path, ["-version"]).lower()
    if "projectdiscovery" in out or re.search(r"httpx\s+v?\d+\.\d+", out):
        return True
    if "usage: httpx" in out or "no such option" in out:
        return False
    # last resort: pd-httpx has a -silent flag the lib does not
    help_out = _run_version(path, ["-h"]).lower()
    return "-silent" in help_out and "-title" in help_out


class Registry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        self._cache: dict[str, Availability] = {}

    def register(self, adapter: ToolAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> ToolAdapter | None:
        return self._adapters.get(name)

    def all(self) -> list[ToolAdapter]:
        return list(self._adapters.values())

    def clear_cache(self) -> None:
        self._cache.clear()

    def availability(self, adapter: ToolAdapter, *, refresh: bool = False) -> Availability:
        if not refresh and adapter.name in self._cache:
            return self._cache[adapter.name]

        if adapter.internal:
            av = Availability(adapter.name, path="<internal>", version="builtin", ok=True)
            self._cache[adapter.name] = av
            return av

        tool_paths = load_config().tool_paths
        path: str | None = None
        for cand in adapter.candidate_binaries():
            p = find_binary(cand, tool_paths=tool_paths)
            if not p:
                continue
            ambiguous = adapter.name == "httpx" and cand in {"httpx", "httpx-toolkit"}
            if ambiguous and not looks_like_pd_httpx(p):
                continue
            path = p
            break

        if path is None:
            av = Availability(adapter.name, note="not installed")
        else:
            ver, probe_out = probe(path)
            ok = True
            note = ""
            low = probe_out.lower()
            if ver is None and any(m in low for m in _BROKEN_MARKERS):
                ok = False
                note = "installed but not runnable unattended (needs sudo / a one-time setup)"
            elif adapter.min_version and ver and _cmp_version(ver, adapter.min_version) < 0:
                ok = False
                note = f"found {ver}, need >= {adapter.min_version}"
            av = Availability(adapter.name, path=path, version=ver, ok=ok, note=note)

        self._cache[adapter.name] = av
        return av

    def resolve_runnable(
        self, adapter: ToolAdapter, *, seen: set[str] | None = None
    ) -> tuple[ToolAdapter, Availability, str | None]:
        """Return (adapter_to_run, availability, fallback_for).

        Walks the ``fallbacks`` chain until it finds something available.
        """
        seen = seen or set()
        av = self.availability(adapter)
        if av.ok:
            return adapter, av, None
        seen.add(adapter.name)
        for fb_name in adapter.fallbacks:
            if fb_name in seen:
                continue
            fb = self.get(fb_name)
            if not fb:
                continue
            run_adapter, run_av, _ = self.resolve_runnable(fb, seen=seen)
            if run_av.ok:
                return run_adapter, run_av, adapter.name
        return adapter, av, None


def _cmp_version(a: str, b: str) -> int:
    ta = tuple(int(x) for x in a.split("."))
    tb = tuple(int(x) for x in b.split("."))
    return (ta > tb) - (ta < tb)


#: process-wide registry
registry = Registry()
_loaded = False


def load_builtin_adapters(reg: Registry | None = None) -> Registry:
    """Register every built-in adapter. Idempotent for the module-level registry."""
    global _loaded
    reg = reg or registry
    if reg is registry and _loaded:
        return reg
    from . import adapters as _adapters
    from . import internal as _internal

    _adapters.register_adapters(reg)
    _internal.register_adapters(reg)
    if reg is registry:
        _loaded = True
    return reg

"""Global (user-level) configuration for gesicht.

Lives at ``$XDG_CONFIG_HOME/gesicht/config.yml`` (default ``~/.config/gesicht``).
Per-workspace settings live in ``<workspace>/.gesicht/config.yml`` and override
these; that merge happens in :mod:`gesicht.core.workspace`.

The HackerOne API token is deliberately NOT a config field - it is read from
the ``GESICHT_H1_TOKEN`` environment variable (or the system keyring) only.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


def config_home() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return Path(base).expanduser() if base else Path.home() / ".config"


def data_home() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    return Path(base).expanduser() if base else Path.home() / ".local" / "share"


CONFIG_PATH = config_home() / "gesicht" / "config.yml"
#: gesicht-managed bin dir - auto-installed tools land here so we never touch /usr
MANAGED_BIN = data_home() / "gesicht" / "bin"


@dataclass(slots=True)
class GlobalConfig:
    #: parent dir new workspaces are created in; also where ``gesicht ls`` looks.
    #: resolution order: --base flag > $GESICHT_HOME > this value > ~/gesicht
    workspaces_root: str = ""
    #: slug of the workspace ``gesicht use`` last selected
    current: str | None = None
    #: explicit path overrides for external tools, {tool_name: /abs/path}
    tool_paths: dict[str, str] = field(default_factory=dict)
    #: default politeness knobs, overridable per-workspace and per-invocation
    concurrency: int = 10
    rate_per_host: float = 5.0
    user_agent: str = "gesicht/0.1 (+recon)"
    #: optional HackerOne handle, appended to the UA when set
    h1_handle: str | None = None

    def resolved_workspaces_root(self) -> Path:
        # $GESICHT_HOME wins - an exported env var is a deliberate choice. A stored
        # ``workspaces_root`` is only a default; ~/gesicht is the last resort.
        env = os.environ.get("GESICHT_HOME")
        if env:
            return Path(env).expanduser()
        if self.workspaces_root:
            return Path(self.workspaces_root).expanduser()
        return Path.home() / "gesicht"

    def effective_user_agent(self) -> str:
        if self.h1_handle:
            return f"{self.user_agent} h1:{self.h1_handle}"
        return self.user_agent


def load_config(path: Path | None = None) -> GlobalConfig:
    p = path or CONFIG_PATH
    if not p.is_file():
        return GlobalConfig()
    raw: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
    known = {f for f in GlobalConfig.__slots__}  # type: ignore[attr-defined]
    return GlobalConfig(**{k: v for k, v in raw.items() if k in known})


def save_config(cfg: GlobalConfig, path: Path | None = None) -> Path:
    p = path or CONFIG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(yaml.safe_dump(asdict(cfg), sort_keys=True))
    tmp.replace(p)
    return p

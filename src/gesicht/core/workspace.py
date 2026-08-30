"""Workspace discovery and layout.

A *workspace* is one target directory. ``gesicht init`` builds it in-process:

    <root>/<slug>/
      README.md  scope.md  notes.md
      recon/{subdomains,dns,ports,urls,screenshots}/
      scans/{nuclei,nmap,web}/
      content/  exploits/  loot/  findings/  reports/
      .gesicht/                                  # gesicht state (this module)
        config.yml scope.json state.json index.db violations.log lock runs/

The ``recon/`` and ``scans/`` folders hold immutable raw tool output; ``.gesicht/``
holds the derived index and run log. ``exploits/`` and ``loot/`` are for the
operator's own files - gesicht never writes there.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import yaml

from .config import GlobalConfig, load_config
from .errors import UsageError, WorkspaceNotFoundError
from .ids import slugify

GESICHT_DIR = ".gesicht"

#: relative directories created for each workspace template
TEMPLATES: dict[str, list[str]] = {
    "web": [
        "recon/subdomains", "recon/dns", "recon/ports", "recon/urls",
        "recon/screenshots", "scans/nuclei", "scans/nmap", "scans/web",
        "content", "exploits", "loot", "findings", "reports",
    ],
    "network": [
        "recon/hosts", "recon/ports", "recon/services", "scans/nmap",
        "scans/nuclei", "scans/vuln", "exploits", "loot/creds", "loot/hashes",
        "findings", "reports",
    ],
    "mobile": [
        "app/apk", "app/decompiled", "recon/endpoints", "recon/urls",
        "scans/static", "scans/dynamic", "exploits", "loot", "findings", "reports",
    ],
}


class Workspace:
    """Handle to a single target directory. Cheap to construct; does no IO."""

    def __init__(self, root: Path, config: GlobalConfig | None = None) -> None:
        self.root = root.resolve()
        self.slug = self.root.name
        self._global = config or load_config()

    # -- paths ------------------------------------------------------------- #
    @property
    def gesicht_dir(self) -> Path:
        return self.root / GESICHT_DIR

    @property
    def scope_md(self) -> Path:
        return self.root / "scope.md"

    @property
    def scope_json(self) -> Path:
        return self.gesicht_dir / "scope.json"

    @property
    def state_json(self) -> Path:
        return self.gesicht_dir / "state.json"

    @property
    def index_db(self) -> Path:
        return self.gesicht_dir / "index.db"

    @property
    def violations_log(self) -> Path:
        return self.gesicht_dir / "violations.log"

    @property
    def runs_dir(self) -> Path:
        return self.gesicht_dir / "runs"

    @property
    def notes_md(self) -> Path:
        return self.root / "notes.md"

    @property
    def findings_dir(self) -> Path:
        return self.root / "findings"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    def raw_dir(self, tool: str) -> Path:
        """Where a tool's immutable raw output is written, mapped onto the tree."""
        mapping = {
            "amass": "recon/subdomains", "subfinder": "recon/subdomains",
            "dnsx": "recon/dns", "resolver": "recon/dns",
            "naabu": "recon/ports", "masscan": "recon/ports",
            "katana": "recon/urls", "crawler": "recon/urls", "gau": "recon/urls",
            "wayback": "recon/urls", "httpx": "recon/urls", "prober": "recon/urls",
            "arjun": "recon/urls", "parambrute": "recon/urls",
            "nmap": "scans/nmap",
            "nuclei": "scans/nuclei",
            "whatweb": "scans/web", "wafw00f": "scans/web", "nikto": "scans/web",
            "wpscan": "scans/web", "sqlmap": "scans/web",
            "ffuf": "content", "feroxbuster": "content", "gobuster": "content",
        }
        return self.root / mapping.get(tool, f"scans/{tool}")

    # -- config ---------------------------------------------------------- #
    def config(self) -> GlobalConfig:
        """Global config merged with per-workspace overrides in .gesicht/config.yml."""
        cfg = self._global
        p = self.gesicht_dir / "config.yml"
        if p.is_file():
            over = yaml.safe_load(p.read_text()) or {}
            known = set(GlobalConfig.__slots__)  # type: ignore[attr-defined]
            cfg = replace(cfg, **{k: v for k, v in over.items() if k in known})
        return cfg

    # -- locking ------------------------------------------------------------ #
    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        """Advisory exclusive lock so concurrent ``gesicht`` runs don't corrupt state."""
        self.gesicht_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.gesicht_dir / "lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # -- lifecycle ------------------------------------------------------- #
    def ensure_gesicht_dir(self) -> None:
        d = self.gesicht_dir
        d.mkdir(parents=True, exist_ok=True)
        (d / "runs").mkdir(exist_ok=True)
        gi = d / ".gitignore"
        if not gi.exists():
            gi.write_text("index.db\nlock\nruns/\n")
        vl = self.violations_log
        if not vl.exists():
            vl.touch()

    def exists(self) -> bool:
        return self.gesicht_dir.is_dir()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Workspace {self.slug} at {self.root}>"


# ----------------------------------------------------------------------- #
# creation
# ----------------------------------------------------------------------- #
def _scaffold(target: str, base: Path, template: str) -> Path:
    """Create the workspace folder tree under ``base``. Returns the created root.

    Safe to re-run: missing folders/files are added, nothing is overwritten.
    """
    import datetime as dt

    if template not in TEMPLATES:
        raise UsageError(f"unknown template '{template}' (have: {', '.join(TEMPLATES)})")
    root = (base / slugify(target)).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for d in TEMPLATES[template]:
        (root / d).mkdir(parents=True, exist_ok=True)
        (root / d / ".gitkeep").touch()

    today = dt.date.today().isoformat()
    files = {
        "README.md": f"# {target}\n\n- **Started:** {today}\n- **Type:** {template}\n"
        "- **Platform / program:**\n- **Scope doc:** ./scope.md\n",
        "scope.md": f"# Scope - {target}\n\n## In scope\n\n- \n\n"
        "## Out of scope\n\n- \n\n## Notes\n\n- \n",
        "notes.md": f"# Running notes\n\n<!-- newest at the top -->\n\n## {today}\n\n"
        "- kicked off recon\n",
    }
    for name, content in files.items():
        fp = root / name
        if not fp.exists():
            fp.write_text(content)
    return root


def create(
    target: str,
    *,
    base: Path | None = None,
    template: str = "web",
    config: GlobalConfig | None = None,
) -> Workspace:
    """Scaffold (or top up) a workspace for ``target`` and attach ``.gesicht/``."""
    cfg = config or load_config()
    base = (base or cfg.resolved_workspaces_root()).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    root = _scaffold(target, base, template)
    ws = Workspace(root, cfg)
    ws.ensure_gesicht_dir()
    return ws


# ----------------------------------------------------------------------- #
# discovery
# ----------------------------------------------------------------------- #
def _walk_up_for_gesicht(start: Path) -> Path | None:
    cur = start.resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / GESICHT_DIR).is_dir():
            return candidate
    return None


def discover(
    *,
    explicit: str | Path | None = None,
    cwd: Path | None = None,
    config: GlobalConfig | None = None,
) -> Workspace:
    """Resolve the active workspace.

    Precedence: explicit path/flag > ``$GESICHT_WORKSPACE`` > walk up from cwd for a
    ``.gesicht/`` dir > ``current:`` pointer in the global config.
    """
    cfg = config or load_config()
    cwd = (cwd or Path.cwd()).resolve()

    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_dir():
            raise WorkspaceNotFoundError(f"no such directory: {p}")
        return Workspace(p, cfg)

    env = os.environ.get("GESICHT_WORKSPACE")
    if env:
        p = Path(env).expanduser().resolve()
        if not p.is_dir():
            raise WorkspaceNotFoundError(f"GESICHT_WORKSPACE points at a missing dir: {p}")
        return Workspace(p, cfg)

    found = _walk_up_for_gesicht(cwd)
    if found:
        return Workspace(found, cfg)

    if cfg.current:
        p = cfg.resolved_workspaces_root() / cfg.current
        if (p / GESICHT_DIR).is_dir():
            return Workspace(p, cfg)

    raise WorkspaceNotFoundError(
        "no workspace found. Run `gesicht init <target>` or `cd` into a target "
        "directory, or select one with `gesicht use <slug>`."
    )


def list_workspaces(config: GlobalConfig | None = None) -> list[Workspace]:
    """All initialised workspaces under the configured root."""
    cfg = config or load_config()
    root = cfg.resolved_workspaces_root()
    if not root.is_dir():
        return []
    out = [
        Workspace(child, cfg)
        for child in sorted(root.iterdir())
        if child.is_dir() and (child / GESICHT_DIR).is_dir()
    ]
    return out

"""The adapter contract every external tool (and internal fallback) implements."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.models import Activity

if TYPE_CHECKING:
    from ..core.workspace import Workspace


@dataclass(slots=True)
class InstallSpec:
    """How to obtain a tool that is missing. Tried in this order: apt, pipx, go."""

    apt: str | None = None
    pipx: str | None = None
    go: str | None = None  # e.g. "github.com/projectdiscovery/katana/cmd/katana@latest"
    binary: str | None = None  # resulting binary name, if different from the adapter name
    note: str | None = None

    def methods(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if self.apt:
            out.append(("apt", self.apt))
        if self.pipx:
            out.append(("pipx", self.pipx))
        if self.go:
            out.append(("go", self.go))
        return out


@dataclass(slots=True)
class Availability:
    name: str
    path: str | None = None
    version: str | None = None
    ok: bool = False
    note: str = ""

    @property
    def installed(self) -> bool:
        return self.path is not None


@dataclass(slots=True)
class Task:
    """One unit of work handed to an adapter."""

    targets: list[str]
    workspace: Workspace
    outdir: Path
    extra_args: list[str] = field(default_factory=list)
    rate: float | None = None
    timeout: float | None = None
    options: dict[str, Any] = field(default_factory=dict)

    def opt(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    def artifact(self, name: str) -> Path:
        """A side-output file path for a tool that writes its own ``-o`` file."""
        self.outdir.mkdir(parents=True, exist_ok=True)
        return self.outdir / name


class ToolAdapter:
    #: canonical adapter name (also the default binary name and CLI keyword)
    name: str = ""
    #: candidate executables in priority order
    binaries: tuple[str, ...] = ()
    #: recon | portscan | content | vuln | fingerprint | crawl | params | dns
    category: str = "recon"
    #: passive = no packets to the target's infrastructure
    activity: Activity = Activity.PASSIVE
    install: InstallSpec | None = None
    #: extra one-time setup a user must do by hand (e.g. download a data pack)
    setup_hint: str | None = None
    min_version: str | None = None
    #: adapter names to try, in order, when this tool is unavailable
    fallbacks: tuple[str, ...] = ()
    #: an internal (pure-Python) implementation never needs installing
    internal: bool = False
    #: unusually intrusive (exploitation payloads) - the CLI double-confirms
    extra_confirm: bool = False

    def candidate_binaries(self) -> tuple[str, ...]:
        return self.binaries or (self.name,)

    # -- process adapters implement these two --------------------------- #
    def build_command(self, task: Task, binary: str) -> list[str]:
        """Full argv for one run. ``binary`` is the resolved executable path."""
        raise NotImplementedError

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        """Ordered argv list for tools that need more than one invocation.

        Defaults to a single ``build_command``. The orchestrator runs each step
        in order; the last step's stdout is the raw output handed to ``parse``.
        """
        return [self.build_command(task, binary)]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Any]:
        """Yield normalized model instances (Host / Service / Endpoint / Param)."""
        raise NotImplementedError

    # -- internal adapters implement this instead ---------------------- #
    def execute(self, task: Task, raw_path: Path) -> Iterator[Any]:
        """Do the work in-process, write raw output to ``raw_path``, yield records."""
        raise NotImplementedError

    def raw_suffix(self) -> str:
        return "txt"

    def health_check(self, av: Availability) -> list[str]:
        """Return human-readable warnings (missing templates, stale config, ...)."""
        return []

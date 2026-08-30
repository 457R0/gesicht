"""Runs adapters. The one place a ``subprocess`` is launched for a tool.

Every ``run()`` call goes: scope authorize -> (active? confirm) -> resolve
binary or fallback -> build argv -> (dry-run stops here) -> execute -> parse ->
log a ToolRun. There is no path around the scope check.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..core.errors import GesichtError, ToolUnavailable
from ..core.models import Activity, ToolRun
from ..core.store import Store
from ..core.workspace import Workspace
from ..scope.guard import ScopeDecision, ScopeGuard
from .base import Task, ToolAdapter
from .registry import Registry, load_builtin_adapters, registry

ConfirmFn = Callable[[ToolAdapter, Sequence[str]], bool]


class Aborted(GesichtError):
    exit_code = 1


@dataclass(slots=True)
class RunResult:
    adapter: str
    records: list = field(default_factory=list)
    run: ToolRun | None = None
    decisions: list[ScopeDecision] = field(default_factory=list)
    dry_run: bool = False
    fallback_for: str | None = None
    raw_path: Path | None = None
    skipped: str | None = None
    tool_missing: bool = False  # dry-run only: the resolved tool is not installed

    @property
    def argv(self) -> list[str]:
        return self.run.argv if self.run else []


def _deny_all_confirm(_a: ToolAdapter, _t: Sequence[str]) -> bool:
    return False


def install_hint(adapter: ToolAdapter) -> str:
    if adapter.setup_hint:
        return adapter.setup_hint
    if not adapter.install:
        return "no known install method"
    bits = [f"{m}: {pkg}" for m, pkg in adapter.install.methods()]
    joined = "; ".join(bits)
    return f"try `gesicht tools install {adapter.name}` ({joined})" if bits else ""


class Orchestrator:
    def __init__(
        self,
        workspace: Workspace,
        guard: ScopeGuard,
        *,
        dry_run: bool = False,
        assume_active: bool = False,
        confirm: ConfirmFn | None = None,
        reg: Registry | None = None,
    ) -> None:
        self.ws = workspace
        self.guard = guard
        self.dry_run = dry_run
        self.assume_active = assume_active
        self._confirm = confirm or _deny_all_confirm
        self.reg = reg or load_builtin_adapters(registry)
        self.store = Store(workspace)

    # ------------------------------------------------------------------ #
    def run(
        self,
        adapter_name: str,
        targets: Sequence[str],
        *,
        options: dict | None = None,
        extra_args: list[str] | None = None,
        rate: float | None = None,
        timeout: float | None = None,
    ) -> RunResult:
        adapter = self.reg.get(adapter_name)
        if adapter is None:
            raise ToolUnavailable(adapter_name, "unknown adapter")

        run_adapter, av, fallback_for = self.reg.resolve_runnable(adapter)
        # A dry run shows what *would* happen, so a missing tool is not fatal
        # there - the plan (and the scope decision) still matter.
        if not av.ok and not self.dry_run:
            raise ToolUnavailable(adapter.name, install_hint(adapter))

        activity = run_adapter.activity
        targets = list(targets)

        # -- SCOPE HOOK: mandatory, before any network activity ------------ #
        if self.dry_run:
            # show every decision; the caller exits non-zero if any are OUT,
            # but a dry run is not an "attempt" so nothing is logged or raised,
            # and we don't do DNS lookups for a plan preview.
            decisions = self.guard.check(targets, activity, resolve=False)
        else:
            decisions = self.guard.authorize(
                targets,
                activity,
                violations_log=self.ws.violations_log,
                actor=f"gesicht/{run_adapter.name}",
            )

        if activity == Activity.ACTIVE and not self.assume_active and not self.dry_run:
            if not self._confirm(run_adapter, targets):
                return RunResult(run_adapter.name, decisions=decisions, skipped="user declined")

        outdir = self.ws.raw_dir(run_adapter.name)
        outdir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        raw_path = outdir / f"{stamp}__{run_adapter.name}.{run_adapter.raw_suffix()}"

        task = Task(
            targets=targets,
            workspace=self.ws,
            outdir=outdir,
            extra_args=extra_args or [],
            rate=rate,
            timeout=timeout,
            options=options or {},
        )

        if run_adapter.internal:
            steps: list[list[str]] = [[f"<internal:{run_adapter.name}>"]]
        else:
            steps = run_adapter.build_steps(task, av.path or run_adapter.name)

        run = ToolRun(
            tool=run_adapter.name,
            argv=(steps[0] if len(steps) == 1 else [c for s in steps for c in [*s, "&&"]][:-1]),
            targets=targets,
            activity=activity,
            version=av.version,
            fallback_for=fallback_for,
            scope_decision="; ".join(d.rule_str() for d in decisions),
        )

        if self.dry_run:
            return RunResult(
                run_adapter.name,
                run=run,
                decisions=decisions,
                dry_run=True,
                fallback_for=fallback_for,
                raw_path=raw_path,
                tool_missing=not av.ok,
            )

        records: list = []
        exit_code = 0
        try:
            if run_adapter.internal:
                records = list(run_adapter.execute(task, raw_path))
            else:
                stdout_acc: list[str] = []
                stderr_acc: list[str] = []
                for i, step in enumerate(steps):
                    proc = subprocess.run(  # noqa: S603 - argv is built by the adapter
                        step, capture_output=True, text=True, timeout=timeout
                    )
                    stdout_acc.append(proc.stdout or "")
                    stderr_acc.append(proc.stderr or "")
                    exit_code = proc.returncode
                    if exit_code != 0 and i < len(steps) - 1:
                        break  # a prep step failed; don't run the rest
                raw_path.write_text(stdout_acc[-1] if stdout_acc else "")
                joined_err = "".join(stderr_acc).strip()
                if joined_err:
                    raw_path.with_suffix(raw_path.suffix + ".stderr").write_text(joined_err)
                records = list(run_adapter.parse(raw_path, task))
        except subprocess.TimeoutExpired:
            exit_code = 124
        except FileNotFoundError as e:
            raise ToolUnavailable(run_adapter.name, str(e)) from e

        run.ended_at = datetime.now(UTC).isoformat(timespec="seconds")
        run.exit_code = exit_code
        run.raw_stdout_path = str(raw_path)
        run.records_emitted = len(records)
        with self.ws.lock():
            self.store.record_run(run)

        return RunResult(
            run_adapter.name,
            records=records,
            run=run,
            decisions=decisions,
            fallback_for=fallback_for,
            raw_path=raw_path,
        )

"""Runs adapters. The one place a ``subprocess`` is launched for a tool.

Every ``run()`` call goes: scope authorize -> (active? confirm) -> resolve
binary or fallback -> build argv -> (dry-run stops here) -> execute -> parse ->
log a ToolRun. There is no path around the scope check.
"""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..core.console import err_console
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


def _pump(stream, sink: list[str], *, echo_label: str | None) -> None:
    """Read lines from a child's pipe, accumulate them, and optionally echo live.

    Runs on a background thread so stdout and stderr can both be drained
    concurrently without deadlocking the child (and without buffering the
    whole run silently until the process exits).
    """
    for line in iter(stream.readline, ""):
        sink.append(line)
        if echo_label is not None:
            err_console.print(f"[dim]{echo_label} | {line.rstrip()}[/dim]")
    stream.close()


def _run_streamed(step: list[str], timeout: float | None) -> tuple[str, str, int]:
    """Run one step, streaming its output live, and return (stdout, stderr, exit_code)."""
    proc = subprocess.Popen(  # noqa: S603 - argv is built by the adapter
        step, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
    )
    echo_label = step[0] if err_console.is_terminal else None
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    t_out = threading.Thread(
        target=_pump, args=(proc.stdout, stdout_lines), kwargs={"echo_label": echo_label}
    )
    t_err = threading.Thread(
        target=_pump, args=(proc.stderr, stderr_lines), kwargs={"echo_label": None}
    )
    t_out.start()
    t_err.start()
    try:
        exit_code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        exit_code = 124
    t_out.join()
    t_err.join()
    return "".join(stdout_lines), "".join(stderr_lines), exit_code


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
                    stdout, stderr, exit_code = _run_streamed(step, timeout)
                    stdout_acc.append(stdout)
                    stderr_acc.append(stderr)
                    if exit_code != 0 and i < len(steps) - 1:
                        break  # a prep step failed; don't run the rest
                raw_path.write_text(stdout_acc[-1] if stdout_acc else "")
                joined_err = "".join(stderr_acc).strip()
                if joined_err:
                    raw_path.with_suffix(raw_path.suffix + ".stderr").write_text(joined_err)
                records = list(run_adapter.parse(raw_path, task))
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

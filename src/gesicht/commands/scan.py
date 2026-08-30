"""``gesicht scan`` - vulnerability scanning (nuclei, nikto, wpscan, sqlmap)."""

from __future__ import annotations

import json

import typer
from rich.table import Table

from ..core import workspace as ws_mod
from ..core.console import console, ok, warn
from ..core.errors import UsageError
from ..core.findings import FindingStore
from ..core.models import VulnHit, severity_rank
from ..core.store import Store
from ..scope import scope_md
from ..scope.guard import ScopeGuard
from ..tools.orchestrator import Orchestrator, RunResult
from .finding import draft_hits
from .recon import _default_domains, _from_store

app = typer.Typer(help="Vulnerability scanning.", no_args_is_help=True)

_W = typer.Option(None, "--workspace", "-w")
_DRY = typer.Option(False, "--dry-run")
_YES = typer.Option(False, "--yes-active", help="Skip the confirmation for ACTIVE tools.")
_JSON = typer.Option(False, "--json")
_RATE = typer.Option(None, "--rate")
_MINSEV = typer.Option("medium", "--min-severity", help="Auto-draft findings at/above this.")
_NODRAFT = typer.Option(False, "--no-draft", help="Store hits but don't draft findings.")


def _confirm(adapter, targets) -> bool:  # noqa: ANN001
    preview = ", ".join(list(targets)[:3]) + (" ..." if len(targets) > 3 else "")
    if getattr(adapter, "extra_confirm", False):
        console.print(
            f"[red bold]{adapter.name}[/red bold] sends intrusive / exploitation payloads "
            f"to [bold]{preview}[/bold]. Only run this with explicit program permission."
        )
        if not typer.confirm(f"Type-confirm: really run {adapter.name}?"):
            return False
    return typer.confirm(f"Run ACTIVE {adapter.name} against {len(targets)} target(s) [{preview}]?")


def _setup(workspace, dry_run, yes_active):
    ws = ws_mod.discover(explicit=workspace)
    scope = scope_md.load(ws.scope_md)
    guard = ScopeGuard(scope)
    orch = Orchestrator(ws, guard, dry_run=dry_run, assume_active=yes_active, confirm=_confirm)
    return ws, scope, orch


def _targets_for_scan(ws, scope, given: list[str] | None) -> list[str]:
    if given:
        return given
    return _from_store(ws, "urls") or _from_store(ws, "hosts") or _default_domains(scope)


def _emit(ws, result: RunResult, *, as_json: bool, min_severity: str, draft: bool) -> None:
    if result.skipped:
        warn(f"skipped: {result.skipped}")
        raise typer.Exit(code=1)
    if result.dry_run:
        head = result.adapter + (
            f" (fallback for {result.fallback_for})" if result.fallback_for else ""
        )
        console.print(f"[bold]{head}[/bold]\n  argv: " + " ".join(result.argv))
        for d in result.decisions:
            mark = "[green]IN [/green]" if d.allowed else "[red]OUT[/red]"
            console.print(f"  {mark} {d.target}  [dim]{d.reason}[/dim]")
        if any(not d.allowed for d in result.decisions):
            raise typer.Exit(code=2)
        return

    hits: list[VulnHit] = [r for r in result.records if isinstance(r, VulnHit)]
    with ws.lock():
        Store(ws).add_records(hits)

    drafted = []
    if draft and hits:
        store = FindingStore(ws)
        with ws.lock():
            drafted = draft_hits(ws, store, hits, min_severity=min_severity)

    if as_json:
        console.print_json(json.dumps({
            "adapter": result.adapter,
            "fallback_for": result.fallback_for,
            "hits": len(hits),
            "drafted": [f.fid for f in drafted],
        }))
        return

    _print_hits(result.adapter, result.fallback_for, hits)
    if drafted:
        ok(f"drafted {len(drafted)} finding(s): " + ", ".join(f.fid for f in drafted))
        console.print("[dim]curate: `gesicht finding show <id>` / `finding edit <id>`[/dim]")
    elif hits and draft:
        console.print(f"[dim]no hits at/above '{min_severity}' - nothing drafted[/dim]")


def _print_hits(adapter: str, fallback_for: str | None, hits: list[VulnHit]) -> None:
    label = adapter + (f" (fallback for {fallback_for})" if fallback_for else "")
    if not hits:
        warn(f"{label}: no hits")
        return
    by_sev: dict[str, int] = {}
    for h in hits:
        by_sev[h.severity] = by_sev.get(h.severity, 0) + 1
    order = sorted(by_sev, key=severity_rank, reverse=True)
    ok(f"{label}: {len(hits)} hit(s) — " + ", ".join(f"{by_sev[s]} {s}" for s in order))
    t = Table(box=None)
    t.add_column("sev")
    t.add_column("name")
    t.add_column("where", style="dim")
    for h in sorted(hits, key=lambda x: severity_rank(x.severity), reverse=True)[:25]:
        t.add_row(h.severity, h.name[:70], h.url or h.host)
    console.print(t)


# --------------------------------------------------------------------------- #
@app.command()
def nuclei(
    targets: list[str] = typer.Argument(None, help="URLs/hosts (default: parsed/urls.txt)."),
    severity: str = typer.Option(None, "--severity", help="e.g. low,medium,high,critical"),
    tags: str = typer.Option(None, "--tags"),
    templates: str = typer.Option(None, "--templates", "-t"),
    min_severity: str = _MINSEV, no_draft: bool = _NODRAFT,
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES,
    rate: float = _RATE, as_json: bool = _JSON,
) -> None:
    """Run nuclei and auto-draft findings from the hits."""
    ws, scope, orch = _setup(workspace, dry_run, yes_active)
    tg = _targets_for_scan(ws, scope, targets)
    if not tg:
        raise UsageError("no targets and nothing in parsed/{urls,hosts}.txt or scope.md")
    res = orch.run(
        "nuclei", tg,
        options={"severity": severity, "tags": tags, "templates": templates},
        rate=rate,
    )
    _emit(ws, res, as_json=as_json, min_severity=min_severity, draft=not no_draft)


@app.command()
def web(
    targets: list[str] = typer.Argument(None, help="URLs/hosts (default: parsed/urls.txt)."),
    min_severity: str = _MINSEV, no_draft: bool = _NODRAFT,
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES, as_json: bool = _JSON,
) -> None:
    """Web server misconfig scan (nikto)."""
    ws, scope, orch = _setup(workspace, dry_run, yes_active)
    tg = _targets_for_scan(ws, scope, targets)
    if not tg:
        raise UsageError("no targets and nothing to scan")
    _emit(ws, orch.run("nikto", tg), as_json=as_json, min_severity=min_severity,
          draft=not no_draft)


@app.command()
def wp(
    targets: list[str] = typer.Argument(..., help="WordPress site URLs."),
    min_severity: str = _MINSEV, no_draft: bool = _NODRAFT,
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES, as_json: bool = _JSON,
) -> None:
    """WordPress scan (wpscan; set WPSCAN_API_TOKEN for vuln data)."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    _emit(ws, orch.run("wpscan", targets), as_json=as_json, min_severity=min_severity,
          draft=not no_draft)


@app.command()
def sqli(
    urls: list[str] = typer.Argument(..., help="URL(s) with a parameter to test."),
    data: str = typer.Option(None, "--data", help="POST body to test."),
    level: int = typer.Option(1, "--level", min=1, max=5),
    risk: int = typer.Option(1, "--risk", min=1, max=3),
    exploit: bool = typer.Option(
        False, "--exploit", help="Also enumerate DBs/user (data extraction). Needs permission."
    ),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES, as_json: bool = _JSON,
) -> None:
    """SQL injection test (sqlmap). Intrusive - double-confirmed."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    if exploit and not dry_run:
        console.print("[red bold]--exploit[/red bold] will extract data from the database.")
        if not (yes_active or typer.confirm("You have explicit permission to do this?")):
            raise typer.Exit(code=1)
    res = orch.run(
        "sqlmap", urls,
        options={"data": data, "level": level, "risk": risk, "exploit": exploit},
    )
    _emit(ws, res, as_json=as_json, min_severity="low", draft=True)

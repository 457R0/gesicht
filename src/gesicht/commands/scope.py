"""``gesicht scope`` - manage and check the in/out-of-scope rule set."""

from __future__ import annotations

import json
import sys

import typer
from rich.table import Table

from ..core import workspace as ws_mod
from ..core.console import console, ok, warn
from ..core.errors import UsageError
from ..core.models import Activity, ScopeEntry, ScopeType
from ..scope import h1_import, scope_md
from ..scope.guard import ScopeGuard
from ..scope.lint import lint as run_lint
from ..scope.lint import worst_level
from ..scope.model import ScopeSet

app = typer.Typer(help="Manage and check the in/out-of-scope rule set.", no_args_is_help=True)


def _load(workspace: str | None) -> tuple[ws_mod.Workspace, ScopeSet]:
    ws = ws_mod.discover(explicit=workspace)
    return ws, scope_md.load(ws.scope_md)


def _sync_cache(ws: ws_mod.Workspace, scope: ScopeSet) -> None:
    scope.program = scope.program or ws.slug
    scope.write_cache(ws.scope_json)


@app.command("list")
def list_(
    workspace: str = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show the current rules."""
    ws, scope = _load(workspace)
    _sync_cache(ws, scope)
    if as_json:
        console.print_json(scope.to_json())
        return
    if not scope.entries:
        warn("no scope rules yet - `gesicht scope add` or `gesicht scope import`")
        return
    for bucket, title in ((scope.allow, "in scope"), (scope.deny, "out of scope")):
        if not bucket:
            continue
        t = Table(title=title, title_justify="left", box=None)
        t.add_column("type", style="cyan")
        t.add_column("value")
        t.add_column("bounty", justify="center")
        t.add_column("max sev")
        t.add_column("note", style="dim")
        for e in bucket:
            t.add_row(
                e.type,
                e.value,
                "-" if not e.in_scope else ("✓" if e.bounty else "·"),
                e.max_severity or "",
                e.note or "",
            )
        console.print(t)


@app.command()
def add(
    value: str = typer.Argument(..., help="Domain, *.wildcard, URL, IP or CIDR."),
    out: bool = typer.Option(False, "--out", help="Add to the OUT-of-scope list."),
    type_: str = typer.Option(None, "--type", "-t", help="Force scope type."),
    no_bounty: bool = typer.Option(False, "--no-bounty"),
    max_severity: str = typer.Option(None, "--max", help="Max severity, e.g. critical."),
    note: str = typer.Option(None, "--note"),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Add one rule to scope.md."""
    ws = ws_mod.discover(explicit=workspace)
    stype = ScopeType(type_) if type_ else scope_md.infer_type(value)
    entry = ScopeEntry(
        type=stype,
        value=value.rstrip("/") if stype != ScopeType.URL else value,
        in_scope=not out,
        bounty=not no_bounty and not out,
        max_severity=max_severity,
        note=note,
        source="manual",
    )
    with ws.lock():
        merged = scope_md.upsert_into_file(ws.scope_md, [entry], title=ws.slug)
        _sync_cache(ws, merged)
    ok(f"added {'out-of-scope' if out else 'in-scope'} {entry.type}:{entry.value}")
    _lint_and_warn(merged)


@app.command()
def rm(
    value: str = typer.Argument(...),
    out: bool = typer.Option(False, "--out", help="Remove from the OUT-of-scope list."),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Remove rules matching a value."""
    ws, scope = _load(workspace)
    n = scope.remove(value, in_scope=None if not out else False)
    if not n and out is False:
        n = scope.remove(value)
    with ws.lock():
        ws.scope_md.write_text(scope_md.render(scope, title=ws.slug))
        _sync_cache(ws, scope)
    (ok if n else warn)(f"removed {n} rule(s) for {value}")


@app.command()
def check(
    targets: list[str] = typer.Argument(..., help="Hosts, URLs or IPs to test."),
    active: bool = typer.Option(False, "--active", help="Evaluate as an ACTIVE action."),
    as_json: bool = typer.Option(False, "--json"),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Explain whether each target is in scope, and via which rule."""
    ws, scope = _load(workspace)
    guard = ScopeGuard(scope)
    activity = Activity.ACTIVE if active else Activity.PASSIVE
    decisions = guard.check(targets, activity)

    if as_json:
        console.print_json(
            json.dumps(
                [
                    {
                        "target": d.target,
                        "allowed": d.allowed,
                        "reason": d.reason,
                        "rule": d.rule_str(),
                        "requires_confirmation": d.requires_confirmation,
                        "resolved_ips": d.resolved_ips,
                    }
                    for d in decisions
                ]
            )
        )
    else:
        width = max((len(d.target) for d in decisions), default=0)
        for d in decisions:
            mark = "[green]IN [/green]" if d.allowed else "[red]OUT[/red]"
            extra = " [yellow](needs --yes-active)[/yellow]" if d.requires_confirmation else ""
            console.print(f"{mark}  {d.target:<{width}}  [dim]-[/dim] {d.reason}{extra}")

    if any(not d.allowed for d in decisions):
        raise typer.Exit(code=2)


@app.command()
def lint(
    workspace: str = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Flag dangerous or useless rules."""
    ws, scope = _load(workspace)
    issues = run_lint(scope)
    if as_json:
        console.print_json(
            json.dumps([{"level": i.level, "message": i.message, "rule": (
                f"{i.entry.type}:{i.entry.value}" if i.entry else None)} for i in issues])
        )
    else:
        if not issues:
            ok("scope looks clean")
        for i in issues:
            colour = {"error": "red", "warn": "yellow", "info": "cyan"}[i.level]
            console.print(f"[{colour}]{i}[/{colour}]")
    if worst_level(issues) == "error":
        raise typer.Exit(code=1)


@app.command("import")
def import_(
    file: str = typer.Option(None, "--file", "-f", help="Path to a JSON or text scope export."),
    stdin: bool = typer.Option(False, "--stdin", help="Read the export from stdin."),
    h1: str = typer.Option(None, "--h1", help="HackerOne program handle (needs GESICHT_H1_TOKEN)."),
    paste: bool = typer.Option(False, "--paste", help="Force best-effort text parsing."),
    out: bool = typer.Option(False, "--out", help="Treat pasted entries as out-of-scope."),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Merge scope from a HackerOne export into scope.md."""
    ws = ws_mod.discover(explicit=workspace)
    sources = [bool(file), stdin, bool(h1)]
    if sum(sources) != 1:
        raise UsageError("choose exactly one of --file, --stdin, --h1")

    if h1:
        from ..scope._h1_api import fetch_structured_scopes

        text = fetch_structured_scopes(h1)
        imported = h1_import.from_structured_json(text, handle=h1)
    else:
        text = sys.stdin.read() if stdin else _read_file(file)
        if not paste and text.lstrip()[:1] in "[{":
            imported = h1_import.from_structured_json(text, handle=ws.slug)
        else:
            imported = h1_import.from_pasted_text(text, handle=ws.slug, in_scope=not out)

    if not imported.entries:
        warn("nothing parsed from that input")
        raise typer.Exit(code=1)

    with ws.lock():
        merged = scope_md.upsert_into_file(ws.scope_md, imported.entries, title=ws.slug)
        merged.imported_from = imported.imported_from
        merged.imported_at = imported.imported_at
        _sync_cache(ws, merged)

    n_in = sum(e.in_scope for e in imported.entries)
    n_out = len(imported.entries) - n_in
    ok(f"imported {len(imported.entries)} rule(s): {n_in} in scope, {n_out} out of scope")
    _lint_and_warn(merged)


def _read_file(path: str) -> str:
    from pathlib import Path

    p = Path(path).expanduser()
    if not p.is_file():
        raise UsageError(f"no such file: {p}")
    return p.read_text()


def _lint_and_warn(scope: ScopeSet) -> None:
    issues = run_lint(scope)
    errs = [i for i in issues if i.level == "error"]
    for i in errs:
        console.print(f"[red]{i}[/red]")
    if errs:
        warn("scope has errors - run `gesicht scope lint` and fix before scanning")

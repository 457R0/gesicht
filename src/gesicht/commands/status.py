"""``gesicht status`` - one-screen summary of the active workspace."""

from __future__ import annotations

import json

import typer
from rich.panel import Panel
from rich.table import Table

from ..core import workspace as ws_mod
from ..core.console import console
from ..core.state import State
from ..core.store import Store

app = typer.Typer()


@app.callback(invoke_without_command=True)
def status(
    ctx: typer.Context,
    workspace: str | None = typer.Option(None, "--workspace", "-w", help="Workspace path."),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    if ctx.invoked_subcommand:
        return
    ws = ws_mod.discover(explicit=workspace)
    store = Store(ws)
    counts = store.summary()
    state = State(ws.state_json)

    scope_txt = ws.scope_md.read_text() if ws.scope_md.is_file() else ""
    in_scope = _count_section(scope_txt, "In scope")
    out_scope = _count_section(scope_txt, "Out of scope")
    violations = (
        sum(1 for _ in ws.violations_log.open()) if ws.violations_log.is_file() else 0
    )

    if as_json:
        console.print_json(
            json.dumps(
                {
                    "workspace": str(ws.root),
                    "slug": ws.slug,
                    "scope": {"in": in_scope, "out": out_scope, "violations": violations},
                    "counts": counts,
                    "last_run": state.raw.get("last_run", {}),
                }
            )
        )
        return

    header = Table.grid(padding=(0, 2))
    header.add_row("[bold]workspace[/bold]", str(ws.root))
    header.add_row("[bold]scope[/bold]", f"{in_scope} in / {out_scope} out")
    if violations:
        header.add_row(
            "[bold red]violations[/bold red]",
            f"{violations} (see .gesicht/violations.log)",
        )

    body = Table(box=None)
    body.add_column("data", style="bold")
    body.add_column("count", justify="right")
    for key in ("hosts", "services", "urls", "params", "vulns", "findings", "runs"):
        body.add_row(key, str(counts.get(key, 0)))

    console.print(Panel(header, title=f"gesicht · {ws.slug}", title_align="left"))
    console.print(body)


def _count_section(md: str, heading: str) -> int:
    """Count non-empty '- ' bullets under a '## <heading>' section of scope.md."""
    lines = md.splitlines()
    n, capture = 0, False
    for line in lines:
        s = line.strip()
        if s.lower().startswith("## "):
            capture = s[3:].strip().lower() == heading.lower()
            continue
        if capture and s.startswith("- ") and s[2:].strip():
            n += 1
    return n

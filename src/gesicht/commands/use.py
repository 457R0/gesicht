"""``gesicht use`` / ``gesicht ls`` - select and list workspaces."""

from __future__ import annotations

import typer
from rich.table import Table

from ..core import workspace as ws_mod
from ..core.config import load_config, save_config
from ..core.console import console, ok
from ..core.errors import UsageError

use_app = typer.Typer(help="Select the active workspace.")
ls_app = typer.Typer(help="List initialised workspaces.")


@use_app.callback(invoke_without_command=True)
def use(
    ctx: typer.Context,
    slug: str = typer.Argument(..., help="Workspace folder name under the workspaces root."),
) -> None:
    if ctx.invoked_subcommand:
        return
    cfg = load_config()
    root = cfg.resolved_workspaces_root() / slug
    if not (root / ws_mod.GESICHT_DIR).is_dir():
        raise UsageError(f"'{slug}' is not an initialised workspace under {root.parent}")
    cfg.current = slug
    save_config(cfg)
    ok(f"active workspace: [bold]{slug}[/bold]  ({root})")


@ls_app.callback(invoke_without_command=True)
def ls(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand:
        return
    cfg = load_config()
    rows = ws_mod.list_workspaces(cfg)
    if not rows:
        console.print(
            f"no workspaces under [dim]{cfg.resolved_workspaces_root()}[/dim] - "
            "create one with `gesicht init <target>`"
        )
        return
    table = Table(box=None, pad_edge=False)
    table.add_column("", width=1)
    table.add_column("slug", style="bold")
    table.add_column("path", style="dim")
    for ws in rows:
        marker = "[green]●[/green]" if ws.slug == cfg.current else " "
        table.add_row(marker, ws.slug, str(ws.root))
    console.print(table)

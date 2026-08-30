"""``gesicht init`` - scaffold (or top up) a target workspace."""

from __future__ import annotations

from pathlib import Path

import typer

from ..core import workspace as ws_mod
from ..core.config import load_config, save_config
from ..core.console import ok, warn

app = typer.Typer(help="Create or update a target workspace.")


@app.callback(invoke_without_command=True)
def init(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target name or domain, e.g. acme.com"),
    base: Path | None = typer.Option(
        None, "--base", "-b", help="Parent dir (default: $GESICHT_HOME / config / ~/gesicht)."
    ),
    template: str = typer.Option(
        "web", "--template", "-t", help="Workspace template: web|network|mobile"
    ),
    use: bool = typer.Option(True, "--use/--no-use", help="Select this workspace afterwards."),
) -> None:
    if ctx.invoked_subcommand:
        return
    cfg = load_config()
    ws = ws_mod.create(target, base=base, template=template, config=cfg)
    ok(f"workspace ready: [bold]{ws.root}[/bold]")
    if not (ws.root / "scope.md").read_text().strip().count("-") > 2:
        warn("scope.md has no scope entries yet - run `gesicht scope import` or edit it.")
    if use:
        cfg.current = ws.slug
        save_config(cfg)
        ok(f"selected workspace [bold]{ws.slug}[/bold]")

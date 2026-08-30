"""``gesicht reindex`` - rebuild .gesicht/index.db from the flat files."""

from __future__ import annotations

import json

import typer

from ..core import workspace as ws_mod
from ..core.console import console, ok
from ..core.store import Store

app = typer.Typer()


@app.callback(invoke_without_command=True)
def reindex(
    ctx: typer.Context,
    workspace: str = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    if ctx.invoked_subcommand:
        return
    ws = ws_mod.discover(explicit=workspace)
    with ws.lock():
        counts = Store(ws).reindex()
    if as_json:
        console.print_json(json.dumps(counts))
    else:
        detail = ", ".join(f"{v} {k}" for k, v in counts.items())
        ok(f"index rebuilt: {detail}" if detail else "index rebuilt (empty)")

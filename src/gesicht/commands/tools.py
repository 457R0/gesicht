"""``gesicht tools`` - list, doctor and install the external toolbox."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer
from rich.table import Table

from ..core.config import MANAGED_BIN
from ..core.console import console, fail, ok, warn
from ..core.errors import UsageError
from ..tools import installer
from ..tools.orchestrator import install_hint
from ..tools.registry import find_binary, load_builtin_adapters, looks_like_pd_httpx, registry

app = typer.Typer(help="List, doctor and install external tools.", no_args_is_help=True)


@app.command("list")
def list_(as_json: bool = typer.Option(False, "--json")) -> None:
    """Show every adapter and whether its tool is available."""
    load_builtin_adapters()
    adapters = sorted(registry.all(), key=lambda a: (a.category, a.name))
    rows = []
    for a in adapters:
        av = registry.availability(a, refresh=True)
        rows.append(
            {
                "name": a.name,
                "category": a.category,
                "activity": a.activity,
                "internal": a.internal,
                "available": av.ok,
                "version": av.version,
                "path": av.path,
                "hint": "" if av.ok else install_hint(a),
            }
        )
    if as_json:
        console.print_json(json.dumps(rows))
        return
    t = Table(box=None)
    t.add_column("tool", style="bold")
    t.add_column("category")
    t.add_column("act")
    t.add_column("status")
    t.add_column("version")
    t.add_column("install hint", style="dim")
    for r in rows:
        status = "[green]ok[/green]" if r["available"] else "[red]missing[/red]"
        if r["internal"]:
            status = "[cyan]builtin[/cyan]"
        t.add_row(
            r["name"], r["category"], "A" if r["activity"] == "active" else "P",
            status, r["version"] or "-", r["hint"],
        )
    console.print(t)


@app.command()
def doctor() -> None:
    """Deeper environment check."""
    load_builtin_adapters()
    grid = Table.grid(padding=(0, 2))

    go = shutil.which("go")
    grid.add_row("go toolchain", f"[green]{go}[/green]" if go else "[yellow]missing[/yellow] "
                 "- `sudo apt install golang-go` (needed only for go-install tools)")
    grid.add_row("managed bin dir", f"{MANAGED_BIN}  "
                 f"({'exists' if MANAGED_BIN.is_dir() else 'not created yet'})")

    seclists = next((p for p in (
        Path("/usr/share/seclists"), Path("/usr/share/wordlists/seclists"),
    ) if p.is_dir()), None)
    grid.add_row("SecLists", str(seclists) if seclists else "[yellow]not found[/yellow]")

    # httpx name collision
    py_httpx = shutil.which("httpx")
    if py_httpx:
        verdict = "ProjectDiscovery httpx" if looks_like_pd_httpx(py_httpx) else \
            "Python httpx library CLI (NOT the recon tool)"
        grid.add_row("httpx on PATH", f"{py_httpx} - {verdict}")
    pd = find_binary("httpx-toolkit")
    grid.add_row("httpx-toolkit", pd or "[yellow]not installed[/yellow] (apt `httpx-toolkit`)")

    nuclei = registry.get("nuclei")
    if nuclei:
        av = registry.availability(nuclei, refresh=True)
        grid.add_row("nuclei", f"{av.path or 'missing'}"
                     + (f"  v{av.version}" if av.version else ""))
    tmpl = next((p for p in (
        Path.home() / ".local/nuclei-templates", Path.home() / "nuclei-templates",
        Path.home() / ".config/nuclei",
    ) if p.exists()), None)
    grid.add_row("nuclei templates", str(tmpl) if tmpl else "[yellow]not found[/yellow] "
                 "- run `nuclei -update-templates`")

    console.print(grid)

    missing = [
        a.name for a in registry.all()
        if not a.internal and not registry.availability(a).ok
    ]
    if missing:
        warn("missing: " + ", ".join(sorted(missing)))
        console.print("[dim]install with `gesicht tools install <name>`[/dim]")
    else:
        ok("all adapters have a usable tool")


@app.command()
def install(
    name: str = typer.Argument(..., help="Adapter name, e.g. subfinder."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't prompt before each method."),
) -> None:
    """Install a missing tool (apt -> pipx -> go)."""
    load_builtin_adapters()
    adapter = registry.get(name)
    if adapter is None:
        raise UsageError(f"unknown adapter '{name}' - see `gesicht tools list`")
    if adapter.internal:
        ok(f"{name} is a built-in - nothing to install")
        return
    if registry.availability(adapter, refresh=True).ok:
        ok(f"{name} is already available")
        return

    def _confirm(tool: str, commands: list[list[str]]) -> bool:
        console.print(f"[bold]{tool}[/bold] - would run:")
        for c in commands:
            console.print(f"  [cyan]$ {' '.join(c)}[/cyan]")
        return True if yes else typer.confirm("proceed with this method?")

    outcome = installer.install(
        name, adapter.install, confirm=_confirm, log=lambda m: console.print(f"[dim]{m}[/dim]")
    )
    registry.clear_cache()
    if outcome.ok:
        ok(f"installed {name} via {outcome.method}")
    else:
        fail(f"could not install {name}: {outcome.message}")
        raise typer.Exit(code=3)

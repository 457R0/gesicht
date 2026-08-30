"""gesicht command-line entry point. Sub-apps are mounted here."""

from __future__ import annotations

import sys

import typer

from . import __version__
from ._banner import print_banner
from .commands import config as config_cmd
from .commands import export as export_cmd
from .commands import finding as finding_cmd
from .commands import init as init_cmd
from .commands import notes as notes_cmd
from .commands import recon as recon_cmd
from .commands import reindex as reindex_cmd
from .commands import report as report_cmd
from .commands import scan as scan_cmd
from .commands import scope as scope_cmd
from .commands import status as status_cmd
from .commands import tools as tools_cmd
from .commands import use as use_cmd
from .commands.query import q as _q_cmd
from .core.console import fail

app = typer.Typer(
    name="gesicht",
    help="Scope-safe recon & vulnerability-scanning orchestrator.",
    no_args_is_help=False,
    add_completion=True,
)


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    """Show the wordmark + help when run with no command."""
    if ctx.invoked_subcommand is None:
        print_banner()
        typer.echo(ctx.get_help())
        raise typer.Exit()

app.add_typer(init_cmd.app, name="init")
app.add_typer(use_cmd.use_app, name="use")
app.add_typer(use_cmd.ls_app, name="ls")
app.add_typer(status_cmd.app, name="status")
app.add_typer(scope_cmd.app, name="scope")
app.add_typer(tools_cmd.app, name="tools")
app.add_typer(recon_cmd.app, name="recon")
app.add_typer(scan_cmd.app, name="scan")
app.add_typer(finding_cmd.app, name="finding")
app.add_typer(report_cmd.app, name="report")
app.add_typer(notes_cmd.app, name="notes")
app.command("q")(_q_cmd)
app.add_typer(export_cmd.app, name="export")
app.add_typer(reindex_cmd.app, name="reindex")
app.add_typer(config_cmd.app, name="config")


@app.command()
def version() -> None:
    """Print the gesicht version."""
    typer.echo(f"gesicht {__version__}")


def main() -> None:
    # GesichtError subclasses click.ClickException, so Click renders them and sets
    # the exit code. This wrapper only catches anything genuinely unexpected.
    try:
        app()
    except Exception as exc:  # noqa: BLE001
        fail(f"unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

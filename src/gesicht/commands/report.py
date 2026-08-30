"""``gesicht report`` - render findings into submittable reports."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from ..core import workspace as ws_mod
from ..core.console import console, ok, warn
from ..core.errors import UsageError
from ..core.findings import FindingStore
from ..core.models import FindingStatus, severity_rank
from ..report.render import available_templates, render_report

app = typer.Typer(help="Render findings into submittable reports.", no_args_is_help=True)

_W = typer.Option(None, "--workspace", "-w")
_TPL = typer.Option("default", "--template", "-t", help="Template; see `gesicht report templates`.")
_NOREDACT = typer.Option(False, "--no-redact", help="Do NOT scrub secrets/PII from evidence.")

# the bundled default template follows the HackerOne report layout; drop your own
# in <workspace>/reports/templates/ to override it.
_ALIASES = {"default": "h1_report.md.j2", "h1": "h1_report.md.j2", "hackerone": "h1_report.md.j2"}


def _tpl_name(name: str) -> str:
    return _ALIASES.get(name, name if name.endswith(".j2") else f"{name}.j2")


def _load(workspace, finding_id):
    ws = ws_mod.discover(explicit=workspace)
    f = FindingStore(ws).get(finding_id)
    if not f:
        raise UsageError(f"no finding matching '{finding_id}'")
    return ws, f


def _redaction_note(fired: list[str]) -> None:
    if fired:
        warn(f"redacted {len(fired)} secret/PII type(s): {', '.join(fired)}")
    else:
        console.print("[dim]no secrets or PII detected[/dim]")


@app.command()
def templates(workspace: str = _W) -> None:
    """List available report templates."""
    ws = ws_mod.discover(explicit=workspace)
    for name in available_templates(ws):
        console.print(f"- {name}")


@app.command()
def preview(
    finding_id: str = typer.Argument(...),
    template: str = _TPL,
    no_redact: bool = _NOREDACT,
    workspace: str = _W,
) -> None:
    """Render a report to stdout without writing a file."""
    ws, f = _load(workspace, finding_id)
    rep = render_report(f, template=_tpl_name(template), workspace=ws, do_redact=not no_redact)
    console.print(rep.text)
    _redaction_note(rep.redacted)


@app.command()
def build(
    finding_id: str = typer.Argument(...),
    template: str = _TPL,
    out: str = typer.Option(None, "--out", "-o", help="Output file (default: under reports/)."),
    no_redact: bool = _NOREDACT,
    workspace: str = _W,
) -> None:
    """Write a report for one finding into reports/."""
    ws, f = _load(workspace, finding_id)
    rep = render_report(f, template=_tpl_name(template), workspace=ws, do_redact=not no_redact)
    dest = Path(out).expanduser() if out else ws.reports_dir / f"{f.fid}-{f.slug}.report.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rep.text)
    ok(f"wrote {dest}")
    _redaction_note(rep.redacted)
    _todo_note(rep.text)


@app.command()
def bundle(
    status: str = typer.Option(None, "--status", "-s", help="Only findings with this status."),
    min_severity: str = typer.Option(None, "--min-severity"),
    template: str = _TPL,
    out: str = typer.Option(None, "--out", "-o", help="Output directory (default: reports/)."),
    no_redact: bool = _NOREDACT,
    workspace: str = _W,
) -> None:
    """Build reports for every matching finding."""
    ws = ws_mod.discover(explicit=workspace)
    items = FindingStore(ws).list()
    if status:
        items = [f for f in items if f.status == FindingStatus(status)]
    if min_severity:
        thr = severity_rank(min_severity)
        items = [f for f in items if severity_rank(f.severity) >= thr]
    if not items:
        warn("no findings match the filter")
        raise typer.Exit(code=1)

    out_dir = Path(out).expanduser() if out else ws.reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    t = Table(box=None)
    t.add_column("id", style="bold")
    t.add_column("file")
    t.add_column("redacted", style="yellow")
    total: set[str] = set()
    for f in items:
        rep = render_report(f, template=_tpl_name(template), workspace=ws, do_redact=not no_redact)
        dest = out_dir / f"{f.fid}-{f.slug}.report.md"
        dest.write_text(rep.text)
        total |= set(rep.redacted)
        t.add_row(f.fid, str(dest), ", ".join(rep.redacted) or "-")
    console.print(t)
    ok(f"built {len(items)} report(s) into {out_dir}")
    if total:
        warn(f"scrubbed across the bundle: {', '.join(sorted(total))}")


def _todo_note(text: str) -> None:
    n = text.count("_TODO")
    if n:
        console.print(
            f"[yellow]{n} TODO placeholder(s) left - fill them in before submitting.[/yellow]"
        )

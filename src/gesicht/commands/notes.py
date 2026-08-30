"""``gesicht notes`` - quick running-log entries in notes.md (hg's format)."""

from __future__ import annotations

import datetime as _dt
import re

import typer

from ..core import workspace as ws_mod
from ..core.console import console, ok, warn

app = typer.Typer(help="Append to and search the running notes.", no_args_is_help=True)
_W = typer.Option(None, "--workspace", "-w")

_HEADER = "# Running notes\n\n<!-- newest at the top -->\n"
_DATE_H = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})\s*$")


@app.command()
def add(
    text: list[str] = typer.Argument(..., help="The note (quote it, or pass words)."),
    tag: list[str] = typer.Option(None, "--tag", "-t", help="Tag(s) to append as #tag."),
    workspace: str = _W,
) -> None:
    """Add a timestamped bullet under today's heading (newest heading on top)."""
    ws = ws_mod.discover(explicit=workspace)
    body = " ".join(text).strip()
    if tag:
        body += " " + " ".join(f"#{t.lstrip('#')}" for t in tag)
    now = _dt.datetime.now()
    today = now.date().isoformat()
    bullet = f"- [{now:%H:%M}] {body}"

    md = ws.notes_md.read_text() if ws.notes_md.is_file() else _HEADER
    lines = md.splitlines()

    # find today's section, or the insert point for a new one
    date_idx = next((i for i, ln in enumerate(lines) if _DATE_H.match(ln) and
                     _DATE_H.match(ln).group(1) == today), None)
    if date_idx is not None:
        # keep the blank line hg leaves between the heading and its bullets
        at = date_idx + 2 if date_idx + 1 < len(lines) and not lines[date_idx + 1].strip() \
            else date_idx + 1
        lines.insert(at, bullet)
    else:
        anchor = next((i for i, ln in enumerate(lines) if "newest at the top" in ln), None)
        if anchor is None:
            anchor = next((i for i, ln in enumerate(lines) if ln.startswith("# ")), -1)
        block = ["", f"## {today}", "", bullet]
        for j, b in enumerate(block):
            lines.insert(anchor + 1 + j, b)

    with ws.lock():
        ws.notes_md.write_text("\n".join(lines).rstrip() + "\n")
    ok(f"noted under {today}")


@app.command()
def show(
    lines_n: int = typer.Option(0, "--lines", "-n", help="Only the first N lines (0 = all)."),
    workspace: str = _W,
) -> None:
    """Print notes.md."""
    ws = ws_mod.discover(explicit=workspace)
    if not ws.notes_md.is_file():
        warn("no notes.md yet")
        return
    text = ws.notes_md.read_text()
    if lines_n:
        text = "\n".join(text.splitlines()[:lines_n])
    console.print(text)


@app.command()
def grep(
    query: str = typer.Argument(...),
    workspace: str = _W,
) -> None:
    """Case-insensitive search over notes.md."""
    ws = ws_mod.discover(explicit=workspace)
    if not ws.notes_md.is_file():
        warn("no notes.md yet")
        return
    q = query.lower()
    section = ""
    hits = 0
    for ln in ws.notes_md.read_text().splitlines():
        if _DATE_H.match(ln):
            section = ln.strip("# ").strip()
        if q in ln.lower() and not ln.startswith("#"):
            hits += 1
            console.print(f"[dim]{section}[/dim]  {ln.strip()}")
    if not hits:
        warn("no matches")

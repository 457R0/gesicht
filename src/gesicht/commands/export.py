"""``gesicht export`` - dump the whole workspace to one JSON file."""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

import typer

from ..core import db as _db
from ..core import workspace as ws_mod
from ..core.console import console, ok
from ..core.findings import FindingStore
from ..core.models import to_dict
from ..scope import scope_md

app = typer.Typer()

_TABLES = ("host", "service", "endpoint", "param", "vuln", "tool_run")


@app.callback(invoke_without_command=True)
def export(
    ctx: typer.Context,
    out: str = typer.Option(None, "--out", "-o", help="Output file (default: under reports/)."),
    stdout: bool = typer.Option(False, "--stdout", help="Write JSON to stdout instead of a file."),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    if ctx.invoked_subcommand:
        return
    ws = ws_mod.discover(explicit=workspace)

    data: dict = {
        "program": ws.slug,
        "exported_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "scope": _scope(ws),
        "findings": [to_dict(f) for f in FindingStore(ws).list()],
    }
    if ws.index_db.exists():
        conn = _db.connect(ws.index_db)
        try:
            for tbl in _TABLES:
                data[tbl] = [dict(r) for r in conn.execute(f"SELECT * FROM {tbl}")]
        finally:
            conn.close()
    else:
        for tbl in _TABLES:
            data[tbl] = []

    blob = json.dumps(data, indent=2, sort_keys=True)
    if stdout:
        console.print_json(blob)
        return
    dest = Path(out).expanduser() if out else (
        ws.reports_dir / f"export-{_dt.date.today().isoformat()}.json"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(blob)
    counts = ", ".join(f"{len(data[t])} {t}" for t in (*_TABLES, "findings") if data.get(t))
    ok(f"wrote {dest}  ({counts or 'empty'})")


def _scope(ws) -> dict:
    if ws.scope_json.is_file():
        return json.loads(ws.scope_json.read_text())
    s = scope_md.load(ws.scope_md)
    return json.loads(s.to_json())

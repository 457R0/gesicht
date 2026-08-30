"""``gesicht q`` - read-only SQL over the derived index (.gesicht/index.db)."""

from __future__ import annotations

import json
import re
import sqlite3

import typer
from rich.table import Table

from ..core import db as _db
from ..core import workspace as ws_mod
from ..core.console import console, warn
from ..core.errors import UsageError

_READ_ONLY = re.compile(r"^\s*(select|with)\b", re.I)
_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|attach|detach|"
    r"pragma|vacuum|reindex|analyze)\b",
    re.I,
)


def q(
    sql: str = typer.Argument(None, help="A SELECT / WITH query."),
    tables: bool = typer.Option(False, "--tables", help="List tables and their columns."),
    limit: int = typer.Option(200, "--limit", help="Row cap if the query has no LIMIT."),
    as_json: bool = typer.Option(False, "--json"),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Run a read-only query against the workspace index."""
    ws = ws_mod.discover(explicit=workspace)
    if not ws.index_db.exists():
        raise UsageError("no index yet - run some recon/scan first, or `gesicht reindex`")
    conn = _db.connect(ws.index_db)
    try:
        if tables:
            _show_schema(conn, as_json)
            return
        if not sql:
            raise UsageError("give a query, or use --tables")
        if _FORBIDDEN.search(sql) or not _READ_ONLY.match(sql):
            raise UsageError("read-only: only SELECT / WITH queries are allowed")
        if " limit " not in sql.lower():
            sql = f"{sql.rstrip().rstrip(';')} LIMIT {int(limit)}"
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error as e:
            raise UsageError(f"SQL error: {e}") from e
        _render(rows, as_json)
    finally:
        conn.close()


def _show_schema(conn: sqlite3.Connection, as_json: bool) -> None:
    tabs = [
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' "
            r"AND name NOT LIKE 'finding\_fts\_%' ESCAPE '\' "
            "ORDER BY name"
        )
    ]
    schema = {t: [c[1] for c in conn.execute(f"PRAGMA table_info({t})")] for t in tabs}
    if as_json:
        console.print_json(json.dumps(schema))
        return
    for t, cols in schema.items():
        console.print(f"[bold cyan]{t}[/bold cyan]  [dim]({', '.join(cols)})[/dim]")


def _render(rows: list[sqlite3.Row], as_json: bool) -> None:
    if not rows:
        warn("no rows")
        return
    cols = rows[0].keys()
    if as_json:
        console.print_json(json.dumps([dict(r) for r in rows]))
        return
    t = Table(box=None)
    for c in cols:
        t.add_column(c)
    for r in rows:
        t.add_row(*["" if r[c] is None else str(r[c]) for c in cols])
    console.print(t)
    console.print(f"[dim]{len(rows)} row(s)[/dim]")

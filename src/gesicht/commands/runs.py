"""``gesicht runs`` - browse, inspect and replay past scan runs.

Reads from the ``tool_run`` table in ``.gesicht/index.db`` and the raw output
files on disk. Zero re-execution — everything here is read-only.

Sub-commands
------------
list      Table of all runs, filterable by tool / target / status.
show      Full detail panel for one run by ID (or short prefix).
raw       Print the raw stdout captured from a run.
results   Re-render the parsed records that came from a specific run.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.columns import Columns
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from ..core import db as _db
from ..core import workspace as ws_mod
from ..core.console import console, warn
from ..core.errors import UsageError

app = typer.Typer(
    help="Browse and inspect past scan/recon runs.",
    no_args_is_help=True,
)

_W   = typer.Option(None,   "--workspace", "-w")
_JSON = typer.Option(False, "--json")

# ── helpers ──────────────────────────────────────────────────────────────────

def _conn(workspace: str | None) -> tuple[sqlite3.Connection, ws_mod.Workspace]:
    ws   = ws_mod.discover(explicit=workspace)
    if not ws.index_db.exists():
        raise UsageError("no index yet — run some recon/scan first, or `gesicht reindex`")
    return _db.connect(ws.index_db), ws


def _resolve_id(conn: sqlite3.Connection, prefix: str) -> str:
    """Resolve a full or prefix run ID. Raises UsageError if ambiguous or missing."""
    rows = conn.execute(
        "SELECT id FROM tool_run WHERE id LIKE ?", (f"{prefix}%",)
    ).fetchall()
    if not rows:
        raise UsageError(f"no run found matching '{prefix}'")
    if len(rows) > 1:
        ids = ", ".join(r["id"][:12] for r in rows)
        raise UsageError(f"ambiguous prefix '{prefix}' — matches: {ids}")
    return rows[0]["id"]


def _duration(started: str | None, ended: str | None) -> str:
    if not started or not ended:
        return "—"
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%S%z"
    try:
        s = datetime.fromisoformat(started)
        e = datetime.fromisoformat(ended)
        secs = int((e - s).total_seconds())
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"
    except Exception:
        return "—"


def _exit_style(code: int | None) -> str:
    if code is None:
        return "[dim]—[/dim]"
    if code == 0:
        return "[green]0 ✓[/green]"
    return f"[red]{code} ✗[/red]"


def _sev_style(sev: str | None) -> str:
    colours = {
        "critical": "red bold", "high": "red", "medium": "yellow",
        "low": "cyan", "info": "dim",
    }
    s = (sev or "").lower()
    c = colours.get(s, "white")
    return f"[{c}]{s or '—'}[/{c}]"


# ── list ──────────────────────────────────────────────────────────────────────

@app.command("list")
def runs_list(
    tool:      Optional[str] = typer.Option(None, "--tool",   "-t", help="Filter by tool name (partial match)."),
    target:    Optional[str] = typer.Option(None, "--target", "-T", help="Filter by target (partial match)."),
    failed:    bool          = typer.Option(False, "--failed", "-f", help="Show only failed runs (exit_code != 0)."),
    limit:     int           = typer.Option(50,   "--limit",  "-n", help="Maximum rows to show."),
    as_json:   bool          = _JSON,
    workspace: Optional[str] = _W,
) -> None:
    """List past scan and recon runs."""
    conn, _ws = _conn(workspace)

    clauses: list[str] = []
    params:  list[str] = []

    if tool:
        clauses.append("tool LIKE ?")
        params.append(f"%{tool}%")
    if target:
        clauses.append("targets LIKE ?")
        params.append(f"%{target}%")
    if failed:
        clauses.append("(exit_code IS NOT NULL AND exit_code != 0)")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, tool, targets, activity, started_at, ended_at,
               exit_code, records_emitted, fallback_for
        FROM tool_run
        {where}
        ORDER BY started_at DESC
        LIMIT {int(limit)}
    """
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    if not rows:
        warn("no runs found")
        return

    if as_json:
        console.print_json(json.dumps([dict(r) for r in rows]))
        return

    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        highlight=True,
        title=f"[bold]Scan / Recon Run History[/bold]  [dim]({len(rows)} shown)[/dim]",
        title_justify="left",
    )
    tbl.add_column("ID",        style="cyan dim",   no_wrap=True, max_width=14)
    tbl.add_column("Tool",      style="bold white",  no_wrap=True)
    tbl.add_column("Targets",   style="white",       max_width=36)
    tbl.add_column("Activity",  style="dim",         no_wrap=True)
    tbl.add_column("Started",   style="dim",         no_wrap=True)
    tbl.add_column("Duration",  style="dim",         no_wrap=True)
    tbl.add_column("Exit",      no_wrap=True)
    tbl.add_column("Records",   justify="right",     style="dim")
    tbl.add_column("Fallback",  style="dim",         no_wrap=True)

    for r in rows:
        targets_preview = ", ".join((r["targets"] or "").split(",")[:3])
        if (r["targets"] or "").count(",") >= 3:
            targets_preview += " …"

        tbl.add_row(
            r["id"][:12],
            r["tool"] or "—",
            targets_preview or "—",
            r["activity"] or "—",
            (r["started_at"] or "")[:16],
            _duration(r["started_at"], r["ended_at"]),
            _exit_style(r["exit_code"]),
            str(r["records_emitted"]) if r["records_emitted"] is not None else "—",
            r["fallback_for"] or "",
        )

    console.print(tbl)
    console.print(
        "[dim]  gesicht runs show <id>     — full detail\n"
        "  gesicht runs raw <id>      — raw captured output\n"
        "  gesicht runs results <id>  — parsed records from this run[/dim]"
    )


# ── show ──────────────────────────────────────────────────────────────────────

@app.command("show")
def runs_show(
    run_id:    str           = typer.Argument(..., help="Run ID or unique prefix."),
    as_json:   bool          = _JSON,
    workspace: Optional[str] = _W,
) -> None:
    """Show full detail for a single run."""
    conn, ws = _conn(workspace)
    rid = _resolve_id(conn, run_id)
    r = conn.execute("SELECT * FROM tool_run WHERE id = ?", (rid,)).fetchone()
    conn.close()

    if as_json:
        console.print_json(json.dumps(dict(r)))
        return

    # Parse argv and targets for display
    argv_str = " ".join(json.loads(r["argv"])) if r["argv"] else "—"
    targets  = (r["targets"] or "").replace(",", "\n")
    raw_path = r["raw_stdout_path"]
    raw_exists = raw_path and Path(raw_path).exists()

    # Summary panel
    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim", no_wrap=True)
    info.add_column()

    def row(label: str, val: str) -> None:
        info.add_row(label, val)

    row("ID",           f"[cyan]{rid}[/cyan]")
    row("Tool",         f"[bold]{r['tool'] or '—'}[/bold]")
    row("Version",      r["version"] or "—")
    row("Activity",     r["activity"] or "—")
    row("Fallback for", r["fallback_for"] or "—")
    row("Started",      r["started_at"] or "—")
    row("Ended",        r["ended_at"] or "—")
    row("Duration",     _duration(r["started_at"], r["ended_at"]))
    row("Exit code",    _exit_style(r["exit_code"]))
    row("Records",      str(r["records_emitted"]) if r["records_emitted"] is not None else "—")
    row("Raw stdout",   (raw_path or "—") + (" [green](exists)[/green]" if raw_exists else " [dim](missing)[/dim]"))
    row("Raw stderr",   r["raw_stderr_path"] or "—")

    console.print(Panel(info, title=f"[bold]Run: {rid[:14]}[/bold]", border_style="cyan"))

    # Command line
    console.print(Panel(
        Syntax(argv_str, "bash", theme="monokai", word_wrap=True),
        title="[bold]Command[/bold]", border_style="dim",
    ))

    # Targets
    if targets.strip():
        console.print(Panel(targets.strip(), title="[bold]Targets[/bold]", border_style="dim"))

    # Scope decisions
    if r["scope_decision"]:
        try:
            decisions = json.loads(r["scope_decision"])
            tbl = Table(box=box.SIMPLE_HEAD, show_edge=False)
            tbl.add_column("Target")
            tbl.add_column("Decision")
            tbl.add_column("Reason", style="dim")
            for d in decisions:
                allowed = d.get("allowed", False)
                tbl.add_row(
                    d.get("target", ""),
                    "[green]IN[/green]" if allowed else "[red]OUT[/red]",
                    d.get("reason", ""),
                )
            console.print(Panel(tbl, title="[bold]Scope Decisions[/bold]", border_style="dim"))
        except Exception:
            pass

    console.print(
        f"[dim]  gesicht runs raw {rid[:12]}      — view captured output\n"
        f"  gesicht runs results {rid[:12]}  — view parsed records[/dim]"
    )


# ── raw ───────────────────────────────────────────────────────────────────────

@app.command("raw")
def runs_raw(
    run_id:    str           = typer.Argument(..., help="Run ID or unique prefix."),
    stderr:    bool          = typer.Option(False, "--stderr", help="Show stderr instead of stdout."),
    head:      Optional[int] = typer.Option(None,  "--head",   help="Show first N lines only."),
    tail:      Optional[int] = typer.Option(None,  "--tail",   help="Show last N lines only."),
    grep:      Optional[str] = typer.Option(None,  "--grep",   help="Filter lines containing this string."),
    workspace: Optional[str] = _W,
) -> None:
    """Print the raw captured output from a run."""
    conn, _ws = _conn(workspace)
    rid  = _resolve_id(conn, run_id)
    r    = conn.execute(
        "SELECT raw_stdout_path, raw_stderr_path, tool FROM tool_run WHERE id = ?", (rid,)
    ).fetchone()
    conn.close()

    path_key = "raw_stderr_path" if stderr else "raw_stdout_path"
    raw_path = r[path_key]

    if not raw_path:
        warn(f"no {'stderr' if stderr else 'stdout'} path recorded for this run")
        raise typer.Exit(1)

    p = Path(raw_path)
    if not p.exists():
        warn(f"raw file missing on disk: {raw_path}")
        raise typer.Exit(1)

    lines = p.read_text(errors="replace").splitlines()

    if grep:
        lines = [l for l in lines if grep.lower() in l.lower()]
    if head:
        lines = lines[:head]
    if tail:
        lines = lines[-tail:]

    label = "stderr" if stderr else "stdout"
    console.print(
        f"[dim]── {r['tool']} / {rid[:14]} / {label} / {len(lines)} lines ──[/dim]"
    )

    # Try to syntax-highlight JSON lines (nuclei output etc)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                parsed = json.loads(stripped)
                console.print_json(json.dumps(parsed))
                continue
            except Exception:
                pass
        console.print(line)


# ── results ───────────────────────────────────────────────────────────────────

@app.command("results")
def runs_results(
    run_id:    str           = typer.Argument(..., help="Run ID or unique prefix."),
    as_json:   bool          = _JSON,
    workspace: Optional[str] = _W,
) -> None:
    """Re-render the parsed records that were emitted from a specific run.

    Queries vuln / host / endpoint / service / param tables filtered by the
    run's tool name and time window. This is a best-effort approximation —
    records are attributed to a run by the ``raw_ref`` field on vulns, or by
    time window for other record types.
    """
    conn, _ws = _conn(workspace)
    rid = _resolve_id(conn, run_id)
    r   = conn.execute(
        "SELECT tool, started_at, ended_at, records_emitted, raw_stdout_path "
        "FROM tool_run WHERE id = ?", (rid,)
    ).fetchone()

    tool = r["tool"] or ""

    # ── vulns (nuclei, nikto, etc.) — attributed directly via raw_ref ──
    vuln_rows = conn.execute(
        "SELECT name, severity, url, host, cwe, description, seen_at "
        "FROM vuln WHERE raw_ref = ?",
        (r["raw_stdout_path"],)
    ).fetchall()

    # ── hosts — attributed by time window ──
    host_rows = []
    if r["started_at"] and r["ended_at"]:
        host_rows = conn.execute(
            "SELECT hostname, ips, in_scope, first_seen "
            "FROM host WHERE first_seen >= ? AND first_seen <= ?",
            (r["started_at"], r["ended_at"])
        ).fetchall()

    # ── endpoints — attributed by time window ──
    url_rows = []
    if r["started_at"] and r["ended_at"]:
        url_rows = conn.execute(
            "SELECT url, status, title, tech "
            "FROM endpoint WHERE sources LIKE ?",
            (f"%{tool}%",)
        ).fetchall()[:200]

    conn.close()

    if as_json:
        out = {
            "run_id": rid,
            "tool": tool,
            "vulns": [dict(v) for v in vuln_rows],
            "hosts": [dict(h) for h in host_rows],
            "endpoints": [dict(u) for u in url_rows],
        }
        console.print_json(json.dumps(out))
        return

    console.print(
        f"\n[bold]Results for run[/bold] [cyan]{rid[:14]}[/cyan]  "
        f"[dim]tool={tool}  records_emitted={r['records_emitted']}[/dim]\n"
    )

    # Vulns
    if vuln_rows:
        tbl = Table(box=box.SIMPLE_HEAD, show_edge=False, title="[bold red]Vulnerabilities[/bold red]")
        tbl.add_column("Severity",    no_wrap=True)
        tbl.add_column("Name",        style="bold")
        tbl.add_column("Target",      style="cyan", max_width=50)
        tbl.add_column("CWE",         style="dim")
        tbl.add_column("Seen",        style="dim", no_wrap=True)
        for v in vuln_rows:
            tbl.add_row(
                _sev_style(v["severity"]),
                v["name"] or "—",
                v["url"] or v["host"] or "—",
                v["cwe"] or "—",
                (v["seen_at"] or "")[:16],
            )
        console.print(tbl)
    else:
        console.print("[dim]  No vulnerability records attributed to this run.[/dim]")

    # Hosts
    if host_rows:
        tbl = Table(box=box.SIMPLE_HEAD, show_edge=False, title="[bold cyan]Hosts Discovered[/bold cyan]")
        tbl.add_column("Hostname",  style="bold")
        tbl.add_column("IPs",       style="dim")
        tbl.add_column("In scope",  no_wrap=True)
        tbl.add_column("First seen", style="dim", no_wrap=True)
        for h in host_rows:
            in_scope = "[green]yes[/green]" if h["in_scope"] else "[red]no[/red]" if h["in_scope"] is not None else "—"
            tbl.add_row(h["hostname"], h["ips"] or "—", in_scope, (h["first_seen"] or "")[:16])
        console.print(tbl)

    # Endpoints
    if url_rows:
        tbl = Table(box=box.SIMPLE_HEAD, show_edge=False, title="[bold]Endpoints[/bold]")
        tbl.add_column("URL",     style="cyan", max_width=60)
        tbl.add_column("Status",  no_wrap=True)
        tbl.add_column("Title",   style="dim", max_width=40)
        tbl.add_column("Tech",    style="dim", max_width=30)
        for u in url_rows:
            status = u["status"]
            sc = "green" if status and 200 <= status < 300 else "yellow" if status and 300 <= status < 400 else "red" if status else "dim"
            tbl.add_row(
                u["url"] or "—",
                f"[{sc}]{status or '—'}[/{sc}]",
                u["title"] or "—",
                u["tech"] or "—",
            )
        console.print(tbl)

    if not vuln_rows and not host_rows and not url_rows:
        console.print(
            "[yellow]  No records could be directly attributed to this run.\n"
            "  Try: gesicht runs raw " + rid[:12] + "  to view the raw captured output.[/yellow]"
        )

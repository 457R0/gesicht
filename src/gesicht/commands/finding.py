"""``gesicht finding`` - create and curate findings (findings/NNNN-slug.md)."""

from __future__ import annotations

import json
import os
import subprocess

import typer
from rich.table import Table

from ..core import workspace as ws_mod
from ..core.console import console, ok, warn
from ..core.errors import UsageError
from ..core.findings import FindingStore, draft_from_vuln, render_finding
from ..core.models import FindingStatus, VulnHit, severity_rank
from ..report.cvss import parse_cvss

app = typer.Typer(help="Create and curate findings.", no_args_is_help=True)
_W = typer.Option(None, "--workspace", "-w")


def _store(workspace) -> tuple[ws_mod.Workspace, FindingStore]:
    ws = ws_mod.discover(explicit=workspace)
    return ws, FindingStore(ws)


_SEV_COLOR = {
    "critical": "red", "high": "bright_red", "medium": "yellow",
    "low": "cyan", "info": "dim",
}


@app.command("ls")
def ls(
    status: str = typer.Option(None, "--status", "-s"),
    severity: str = typer.Option(None, "--severity"),
    workspace: str = _W,
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List findings."""
    _ws, store = _store(workspace)
    items = store.list()
    if status:
        items = [f for f in items if f.status == FindingStatus(status)]
    if severity:
        items = [f for f in items if (f.severity or "") == severity]
    if as_json:
        console.print_json(json.dumps([
            {"id": f.fid, "title": f.title, "severity": f.severity,
             "status": f.status.value, "target": f.target} for f in items
        ]))
        return
    if not items:
        warn("no findings yet - `gesicht finding new` or `gesicht scan nuclei`")
        return
    t = Table(box=None)
    t.add_column("id", style="bold")
    t.add_column("sev")
    t.add_column("status")
    t.add_column("title")
    t.add_column("target", style="dim")
    for f in items:
        colour = _SEV_COLOR.get(f.severity or "info", "white")
        t.add_row(f.fid, f"[{colour}]{f.severity or '-'}[/{colour}]",
                  f.status.value, f.title, f.target)
    console.print(t)


@app.command()
def show(
    finding_id: str = typer.Argument(...),
    workspace: str = _W,
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Print a finding."""
    _ws, store = _store(workspace)
    f = store.get(finding_id)
    if not f:
        raise UsageError(f"no finding matching '{finding_id}'")
    if as_json:
        from ..core.models import to_dict
        console.print_json(json.dumps(to_dict(f)))
    else:
        console.print(render_finding(f))


@app.command()
def new(
    title: str = typer.Argument(...),
    target: str = typer.Option("", "--target", "-t"),
    severity: str = typer.Option(None, "--severity", "-s"),
    vuln_class: str = typer.Option(None, "--class", help="CWE id, e.g. CWE-79."),
    from_vuln: str = typer.Option(None, "--from-vuln", help="Seed from a stored scanner hit id."),
    edit: bool = typer.Option(False, "--edit", "-e", help="Open $EDITOR afterwards."),
    workspace: str = _W,
) -> None:
    """Create a finding."""
    ws, store = _store(workspace)
    with ws.lock():
        if from_vuln:
            hit = _load_vuln(ws, from_vuln)
            draft = draft_from_vuln(hit, program=ws.slug)
            draft.number = store.next_number()
            if title and title != "-":
                draft.title = title
            f = draft
            store.save(f, touch=False)
        else:
            f = store.create(
                title, target=target, severity=severity, vuln_class=vuln_class
            )
    ok(f"created {f.fid} - {store.path_for(f)}")
    if edit:
        _open_editor(store, f)


@app.command("set")
def set_(
    finding_id: str = typer.Argument(...),
    status: str = typer.Option(None, "--status"),
    severity: str = typer.Option(None, "--severity"),
    cvss: str = typer.Option(None, "--cvss", help="CVSS vector; sets score + severity band."),
    title: str = typer.Option(None, "--title"),
    vuln_class: str = typer.Option(None, "--class"),
    target: str = typer.Option(None, "--target"),
    workspace: str = _W,
) -> None:
    """Update a finding's metadata."""
    ws, store = _store(workspace)
    f = store.get(finding_id)
    if not f:
        raise UsageError(f"no finding matching '{finding_id}'")
    if status:
        f.status = FindingStatus(status)
    if severity:
        f.severity = severity
    if title:
        f.title = title
    if vuln_class:
        f.vuln_class = vuln_class
    if target:
        f.target = target
    if cvss:
        res = parse_cvss(cvss)
        f.cvss_vector = res.vector
        f.cvss_score = res.score
        if not severity:
            f.severity = res.severity
        console.print(f"CVSS {res.version}: {res.score} ({res.severity})")
    with ws.lock():
        store.save(f)
    ok(f"updated {f.fid}")


@app.command()
def cvss(finding_id: str = typer.Argument(...), workspace: str = _W) -> None:
    """Interactive CVSS 3.1 wizard - sets vector, score and severity band."""
    from ..report.cvss import build_cvss31_interactive, parse_cvss

    ws, store = _store(workspace)
    f = store.get(finding_id)
    if not f:
        raise UsageError(f"no finding matching '{finding_id}'")
    vector = build_cvss31_interactive()
    res = parse_cvss(vector)
    f.cvss_vector = res.vector
    f.cvss_score = res.score
    f.severity = res.severity
    with ws.lock():
        store.save(f)
    ok(f"{f.fid}: {res.vector}  ->  {res.score} ({res.severity})")


@app.command()
def edit(finding_id: str = typer.Argument(...), workspace: str = _W) -> None:
    """Open a finding in $EDITOR, then re-index it."""
    ws, store = _store(workspace)
    f = store.get(finding_id)
    if not f:
        raise UsageError(f"no finding matching '{finding_id}'")
    _open_editor(store, f)


@app.command()
def rm(
    finding_id: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", "-y"),
    workspace: str = _W,
) -> None:
    """Delete a finding file."""
    ws, store = _store(workspace)
    f = store.get(finding_id)
    if not f:
        raise UsageError(f"no finding matching '{finding_id}'")
    if not yes and not typer.confirm(f"delete {f.fid} '{f.title}'?"):
        return
    with ws.lock():
        store.path_for(f).unlink(missing_ok=True)
        conn = _connect(ws)
        try:
            with conn:
                conn.execute("DELETE FROM finding WHERE number = ?", (f.number,))
                conn.execute("DELETE FROM finding_fts WHERE number = ?", (f.number,))
        finally:
            conn.close()
    ok(f"deleted {f.fid}")


@app.command()
def search(
    query: str = typer.Argument(...),
    workspace: str = _W,
) -> None:
    """Full-text search over finding bodies."""
    ws, _ = _store(workspace)
    conn = _connect(ws)
    try:
        rows = conn.execute(
            "SELECT number, title FROM finding_fts WHERE finding_fts MATCH ? ORDER BY rank",
            (query,),
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        warn("no matches")
        return
    for r in rows:
        console.print(f"[bold]{r['number']:04d}[/bold]  {r['title']}")


def _open_editor(store: FindingStore, f) -> None:
    path = store.path_for(f)
    editor = os.environ.get("EDITOR", "vi")
    subprocess.run([editor, str(path)], check=False)  # noqa: S603
    reloaded = store.get(f.fid)
    if reloaded:
        with store.ws.lock():
            store.save(reloaded, touch=True)
        ok(f"re-indexed {f.fid}")


def _connect(ws):
    from ..core import db as _db

    return _db.connect(ws.index_db)


def _load_vuln(ws, vuln_id: str) -> VulnHit:
    conn = _connect(ws)
    try:
        row = conn.execute(
            "SELECT * FROM vuln WHERE id = ? OR id LIKE ?", (vuln_id, vuln_id + "%")
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise UsageError(f"no stored scanner hit matching '{vuln_id}' (see `gesicht scan ... `)")
    d = dict(row)
    for k in ("cve", "tags", "extracted", "reference"):
        d[k] = json.loads(d[k]) if d.get(k) else []
    return VulnHit(
        scanner=d["scanner"], signature=d["signature"], name=d["name"],
        severity=d["severity"] or "info", url=d["url"] or "", host=d["host"] or "",
        cwe=d["cwe"], cve=d["cve"], cvss_score=d["cvss_score"],
        cvss_vector=d["cvss_vector"], tags=d["tags"], description=d["description"] or "",
        extracted=d["extracted"], reference=d["reference"], raw_ref=d["raw_ref"],
    )


# used by `gesicht scan` to auto-draft
def draft_hits(ws, store: FindingStore, hits: list[VulnHit], *, min_severity: str) -> list:
    threshold = severity_rank(min_severity)
    drafted = []
    for h in hits:
        if severity_rank(h.severity) < threshold:
            continue
        if store.has_source_key(h.id):
            continue
        f = draft_from_vuln(h, program=ws.slug)
        f.number = store.next_number()
        store.save(f, touch=False)
        drafted.append(f)
    return drafted

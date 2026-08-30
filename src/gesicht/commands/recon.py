"""``gesicht recon`` - asset discovery. Passive by default; active needs --yes-active."""

from __future__ import annotations

import json
from urllib.parse import urlparse

import typer
from rich.table import Table

from ..core import workspace as ws_mod
from ..core.console import console, ok, warn
from ..core.errors import UsageError
from ..core.models import ScopeType
from ..core.store import Store, stream_for
from ..scope import scope_md
from ..scope.guard import ScopeGuard
from ..tools.orchestrator import Orchestrator, RunResult

app = typer.Typer(help="Asset discovery: subdomains, DNS, ports.", no_args_is_help=True)

_W = typer.Option(None, "--workspace", "-w", help="Workspace path.")
_DRY = typer.Option(False, "--dry-run", help="Show the plan, run nothing.")
_YES = typer.Option(False, "--yes-active", help="Skip the confirmation for ACTIVE tools.")
_JSON = typer.Option(False, "--json", help="Machine-readable output.")
_RATE = typer.Option(None, "--rate", help="Requests/sec hint passed to the tool.")


def _confirm(adapter, targets) -> bool:  # noqa: ANN001
    preview = ", ".join(list(targets)[:3]) + (" ..." if len(targets) > 3 else "")
    return typer.confirm(
        f"Run ACTIVE {adapter.name} against {len(targets)} target(s) [{preview}]?"
    )


def _setup(workspace, dry_run, yes_active):
    ws = ws_mod.discover(explicit=workspace)
    scope = scope_md.load(ws.scope_md)
    guard = ScopeGuard(scope)
    orch = Orchestrator(
        ws, guard, dry_run=dry_run, assume_active=yes_active, confirm=_confirm
    )
    return ws, scope, orch


def _default_domains(scope) -> list[str]:
    out: set[str] = set()
    for e in scope.allow:
        if e.type == ScopeType.WILDCARD:
            out.add(e.value[2:] if e.value.startswith("*.") else e.value)
        elif e.type == ScopeType.DOMAIN:
            out.add(e.value)
        elif e.type == ScopeType.URL:
            h = urlparse(e.value).hostname
            if h:
                out.add(h)
    return sorted(out)


def _from_store(ws, stream: str) -> list[str]:
    p = ws.root / "parsed" / f"{stream}.txt"
    if not p.is_file():
        return []
    return [ln.split("\t")[0].strip() for ln in p.read_text().splitlines() if ln.strip()]


def _hosts_from_store(ws) -> list[str]:
    return _from_store(ws, "hosts")


def _emit(ws, result: RunResult, as_json: bool) -> None:
    if result.skipped:
        warn(f"skipped: {result.skipped}")
        raise typer.Exit(code=1)

    if result.dry_run:
        payload = {
            "adapter": result.adapter,
            "fallback_for": result.fallback_for,
            "argv": result.argv,
            "decisions": [
                {"target": d.target, "allowed": d.allowed, "reason": d.reason}
                for d in result.decisions
            ],
        }
        console.print_json(json.dumps(payload)) if as_json else _print_dry(payload)
        if any(not d.allowed for d in result.decisions):
            raise typer.Exit(code=2)
        return

    with ws.lock():
        counts = Store(ws).add_records(result.records)

    if as_json:
        console.print_json(
            json.dumps(
                {
                    "adapter": result.adapter,
                    "fallback_for": result.fallback_for,
                    "records": len(result.records),
                    "stored": counts,
                    "raw": str(result.raw_path) if result.raw_path else None,
                }
            )
        )
        return

    label = result.adapter
    if result.fallback_for:
        label += f" (fallback for {result.fallback_for})"
    if not result.records:
        warn(f"{label}: no results")
        return
    by_stream: dict[str, int] = {}
    for r in result.records:
        s = stream_for(r) or "other"
        by_stream[s] = by_stream.get(s, 0) + 1
    ok(f"{label}: " + ", ".join(f"{n} {s}" for s, n in by_stream.items()))
    console.print(f"[dim]raw: {result.raw_path}[/dim]")


def _print_dry(payload: dict) -> None:
    head = payload["adapter"]
    if payload["fallback_for"]:
        head += f"  (fallback for {payload['fallback_for']})"
    console.print(f"[bold]{head}[/bold]")
    console.print("  argv: " + " ".join(payload["argv"]))
    t = Table(box=None, show_header=False)
    for d in payload["decisions"]:
        mark = "[green]IN [/green]" if d["allowed"] else "[red]OUT[/red]"
        t.add_row(mark, d["target"], d["reason"])
    console.print(t)


@app.command()
def subs(
    targets: list[str] = typer.Argument(None, help="Domains (default: in-scope apexes)."),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES, as_json: bool = _JSON,
) -> None:
    """Passive subdomain enumeration (amass; falls back to archive.org CDX)."""
    ws, scope, orch = _setup(workspace, dry_run, yes_active)
    tg = targets or _default_domains(scope)
    if not tg:
        raise UsageError("no targets given and no in-scope domains in scope.md")
    _emit(ws, orch.run("amass", tg, options={"emit_hosts": True}), as_json)


@app.command()
def resolve(
    hosts: list[str] = typer.Argument(None, help="Hosts (default: parsed/hosts.txt)."),
    workspace: str = _W, dry_run: bool = _DRY, as_json: bool = _JSON,
) -> None:
    """Resolve hostnames to IPs (stdlib DNS)."""
    ws, _scope, orch = _setup(workspace, dry_run, True)
    tg = hosts or _hosts_from_store(ws)
    if not tg:
        raise UsageError(
            "no hosts given and parsed/hosts.txt is empty - run `gesicht recon subs` first"
        )
    _emit(ws, orch.run("resolver", tg), as_json)


@app.command()
def ports(
    targets: list[str] = typer.Argument(..., help="Hosts or IPs to scan."),
    ports_: str = typer.Option(None, "--ports", "-p", help="Port spec, e.g. 80,443,8000-9000."),
    top: int = typer.Option(1000, "--top", help="Scan the N most common ports."),
    tool: str = typer.Option("nmap", "--tool", help="nmap or naabu."),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES,
    rate: float = _RATE, as_json: bool = _JSON,
) -> None:
    """Service/port scan (nmap, or naabu). ACTIVE."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    opts = {"ports": ports_, "top_ports": None if ports_ else top}
    _emit(ws, orch.run(tool, targets, options=opts, rate=rate), as_json)


@app.command()
def urls(
    domains: list[str] = typer.Argument(None, help="Domains (default: in-scope apexes)."),
    limit: int = typer.Option(5000, "--limit", help="Max URLs from the archive."),
    workspace: str = _W, dry_run: bool = _DRY, as_json: bool = _JSON,
) -> None:
    """Passive URL discovery from archive.org (gau/waybackurls-style)."""
    ws, scope, orch = _setup(workspace, dry_run, True)
    tg = domains or _default_domains(scope)
    if not tg:
        raise UsageError("no domains given and no in-scope domains in scope.md")
    _emit(ws, orch.run("wayback", tg, options={"limit": limit}), as_json)


@app.command()
def probe(
    hosts: list[str] = typer.Argument(None, help="Hosts/URLs (default: parsed/hosts.txt)."),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES,
    rate: float = _RATE, as_json: bool = _JSON,
) -> None:
    """Probe which hosts serve HTTP(S) (httpx; falls back to the internal prober). ACTIVE."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    tg = hosts or _hosts_from_store(ws)
    if not tg:
        raise UsageError("no hosts given and parsed/hosts.txt is empty - run `gesicht recon subs`")
    _emit(ws, orch.run("httpx", tg, rate=rate), as_json)


@app.command()
def content(
    targets: list[str] = typer.Argument(..., help="Base URLs to fuzz for paths."),
    tool: str = typer.Option("ffuf", "--tool", help="ffuf, feroxbuster or gobuster."),
    wordlist: str = typer.Option(None, "--wordlist", "-W", help="Path to a wordlist."),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES,
    rate: float = _RATE, as_json: bool = _JSON,
) -> None:
    """Directory / content discovery. ACTIVE."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    _emit(ws, orch.run(tool, targets, options={"wordlist": wordlist}, rate=rate), as_json)


@app.command()
def crawl(
    urls_: list[str] = typer.Argument(None, help="Start URLs (default: parsed/urls.txt)."),
    depth: int = typer.Option(2, "--depth", "-d"),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES,
    rate: float = _RATE, as_json: bool = _JSON,
) -> None:
    """Crawl for endpoints (katana; falls back to the internal crawler). ACTIVE."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    tg = urls_ or _from_store(ws, "urls") or _hosts_from_store(ws)
    if not tg:
        raise UsageError("no start URLs given and nothing in parsed/{urls,hosts}.txt")
    _emit(ws, orch.run("katana", tg, options={"depth": depth}, rate=rate), as_json)


@app.command()
def params(
    targets: list[str] = typer.Argument(..., help="URLs to test for hidden parameters."),
    wordlist: str = typer.Option(None, "--wordlist", "-W"),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES,
    rate: float = _RATE, as_json: bool = _JSON,
) -> None:
    """Discover hidden HTTP parameters (arjun; falls back to the internal brute). ACTIVE."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    _emit(ws, orch.run("arjun", targets, options={"wordlist": wordlist}, rate=rate), as_json)


@app.command()
def fingerprint(
    hosts: list[str] = typer.Argument(None, help="Hosts/URLs (default: parsed/hosts.txt)."),
    waf: bool = typer.Option(False, "--waf", help="Also run wafw00f."),
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES, as_json: bool = _JSON,
) -> None:
    """Tech fingerprinting (whatweb, optionally wafw00f). ACTIVE."""
    ws, _scope, orch = _setup(workspace, dry_run, yes_active)
    tg = hosts or _hosts_from_store(ws)
    if not tg:
        raise UsageError("no hosts given and parsed/hosts.txt is empty")
    _emit(ws, orch.run("whatweb", tg), as_json)
    if waf:
        _emit(ws, orch.run("wafw00f", tg), as_json)


@app.command()
def all(  # noqa: A001 - matches the CLI verb
    workspace: str = _W, dry_run: bool = _DRY, yes_active: bool = _YES,
    passive: bool = typer.Option(False, "--passive", help="Passive steps only."),
    rate: float = _RATE,
) -> None:
    """Run the standard pipeline: subs -> resolve -> urls [-> probe -> fingerprint]."""
    ws, scope, orch = _setup(workspace, dry_run, yes_active)
    domains = _default_domains(scope)
    if not domains:
        raise UsageError("no in-scope domains in scope.md - add some with `gesicht scope add`")

    plan: list[tuple[str, list[str], dict]] = [
        ("amass", domains, {"emit_hosts": True}),
    ]
    steps_done = []
    for adapter, _tg, opts in plan:
        _run_step(ws, orch, adapter, domains, opts, rate, steps_done)

    hosts = _hosts_from_store(ws) or domains
    _run_step(ws, orch, "resolver", hosts, {}, rate, steps_done)
    _run_step(ws, orch, "wayback", domains, {}, rate, steps_done)
    if not passive:
        live = _hosts_from_store(ws) or hosts
        _run_step(ws, orch, "httpx", live, {}, rate, steps_done)
        _run_step(ws, orch, "whatweb", live, {}, rate, steps_done)

    ok("pipeline complete: " + ", ".join(steps_done))


def _run_step(ws, orch, adapter, targets, opts, rate, done: list[str]) -> None:
    try:
        res = orch.run(adapter, targets, options=opts, rate=rate)
    except Exception as e:  # noqa: BLE001 - one bad step shouldn't kill the pipeline
        warn(f"{adapter}: {e}")
        return
    if res.dry_run:
        console.print(f"[dim]{res.adapter}: " + " ".join(res.argv) + "[/dim]")
        done.append(f"{res.adapter}(dry)")
        return
    if res.skipped:
        warn(f"{res.adapter}: {res.skipped}")
        return
    with ws.lock():
        Store(ws).add_records(res.records)
    tag = res.adapter + (f"<-{res.fallback_for}" if res.fallback_for else "")
    done.append(f"{tag}:{len(res.records)}")

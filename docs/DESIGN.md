# gesicht — architecture

`gesicht` is ~7k lines of Python. It is an **orchestrator**: it builds command
lines for external security tools, runs them, parses the output into a common
model, and manages the finding → report lifecycle. Nothing here reimplements a
scanner — but every external tool has a small pure-Python fallback so the core
workflow keeps working when a binary is missing.

```
src/gesicht/
  cli.py                one Typer sub-app per verb
  commands/             init, scope, tools, recon, scan, finding, report, notes, q, export …
  core/
    workspace.py        per-target folder tree + discovery
    config.py           ~/.config/gesicht/config.yml, workspace-root resolution
    models.py           Host / Service / Endpoint / Param / VulnHit / Finding (dataclasses)
    store.py            flat files are truth; SQLite index is derived
    findings.py         findings/NNNN-slug.md  <->  Finding, + FTS index
    db.py               schema + migrations
  scope/
    guard.py            the fail-closed chokepoint
    matcher.py          domain / wildcard / URL / IP / CIDR matching (publicsuffix2)
    scope_md.py         parse/merge the scope.md bullet lists
    h1_import.py        HackerOne structured-scope import
  tools/
    base.py             ToolAdapter contract
    registry.py         binary discovery + availability + fallback resolution
    orchestrator.py     the only place a tool subprocess is launched
    installer.py        apt -> pipx -> go, with graceful failure
    adapters/           one class per external tool
    internal/           pure-Python fallbacks: prober, crawler, resolver, cdx, parambrute
  report/
    render.py           Jinja report from a Finding
    redact.py           scrub secrets / PII from evidence
    cvss.py             CVSS 3.1 / 4.0 via the `cvss` library
```

## The scope chokepoint

`scope/guard.py` is the single gate. `ScopeGuard.check()` is pure; every target
resolves to exactly one decision:

1. a matching **deny** rule wins → OUT
2. otherwise a matching **allow** rule → IN
3. otherwise (no rule matches) → OUT — *fail closed*
4. for an ACTIVE action, if the host resolves to an IP inside a deny CIDR → OUT
   (shared-infra trap)

`tools/orchestrator.py` calls the guard before **every** `subprocess` launch —
there is no code path that runs a tool without a decision. Out-of-scope attempts
are logged to `.gesicht/violations.log` and exit code 2.

Wildcard matching goes through `publicsuffix2` so `*.example.co.uk` can never be
read as covering the `co.uk` eTLD.

## Tool adapters + fallback chain

Every tool implements `ToolAdapter` (`tools/base.py`):

```python
name; binaries; category; activity            # passive | active
install: InstallSpec | None                   # apt / pipx / go
fallbacks: tuple[str, ...]                     # adapter names to try if this one is absent
build_steps(task, binary) -> list[list[str]]  # argv (one or more invocations)
parse(raw_path, task) -> Iterator[record]     # normalised model instances
```

`registry.resolve_runnable()` walks the `fallbacks` chain until it finds
something available. `amass` → `subfinder` → `wayback` (archive.org CDX);
`httpx` → an internal `urllib` prober; `katana` → an internal BFS crawler;
`arjun` → an internal parameter brute; every substitution is recorded in the
`ToolRun` log.

Passive vs active is a hard line declared per adapter. Passive never reaches the
target's infrastructure and runs freely; active needs `--yes-active` (or an
interactive confirmation), and `sqlmap` is confirmed twice.

## Storage: flat files are the truth

Raw tool output is written immutably under `recon/` and `scans/`. Parsers emit
normalised records that `core/store.py` writes two ways:

* `parsed/<stream>.ndjson` — append-only history
* `parsed/<stream>.txt` — sorted, de-duped, greppable projection

…and upserts into `.gesicht/index.db`. The database is a **cache**: `gesicht reindex`
rebuilds it from the flat files and run logs. Findings live as Markdown files
with YAML frontmatter; `findings.py` keeps a `finding` table and an FTS index in
sync.

## Findings → reports

A scanner hit (`VulnHit`) at or above `--min-severity` is auto-drafted into a
`findings/NNNN-slug.md` file (CWE inferred from tags via `data/severity_map.yml`,
deduped by a `source_key`). `gesicht finding` edits the metadata and body;
`gesicht report build` renders a Markdown report from a Jinja template (the
bundled default follows the HackerOne report layout; a workspace can override it
in `reports/templates/`), redacting secrets and PII from any embedded evidence by
default. `gesicht` never submits anything.

Scope can be typed by hand, imported from a file, or pulled from the HackerOne
API (`scope import --h1`) — the engine itself is program-agnostic.

## Not yet built

Traffic analysis — `gesicht traffic import` for HAR / Burp / mitmproxy captures with
heuristics (reflected params, IDOR candidates, tokens in URLs, CORS, secrets in
responses) feeding back into recon and findings.

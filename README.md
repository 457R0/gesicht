```
 _______  _______  _______  ___   _______  __   __  _______
|       ||       ||       ||   | |       ||  | |  ||       |
|    ___||    ___||  _____||   | |       ||  |_|  ||_     _|
|   | __ |   |___ | |_____ |   | |       ||       |  |   |
|   ||  ||    ___||_____  ||   | |      _||       |  |   |
|   |_| ||   |___  _____| ||   | |     |_ |   _   |  |   |
|_______||_______||_______||___| |_______||__| |__|  |___|
```

# gesicht

**A scope-safe recon & vulnerability-scanning orchestrator.**

[![ci](https://github.com/457r0/gesicht/actions/workflows/ci.yml/badge.svg)](https://github.com/457r0/gesicht/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`gesicht` combines various tools like `amass`, `nmap`, `nuclei`, `httpx`,
`katana`, `arjun`, `sqlmap`, `nikto`, `wpscan`, `whatweb`, and more — into one
workflow (subdomains → resolve → URLs → probe → scan → findings → report) and
**refuses to send a packet at anything outside the scope you defined.**

Two ideas do most of the work:

- **A fail-closed scope engine.** Every action that sends a packet is checked
  first. Deny beats allow; a target that matches no rule is out of scope. There
  is no code path that runs a tool without a decision.
- **Adapters with fallbacks.** Each external tool is a thin adapter. If a binary
  is missing, `gesicht` offers to install it (`apt` → `pipx` → `go`) and, failing
  that, substitutes a built-in Python implementation and records the swap.

Each target gets a small, greppable **workspace**; plain-text files are the
source of truth and the SQLite index is a rebuildable cache on top.
See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture.

## See it decide

```console
$ gesicht scope add '*.acme.com'
$ gesicht scope add 'secret.acme.com' --out
$ gesicht scope check www.acme.com secret.acme.com evil.com
IN   www.acme.com     - in scope via wildcard:*.acme.com
OUT  secret.acme.com  - matches out-of-scope rule domain:secret.acme.com
OUT  evil.com         - no scope rule matches this target (fail-closed)
```

## Languages & tooling — what's used, and where

`gesicht` is **~6,850 lines of Python** (plus ~2,270 lines of tests) across 65
modules. It is pure Python by design: the value is in orchestration, not in a new
scanner implementation.

| Language / format | Where it lives | What it does |
|---|---|---|
| **Python 3.11+** | all of `src/gesicht/` | 100% of the logic — CLI, scope engine, tool adapters, storage, reporting |
| **Typer** (Click-based) | `cli.py`, `commands/` | the command tree — one Typer sub-app per verb (`init`, `scope`, `recon`, `scan`, `finding`, `report`, …) |
| **Rich** | `core/console.py` | tables, colour, progress in the terminal |
| **Jinja2** | `report/render.py`, `report/templates/h1_report.md.j2` | renders a Markdown report from a `Finding`; the bundled template follows the HackerOne layout and a workspace can override it |
| **YAML** | `~/.config/gesicht/config.yml`, `src/gesicht/data/severity_map.yml` | global config (workspace root, rate limits, pinned binary paths) and the tag → CWE / severity map |
| **Markdown + YAML frontmatter** | `findings/NNNN-slug.md`, `scope.md` in every workspace | the *source of truth* for findings and scope — human-readable, diffable, hand-editable |
| **SQLite** (stdlib `sqlite3`) | `core/db.py`, `.gesicht/index.db` | a **derived** index + full-text search over the flat files; rebuilt from scratch by `gesicht reindex` |
| **NDJSON / plain text** | `parsed/*.ndjson`, `parsed/*.txt` in every workspace | append-only record history + a sorted, de-duped, greppable projection |
| **TOML** | `pyproject.toml` | packaging (Hatchling build backend), dependency pins, `ruff` / `pytest` config |
| **GitHub Actions YAML** | `.github/workflows/ci.yml` | CI: `ruff` + `pytest` on a Python 3.11 / 3.12 / 3.13 matrix |

### Internal architecture (Python), by package

| Package | Responsibility |
|---|---|
| `core/` | workspace folder tree, config resolution, the dataclass model (`Host` / `Service` / `Endpoint` / `Param` / `VulnHit` / `Finding`), the flat-file store, the findings ↔ Markdown bridge, DB schema |
| `scope/` | the fail-closed decision engine — `guard.py` (the chokepoint), `matcher.py` (domain / wildcard / URL / IP / CIDR matching via `publicsuffix2`), `scope_md.py` (parse/merge the scope bullet lists), `h1_import.py` (HackerOne structured-scope import) |
| `tools/` | the `ToolAdapter` contract, binary discovery + fallback resolution (`registry.py`), the single subprocess launch point (`orchestrator.py`), the `apt → pipx → go` installer, one adapter per external tool (`adapters/`), and pure-Python fallbacks (`internal/`: `prober`, `crawler`, `resolver`, `cdx`, `parambrute`) |
| `commands/` | thin CLI layer — argument parsing and output formatting, one module per verb |
| `report/` | Jinja rendering, secret/PII redaction, CVSS 3.1 / 4.0 scoring (via the `cvss` library) |

### Dependencies

Runtime: `typer` (pinned to the `0.12.x` line with `click>=8.1,<8.2` — 0.13+
vendors its own Click fork), `rich`, `jinja2`, `pyyaml`, `cvss`, `publicsuffix2`.

Dev: `pytest`, `pytest-mock`, `pytest-socket` (sockets are hard-disabled for the
whole suite), `hypothesis` (property-based tests), `ruff`.

## Install

Requires **Python 3.11+** and Linux. The external security tools are optional —
`gesicht` installs them on demand or falls back to a built-in implementation.

```bash
# put `gesicht` on your PATH (recommended)
pipx install --editable .

# or a plain venv for development
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

gesicht --help
```

Shell completion: `gesicht --install-completion`.

### First run

```bash
gesicht init acme.com                       # scaffold + select a workspace
gesicht scope add '*.acme.com' --max critical
gesicht scope check www.acme.com evil.com   # explains every decision
gesicht tools doctor                        # what's installed, what will fall back
```

## A session, end to end

```bash
# 1. scaffold a workspace and select it
gesicht init acme.com

# 2. define scope — by hand, from a file, or from the HackerOne API
gesicht scope add '*.acme.com' --max critical
gesicht scope add legacy.acme.com --out
gesicht scope import --file scope.json
gesicht scope import --h1 acme            # needs GESICHT_H1_TOKEN
gesicht scope check www.acme.com evil.com # explains every decision
gesicht scope lint                        # flags dangerous rules

# 3. recon (passive unless --yes-active)
gesicht recon subs                        # amass -> subfinder -> archive.org fallback
gesicht recon resolve
gesicht recon urls
gesicht recon probe --yes-active          # httpx -> internal prober
gesicht recon content https://www.acme.com --yes-active
gesicht recon all --passive               # subs -> resolve -> urls pipeline

# 4. vuln scanning — auto-drafts findings from the hits
gesicht scan nuclei --yes-active --min-severity medium
gesicht scan web --yes-active             # nikto
gesicht scan sqli 'https://a.acme.com/item?id=1' --yes-active   # double-confirmed

# 5. curate findings
gesicht finding ls
gesicht finding show 1
gesicht finding cvss 1                    # interactive CVSS 3.1 wizard
gesicht finding set 1 --status confirmed
gesicht finding edit 1                    # opens $EDITOR

# 6. reports (secrets/PII redacted by default)
gesicht report preview 1
gesicht report build 1                    # -> reports/0001-<slug>.report.md
gesicht report bundle --status confirmed

# 7. anytime
gesicht status
gesicht notes add "idor smells around /invoices" -t idea
gesicht q "select severity, count(*) from vuln group by 1"
gesicht export                            # one JSON of the whole workspace
```

## Features

### 1. A fail-closed scope engine

`scope/guard.py` is a single, **pure** chokepoint. Every target resolves to
exactly one decision, in this order:

1. a matching **deny** rule always wins → **OUT**
2. otherwise a matching **allow** rule → **IN**
3. otherwise (nothing matches) → **OUT** — *fail closed*
4. for an **active** action, the host is resolved to its IPs and each is
   re-checked against deny `ip` / `cidr` rules → **OUT** — the shared-infra trap

`tools/orchestrator.py` is the **only** place a tool subprocess is launched, and
it calls the guard before every launch. Out-of-scope attempts are appended to
`.gesicht/violations.log` and exit code `2`. Wildcard matching goes through
`publicsuffix2`, so `*.example.co.uk` can never be read as covering the `co.uk`
eTLD.

### 2. Adapters with a fallback chain

Every external tool implements one small contract (`tools/base.py`):
`build_steps(task, binary) -> argv` and `parse(raw_path, task) -> records`. When
a binary is missing, `registry.resolve_runnable()` walks a declared fallback
chain until it finds something that works:

- `amass` → `subfinder` → `wayback` (archive.org CDX)
- `httpx` → an internal `urllib` prober
- `katana` → an internal BFS crawler
- `arjun` → an internal parameter brute

Failing that, `gesicht` offers to install the tool (`apt → pipx → go`). Every
substitution is recorded in the `ToolRun` log. **The core workflow runs with zero
third-party tools installed.**

### 3. Passive vs. active is a hard, declared line

Passive actions never reach the target's infrastructure and run freely. Active
actions require `--yes-active` (or an interactive confirmation); `sqlmap` is
confirmed twice. `--dry-run` prints the exact argv and the scope decision for
every target without doing DNS or sending traffic.

### 4. Plain text is the source of truth

Raw tool output is written **immutably** under `recon/` and `scans/`. Parsers
emit normalised records that the store writes two ways — an append-only
`parsed/<stream>.ndjson` and a sorted, de-duped, greppable `parsed/<stream>.txt`
— and upserts into `.gesicht/index.db`. **The database is a cache.**
`gesicht reindex` rebuilds it from the flat files and run logs. Findings are
Markdown files with YAML frontmatter, one per finding, kept in sync with a
`finding` table and an FTS index.

### 5. Finding → report lifecycle

A scanner hit at or above `--min-severity` is auto-drafted into a
`findings/NNNN-slug.md` file (CWE inferred from tags via `data/severity_map.yml`,
deduped by a `source_key`). `gesicht finding` edits the metadata and body;
`gesicht finding cvss` is an interactive CVSS 3.1 / 4.0 wizard. `gesicht report
build` renders a Markdown report from the Jinja template, **redacting secrets and
PII from any embedded evidence by default**. `gesicht` never submits anything.

### 6. Program-agnostic scope import

Scope can be typed by hand, imported from a JSON file, or pulled straight from the
HackerOne API (`gesicht scope import --h1 <handle>`). `gesicht scope lint` flags
dangerous rules (e.g. a wildcard whose base is a public suffix).

### 7. Tested like a safety-critical tool

**188 tests** — unit, full CLI end-to-end, and **property-based** (Hypothesis)
tests that hammer the pure matcher and guard. `pytest-socket` disables all
sockets for the suite, so no test can accidentally hit the network. `ruff`-clean,
CI on Python 3.11–3.13.

```bash
pytest -q && ruff check src/ tests/
```

## Command map

| Group | Commands |
|---|---|
| workspace | `init`, `use`, `ls`, `status`, `reindex`, `config` |
| scope | `scope add\|rm\|list\|check\|lint\|import` |
| tools | `tools list\|doctor\|install` |
| recon | `recon subs\|resolve\|ports\|urls\|probe\|content\|crawl\|params\|fingerprint\|all` |
| vuln | `scan nuclei\|web\|wp\|sqli` |
| findings | `finding new\|ls\|show\|set\|edit\|rm\|search\|cvss` |
| reports | `report build\|preview\|bundle\|templates` |
| misc | `notes add\|show\|grep`, `q`, `export` |

Most commands take `--json`, `--workspace/-w`, and (for active tools)
`--dry-run` / `--yes-active` / `--rate`.

## Layout of a workspace

```
<your-workspace-root>/<slug>/
  README.md  scope.md  notes.md          # scope.md is the scope source of truth
  recon/{subdomains,dns,ports,urls}/     # raw tool output (immutable)
  scans/{nuclei,nmap,web}/  content/
  parsed/*.ndjson  *.txt                 # normalised + greppable projections
  findings/NNNN-slug.md                  # one file per finding (YAML + sections)
  reports/                               # rendered reports
  exploits/  loot/                       # your files — gesicht never writes here
  .gesicht/  index.db  scope.json  state.json  runs/  violations.log
```

## Choosing your workspace root

The parent directory that holds every workspace is resolved in this order:

1. `--base` on `gesicht init`
2. `$GESICHT_HOME`
3. `workspaces_root` in `~/.config/gesicht/config.yml`
   (`gesicht config set workspaces_root <dir>`)
4. `~/gesicht` (default)

## Configuration

Global config lives at `~/.config/gesicht/config.yml` (`gesicht config path`) —
keys include `workspaces_root`, `rate_per_host`, and `tool.<name>` to pin a
binary path. Secrets stay in the environment: `GESICHT_H1_TOKEN` for HackerOne
scope import (read from the env or the system keyring, never written to disk),
`WPSCAN_API_TOKEN` for wpscan vulnerability data.

## Why use gesicht instead of running the tools yourself

- **A safety rail you cannot get by hand.** One enforced scope gate means you
  physically cannot fire `nuclei` at an out-of-scope host — or at a shared-infra
  IP a hostname quietly resolves to — even with a typo. Run ten tools manually
  and that guarantee lives only in your memory.
- **One data model, not ten output formats.** You don't hand-glue `nmap` XML into
  `httpx` JSON into `nuclei` results. `Host` / `Service` / `Endpoint` / `Param` /
  `VulnHit` / `Finding` are shared across every adapter.
- **A missing tool doesn't break the workflow.** Fallbacks and on-demand install
  keep the pipeline moving, and every substitution is logged.
- **Reproducibility and auditability.** Immutable raw output, run logs with the
  exact command line and the scope decision behind it, `violations.log`,
  greppable projections, and a single-JSON `gesicht export`. You can prove what
  you ran, against what, and when.
- **Curation is built in.** Auto-drafted findings, a CVSS wizard, and redacted
  reports in a submittable format — not just a pile of scanner output.
- **Low-friction querying.** A greppable plain-text workspace plus
  `gesicht q "select severity, count(*) from vuln group by 1"` straight against
  the index.

`gesicht` does **not** replace judgement, manual testing, or a real methodology.
It removes the glue work and the footguns around the parts that *are*
mechanisable.

## FAQ

**Why is the scope engine fail-closed?**
The cost of a wrong *deny* is a warning message you override. The cost of a wrong
*allow* is an unauthorised scan, with the legal and reputational exposure that
carries. The risk is asymmetric, so the default is deny.

**How do you test code that is supposed to hit the network?**
Adapters are split into pure halves — build an argv, parse a text file — so they
are tested with fixtures and no tool installed. `pytest-socket` blocks every
socket in the suite. The scope matcher and guard are pure functions, fuzzed with
Hypothesis.

**Why plain files instead of a database?**
Flat files are greppable, diffable, survive schema changes, and can be
hand-edited mid-engagement. The SQLite index is a performance cache;
`gesicht reindex` rebuilds it from the files and run logs at any time.

**What happens if I don't have `amass` / `nuclei` / `httpx` installed?**
`gesicht` offers to install the tool (`apt`, then `pipx`, then `go`). If that
fails or you decline, it substitutes a built-in Python implementation where one
exists (subdomain discovery, HTTP probing, crawling, parameter brute-forcing) and
records the swap in the run log.

**Does gesicht submit reports or exploit anything automatically?**
No. It drafts and renders findings; submission is always a manual step outside the
tool. Active scans require explicit opt-in (`--yes-active`), and `sqlmap` is
confirmed twice.

**Is it tied to HackerOne?**
No. HackerOne is one scope *source* (`scope import --h1`). The scope engine and
the rest of the workflow are program-agnostic — scope can equally come from a
file or be typed by hand.
I created this initially to be used for Bounty Hunts, it can be used with any, H1 is just where i started.
## License

MIT — see [`LICENSE`](LICENSE).

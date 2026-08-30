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

`gesicht` drives the tools you already have (`amass`, `nmap`, `nuclei`, `ffuf`,
`feroxbuster`, `httpx`, `sqlmap`, `wpscan`, `nikto`, `whatweb`, …) through one
workflow — **recon → vulnerability scanning → findings → reports** — and refuses
to touch anything outside the scope you defined.

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

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # development
pipx install --editable .        # or: put `gesicht` on your PATH
gesicht --help
```

Shell completion: `gesicht --install-completion`.

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

## Quality

188 tests (unit, property, and CLI), `ruff`-clean, CI on Python 3.11–3.13.

```bash
pytest -q && ruff check src/ tests/
```

Planned: `gesicht traffic import` — HAR / Burp / mitmproxy analysis feeding back
into recon and findings. See [`docs/DESIGN.md`](docs/DESIGN.md).

## License

MIT — see [`LICENSE`](LICENSE).

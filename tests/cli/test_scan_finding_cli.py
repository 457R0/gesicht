from __future__ import annotations

from typer.testing import CliRunner

from gesicht.cli import app
from gesicht.core.models import VulnHit
from gesicht.scope.guard import ScopeDecision
from gesicht.tools.orchestrator import RunResult

runner = CliRunner()


def _setup(root, monkeypatch):
    monkeypatch.chdir(root)
    runner.invoke(app, ["init", "acme.com"])
    monkeypatch.chdir(root / "acme.com")
    runner.invoke(app, ["scope", "add", "*.acme.com"])
    runner.invoke(app, ["scope", "add", "acme.com"])


def _fake_run(hits):
    def _run(self, adapter_name, targets, **kw):
        decs = [ScopeDecision(t, True, "ok") for t in targets]
        if self.dry_run:
            from gesicht.core.models import Activity, ToolRun
            run = ToolRun(tool=adapter_name, argv=[adapter_name, *targets],
                          targets=list(targets), activity=Activity.ACTIVE)
            return RunResult(adapter_name, run=run, decisions=decs, dry_run=True)
        return RunResult(adapter_name, records=list(hits), decisions=decs,
                         run=None)
    return _run


def test_scan_nuclei_drafts_findings(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    hits = [
        VulnHit(scanner="nuclei", signature="rce-1", name="RCE somewhere",
                severity="critical", url="https://a.acme.com/x", host="a.acme.com",
                tags=["rce"]),
        VulnHit(scanner="nuclei", signature="info-1", name="Version disclosure",
                severity="info", url="https://a.acme.com/y", host="a.acme.com"),
    ]
    monkeypatch.setattr("gesicht.tools.orchestrator.Orchestrator.run", _fake_run(hits))
    r = runner.invoke(app, ["scan", "nuclei", "https://a.acme.com", "--yes-active", "--json"])
    assert r.exit_code == 0, r.output
    assert '"hits": 2' in r.output
    # only the critical one is >= default min-severity 'medium'
    assert r.output.count('"00') == 1 or '"drafted": ["0001"]' in r.output

    lr = runner.invoke(app, ["finding", "ls", "--json"])
    assert lr.output.count('"id"') == 1
    assert "RCE somewhere" in lr.output


def test_scan_nuclei_no_draft_flag(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    hits = [VulnHit(scanner="nuclei", signature="x", name="High thing",
                    severity="high", url="https://a.acme.com/x")]
    monkeypatch.setattr("gesicht.tools.orchestrator.Orchestrator.run", _fake_run(hits))
    runner.invoke(app, ["scan", "nuclei", "https://a.acme.com", "--yes-active", "--no-draft"])
    assert runner.invoke(app, ["finding", "ls", "--json"]).output.count('"id"') == 0


def test_scan_nuclei_dedupes_on_rerun(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    hits = [VulnHit(scanner="nuclei", signature="x", name="Dup", severity="high",
                    url="https://a.acme.com/x")]
    monkeypatch.setattr("gesicht.tools.orchestrator.Orchestrator.run", _fake_run(hits))
    runner.invoke(app, ["scan", "nuclei", "https://a.acme.com", "--yes-active"])
    runner.invoke(app, ["scan", "nuclei", "https://a.acme.com", "--yes-active"])
    assert runner.invoke(app, ["finding", "ls", "--json"]).output.count('"id"') == 1


def test_scan_nuclei_dry_run(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["scan", "nuclei", "https://a.acme.com", "--dry-run"])
    assert r.exit_code == 0
    assert "nuclei" in r.output and "IN" in r.output


def test_finding_new_set_show(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["finding", "new", "Open redirect on login",
                            "-t", "https://a.acme.com/login", "-s", "low"])
    assert r.exit_code == 0 and "0001" in r.output

    r = runner.invoke(app, [
        "finding", "set", "1",
        "--cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "--status", "confirmed",
    ])
    assert r.exit_code == 0

    r = runner.invoke(app, ["finding", "show", "1"])
    assert "cvss_score" in r.output and "confirmed" in r.output

    r = runner.invoke(app, ["finding", "ls", "--status", "confirmed", "--json"])
    assert '"id": "0001"' in r.output


def test_finding_search(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    runner.invoke(app, ["finding", "new", "SSRF via avatar URL", "-s", "high"])
    f = workspaces_root / "acme.com" / "findings" / "0001-ssrf-via-avatar-url.md"
    f.write_text(
        f.read_text().replace("## Summary\n\n", "## Summary\n\nfetches internal metadata\n")
    )
    assert runner.invoke(app, ["finding", "edit", "1"]).exit_code == 0  # re-indexes
    r = runner.invoke(app, ["finding", "search", "metadata"])
    assert "0001" in r.output


def test_scan_out_of_scope_blocked(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["scan", "nuclei", "https://evil.com", "--dry-run"])
    assert r.exit_code == 2

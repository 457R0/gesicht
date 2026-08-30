from __future__ import annotations

from typer.testing import CliRunner

from gesicht.cli import app

runner = CliRunner()


def _setup(root, monkeypatch):
    monkeypatch.chdir(root)
    runner.invoke(app, ["init", "acme.com"])
    monkeypatch.chdir(root / "acme.com")
    runner.invoke(app, ["scope", "add", "*.acme.com"])
    runner.invoke(app, ["finding", "new", "IDOR in invoices", "-t",
                        "https://api.acme.com/i/1", "-s", "high"])
    return root / "acme.com"


def test_report_build_writes_file(workspaces_root, monkeypatch):
    ws = _setup(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["report", "build", "1"])
    assert r.exit_code == 0, r.output
    out = ws / "reports" / "0001-idor-in-invoices.report.md"
    assert out.is_file()
    body = out.read_text()
    assert "# IDOR in invoices" in body and "## Remediation" in body


def test_report_build_redacts_and_reports(workspaces_root, monkeypatch):
    ws = _setup(workspaces_root, monkeypatch)
    fp = ws / "findings" / "0001-idor-in-invoices.md"
    fp.write_text(fp.read_text().replace(
        "## Proof of Concept\n\n",
        "## Proof of Concept\n\nAuthorization: Bearer abcdef0123456789abcdef0\n",
    ))
    runner.invoke(app, ["reindex"])
    r = runner.invoke(app, ["report", "build", "1"])
    assert "redacted 1 secret" in r.output.lower() or "REDACTED-BEARER" in (
        ws / "reports" / "0001-idor-in-invoices.report.md"
    ).read_text()


def test_report_preview_does_not_write(workspaces_root, monkeypatch):
    ws = _setup(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["report", "preview", "1"])
    assert r.exit_code == 0
    assert "# IDOR in invoices" in r.output
    assert not (ws / "reports" / "0001-idor-in-invoices.report.md").exists()


def test_report_bundle_status_filter(workspaces_root, monkeypatch):
    ws = _setup(workspaces_root, monkeypatch)
    runner.invoke(app, ["finding", "new", "Low sev thing", "-s", "low"])
    runner.invoke(app, ["finding", "set", "1", "--status", "confirmed"])
    r = runner.invoke(app, ["report", "bundle", "--status", "confirmed"])
    assert r.exit_code == 0
    assert (ws / "reports" / "0001-idor-in-invoices.report.md").is_file()
    assert not (ws / "reports" / "0002-low-sev-thing.report.md").is_file()


def test_report_templates_lists(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["report", "templates"])
    assert "h1_report.md.j2" in r.output


def test_finding_cvss_wizard(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    monkeypatch.setattr(
        "gesicht.report.cvss.build_cvss31_interactive",
        lambda prompt=None: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    )
    r = runner.invoke(app, ["finding", "cvss", "1"])
    assert r.exit_code == 0
    assert "6.5" in r.output and "medium" in r.output  # 6.5 is CVSS "Medium"

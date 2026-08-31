from __future__ import annotations

import pytest

from gesicht.core.errors import ScopeViolation, ToolUnavailable
from gesicht.core.models import ScopeEntry, ScopeType
from gesicht.scope.guard import ScopeGuard
from gesicht.scope.model import ScopeSet
from gesicht.tools.orchestrator import Orchestrator


def _guard(*rules):
    entries = [ScopeEntry(type=ScopeType(t), value=v, in_scope=s) for t, v, s in rules]
    return ScopeGuard(ScopeSet(entries=entries), resolver=lambda h: [])


@pytest.fixture
def ws(make_ws):
    return make_ws("acme.com")


def test_scope_hook_blocks_out_of_scope_before_running(ws, fake_registry):
    guard = _guard(("wildcard", "*.acme.com", True))
    orch = Orchestrator(ws, guard, reg=fake_registry)
    with pytest.raises(ScopeViolation):
        orch.run("fake_internal", ["evil.com"])
    log = ws.violations_log.read_text()
    assert "evil.com" in log and "fake_internal" in log
    # nothing was produced
    assert not (ws.root / "parsed").exists()


def test_in_scope_passive_runs_and_logs_toolrun(ws, fake_registry):
    guard = _guard(("wildcard", "*.acme.com", True))
    orch = Orchestrator(ws, guard, reg=fake_registry)
    res = orch.run("fake_internal", ["acme.com"])
    assert [h.hostname for h in res.records] == ["sub.acme.com"]
    assert res.run.exit_code == 0
    assert res.run.records_emitted == 1
    assert list(ws.runs_dir.glob("*.json"))
    assert res.raw_path.read_text() == "fake raw\n"


def test_active_requires_confirmation(ws, fake_registry):
    guard = _guard(("wildcard", "*.acme.com", True))

    declined = Orchestrator(ws, guard, reg=fake_registry, confirm=lambda a, t: False)
    assert declined.run("fake_active", ["acme.com"]).skipped == "user declined"

    accepted = Orchestrator(ws, guard, reg=fake_registry, confirm=lambda a, t: True)
    assert accepted.run("fake_active", ["acme.com"]).records

    yes = Orchestrator(ws, guard, reg=fake_registry, assume_active=True)
    assert yes.run("fake_active", ["acme.com"]).records


def test_dry_run_builds_argv_without_executing(ws, fake_registry):
    guard = _guard(("domain", "acme.com", True))
    orch = Orchestrator(ws, guard, reg=fake_registry, dry_run=True)
    res = orch.run("fake_echo", ["acme.com"])
    assert res.dry_run
    assert res.argv[0].endswith("echo") and res.argv[-1] == "acme.com"
    assert not list(ws.runs_dir.glob("*.json"))  # nothing ran


def test_missing_tool_falls_back(ws, fake_registry):
    guard = _guard(("domain", "acme.com", True))
    orch = Orchestrator(ws, guard, reg=fake_registry)
    res = orch.run("fake_missing", ["acme.com"])
    assert res.adapter == "fake_internal"
    assert res.fallback_for == "fake_missing"
    assert res.records


def test_missing_tool_no_fallback_raises(ws, fake_registry):
    fake_registry.get("fake_missing").fallbacks = ()
    guard = _guard(("domain", "acme.com", True))
    orch = Orchestrator(ws, guard, reg=fake_registry)
    with pytest.raises(ToolUnavailable):
        orch.run("fake_missing", ["acme.com"])


def test_real_subprocess_path(ws, fake_registry):
    guard = _guard(("domain", "acme.com", True))
    orch = Orchestrator(ws, guard, reg=fake_registry)
    res = orch.run("fake_echo", ["acme.com"])
    assert res.run.exit_code == 0
    assert "hello acme.com" in res.raw_path.read_text()
    assert [h.hostname for h in res.records] == ["echoed.example.com"]


def test_subprocess_timeout_kills_process_and_reports_exit_code(ws, fake_registry):
    guard = _guard(("domain", "acme.com", True))
    orch = Orchestrator(ws, guard, reg=fake_registry)
    res = orch.run("fake_sleep", ["acme.com"], timeout=0.05)
    assert res.run.exit_code == 124

from __future__ import annotations

import pytest

from gesicht.core.errors import ScopeViolation
from gesicht.core.models import Activity, ScopeEntry, ScopeType
from gesicht.scope.guard import ScopeGuard
from gesicht.scope.model import ScopeSet


def mkscope(*rules, **settings):
    entries = []
    for t, v, in_scope in rules:
        entries.append(ScopeEntry(type=ScopeType(t), value=v, in_scope=in_scope))
    s = ScopeSet(entries=entries)
    s.settings.update(settings)
    return s


@pytest.fixture
def guard():
    scope = mkscope(
        ("wildcard", "*.acme.com", True),
        ("domain", "api.acme.com", True),
        ("cidr", "10.0.0.0/8", False),
        ("domain", "secret.acme.com", False),
    )
    return ScopeGuard(scope, resolver=lambda h: [])


def test_in_scope_via_wildcard(guard):
    d = guard.check_one("www.acme.com")
    assert d.allowed and d.matched_rule.value == "*.acme.com"


def test_denylist_beats_allowlist(guard):
    d = guard.check_one("secret.acme.com")
    assert not d.allowed
    assert d.matched_rule.value == "secret.acme.com"


def test_fail_closed_for_unmatched(guard):
    d = guard.check_one("example.org")
    assert not d.allowed and d.matched_rule is None
    assert "fail-closed" in d.reason


def test_active_requires_confirmation(guard):
    assert guard.check_one("www.acme.com", Activity.ACTIVE).requires_confirmation is True
    assert guard.check_one("www.acme.com", Activity.PASSIVE).requires_confirmation is False


def test_resolution_guard_blocks_shared_infra():
    scope = mkscope(
        ("wildcard", "*.acme.com", True),
        ("cidr", "10.0.0.0/8", False),
        resolve_before_active=True,
    )
    g = ScopeGuard(scope, resolver=lambda h: ["10.1.2.3"])
    passive = g.check_one("www.acme.com", Activity.PASSIVE)
    assert passive.allowed  # passive doesn't resolve
    active = g.check_one("www.acme.com", Activity.ACTIVE)
    assert not active.allowed
    assert "resolves to 10.1.2.3" in active.reason


def test_authorize_logs_and_raises(guard, tmp_path):
    log = tmp_path / "violations.log"
    with pytest.raises(ScopeViolation):
        guard.authorize(["www.acme.com", "evil.com"], violations_log=log)
    assert log.is_file()
    contents = log.read_text()
    assert "evil.com" in contents and "www.acme.com" not in contents


def test_authorize_passes_when_all_in_scope(guard, tmp_path):
    out = guard.authorize(["www.acme.com", "api.acme.com"], violations_log=tmp_path / "v.log")
    assert all(d.allowed for d in out)
    assert not (tmp_path / "v.log").exists()

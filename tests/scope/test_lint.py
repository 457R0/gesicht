from __future__ import annotations

from gesicht.core.models import ScopeEntry, ScopeType
from gesicht.scope.lint import lint, worst_level
from gesicht.scope.model import ScopeSet


def S(*entries):
    return ScopeSet(entries=list(entries))


def E(t, v, in_scope=True):
    return ScopeEntry(type=ScopeType(t), value=v, in_scope=in_scope)


def test_bare_tld_wildcard_is_an_error():
    issues = lint(S(E("wildcard", "*.com")))
    assert worst_level(issues) == "error"
    assert any("public suffix" in i.message for i in issues)


def test_etld_wildcard_is_an_error():
    assert worst_level(lint(S(E("wildcard", "*.co.uk")))) == "error"


def test_legit_wildcard_ok():
    issues = lint(S(E("wildcard", "*.acme.com")))
    assert worst_level(issues) != "error"


def test_apex_note_when_setting_disabled():
    scope = S(E("wildcard", "*.acme.com"))
    scope.settings["wildcard_includes_apex"] = False
    assert any("apex" in i.message for i in lint(scope))


def test_private_range_in_scope_warns():
    issues = lint(S(E("cidr", "192.168.0.0/16", in_scope=True)))
    assert any(i.level == "warn" and "RFC1918" in i.message for i in issues)


def test_value_in_both_lists_is_error():
    issues = lint(S(E("domain", "x.acme.com", True), E("domain", "x.acme.com", False)))
    assert worst_level(issues) == "error"


def test_empty_scope_warns():
    assert any("no in-scope" in i.message for i in lint(S()))

"""Property tests for the invariants that keep a researcher un-banned."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from gesicht.core.models import Activity, ScopeEntry, ScopeType
from gesicht.scope.guard import ScopeGuard
from gesicht.scope.matcher import match_entry
from gesicht.scope.model import ScopeSet, parse_target

_labels = st.text("abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=8)
hostnames = st.lists(_labels, min_size=1, max_size=4).map(lambda p: ".".join(p) + ".com")
rule_types = st.sampled_from(["domain", "wildcard"])


@st.composite
def scopesets(draw):
    n = draw(st.integers(min_value=0, max_value=6))
    entries = []
    for _ in range(n):
        t = draw(rule_types)
        base = draw(hostnames)
        val = f"*.{base}" if t == "wildcard" else base
        entries.append(
            ScopeEntry(type=ScopeType(t), value=val, in_scope=draw(st.booleans()))
        )
    return ScopeSet(entries=entries)


@given(scope=scopesets(), target=hostnames)
def test_no_target_outside_the_ruleset_is_ever_allowed(scope, target):
    """If nothing in the allow list matches, the decision must be OUT."""
    g = ScopeGuard(scope, resolver=lambda h: [])
    d = g.check_one(target, Activity.PASSIVE)
    tgt = parse_target(target)
    # mirror the guard's default (wildcard_includes_apex = True)
    allow_matches = any(match_entry(e, tgt, includes_apex=True) for e in scope.allow)
    if not allow_matches:
        assert d.allowed is False


@given(scope=scopesets(), target=hostnames)
def test_any_matching_deny_forces_out(scope, target):
    g = ScopeGuard(scope, resolver=lambda h: [])
    tgt = parse_target(target)
    if any(match_entry(e, tgt) for e in scope.deny):
        assert g.check_one(target).allowed is False


@given(scope=scopesets(), target=hostnames)
def test_decision_reason_is_never_empty(scope, target):
    d = ScopeGuard(scope, resolver=lambda h: []).check_one(target)
    assert d.reason
    assert (d.matched_rule is None) == ("fail-closed" in d.reason)

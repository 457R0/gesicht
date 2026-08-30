from __future__ import annotations

import pytest

from gesicht.core.models import ScopeEntry, ScopeType
from gesicht.scope.matcher import (
    is_public_suffix,
    match_entry,
    wildcard_base_is_safe,
)
from gesicht.scope.model import parse_target


def E(t, v, in_scope=True):
    return ScopeEntry(type=ScopeType(t), value=v, in_scope=in_scope)


@pytest.mark.parametrize(
    "host,expected",
    [
        ("com", True),
        ("co.uk", True),
        ("acme.com", False),
        ("acme.co.uk", False),
        ("", True),
    ],
)
def test_is_public_suffix(host, expected):
    assert is_public_suffix(host) is expected


@pytest.mark.parametrize(
    "base,safe",
    [
        ("acme.com", True),
        ("acme.co.uk", True),
        ("dev.acme.com", True),
        ("com", False),
        ("co.uk", False),
        ("", False),
    ],
)
def test_wildcard_base_is_safe(base, safe):
    assert wildcard_base_is_safe(base) is safe


class TestWildcard:
    def test_matches_any_depth_subdomain(self):
        e = E("wildcard", "*.acme.com")
        for h in ("www.acme.com", "a.b.c.acme.com", "api.acme.com"):
            assert match_entry(e, parse_target(h))

    def test_apex_excluded_by_default(self):
        e = E("wildcard", "*.acme.com")
        assert not match_entry(e, parse_target("acme.com"))
        assert match_entry(e, parse_target("acme.com"), includes_apex=True)

    def test_does_not_cross_to_sibling_or_parent(self):
        e = E("wildcard", "*.acme.com")
        assert not match_entry(e, parse_target("acme.com.evil.com"))
        assert not match_entry(e, parse_target("notacme.com"))
        assert not match_entry(e, parse_target("acmexcom"))

    def test_never_crosses_etld(self):
        # even if someone sneaks a bad rule in, a *.co.uk rule must not match a
        # random other .co.uk domain as if it were "in scope for the whole eTLD"
        e = E("wildcard", "*.acme.co.uk")
        assert match_entry(e, parse_target("shop.acme.co.uk"))
        assert not match_entry(e, parse_target("bank.co.uk"))


class TestDomain:
    def test_exact_only(self):
        e = E("domain", "acme.com")
        assert match_entry(e, parse_target("acme.com"))
        assert match_entry(e, parse_target("https://acme.com/x"))
        assert not match_entry(e, parse_target("www.acme.com"))


class TestUrl:
    def test_path_prefix(self):
        e = E("url", "https://api.acme.com/v2")
        assert match_entry(e, parse_target("https://api.acme.com/v2/users"))
        assert not match_entry(e, parse_target("https://api.acme.com/v1"))

    def test_scheme_sensitive(self):
        e = E("url", "https://api.acme.com/")
        assert not match_entry(e, parse_target("http://api.acme.com/x"))

    def test_host_only_target_allows_but_deny_needs_whole_host(self):
        allow = E("url", "https://api.acme.com/v2", in_scope=True)
        deny = E("url", "https://api.acme.com/v2", in_scope=False)
        assert match_entry(allow, parse_target("api.acme.com"))
        assert not match_entry(deny, parse_target("api.acme.com"))


class TestIpAndCidr:
    def test_ip_exact(self):
        assert match_entry(E("ip", "1.2.3.4"), parse_target("1.2.3.4"))
        assert not match_entry(E("ip", "1.2.3.4"), parse_target("1.2.3.5"))

    def test_cidr_contains(self):
        e = E("cidr", "10.0.0.0/8")
        assert match_entry(e, parse_target("10.9.9.9"))
        assert not match_entry(e, parse_target("11.0.0.1"))

    def test_non_ip_target_never_matches_ip_rule(self):
        assert not match_entry(E("cidr", "10.0.0.0/8"), parse_target("acme.com"))

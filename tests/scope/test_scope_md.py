from __future__ import annotations

from gesicht.core.models import ScopeType
from gesicht.scope import scope_md
from gesicht.scope.scope_md import infer_type, parse, parse_bullet

SAMPLE = """\
# Scope - acme

Some preamble.

## In scope

- *.acme.com  (max:critical)
- api.acme.com
- https://shop.acme.com/checkout
- 198.51.100.0/24  (no-bounty)
- com.acme.mobile  (type:mobile-app)
-
- TODO

## Out of scope

- blog.acme.com  # marketing site
- 10.0.0.0/8

## Notes

- remember to throttle
"""


def test_infer_type():
    assert infer_type("*.acme.com") == ScopeType.WILDCARD
    assert infer_type("https://a.com/x") == ScopeType.URL
    assert infer_type("10.0.0.0/8") == ScopeType.CIDR
    assert infer_type("1.2.3.4") == ScopeType.IP
    assert infer_type("api.acme.com") == ScopeType.DOMAIN


def test_parse_sections_and_annotations():
    scope = parse(SAMPLE)
    allow = {e.value: e for e in scope.allow}
    deny = {e.value: e for e in scope.deny}

    assert set(allow) == {
        "*.acme.com",
        "api.acme.com",
        "https://shop.acme.com/checkout",
        "198.51.100.0/24",
        "com.acme.mobile",
    }
    assert allow["*.acme.com"].max_severity == "critical"
    assert allow["198.51.100.0/24"].bounty is False
    assert allow["com.acme.mobile"].type == ScopeType.MOBILE_APP

    assert set(deny) == {"blog.acme.com", "10.0.0.0/8"}
    assert deny["blog.acme.com"].note == "marketing site"
    # the "## Notes" bullet must not leak into scope
    assert "remember to throttle" not in {e.value for e in scope.entries}


def test_placeholder_bullets_are_skipped():
    assert parse_bullet("-", in_scope=True) is None
    assert parse_bullet("", in_scope=True) is None
    assert parse_bullet("TODO", in_scope=True) is None


def test_upsert_preserves_notes_and_merges(tmp_path):
    p = tmp_path / "scope.md"
    p.write_text(SAMPLE)
    from gesicht.core.models import ScopeEntry

    new = [ScopeEntry(type=ScopeType.DOMAIN, value="new.acme.com", in_scope=True)]
    merged = scope_md.upsert_into_file(p, new, title="acme")

    text = p.read_text()
    assert "new.acme.com" in text
    assert "remember to throttle" in text  # Notes section survived
    assert "api.acme.com" in text  # existing entries survived
    assert sum(e.value == "new.acme.com" for e in merged.allow) == 1

    # idempotent
    merged2 = scope_md.upsert_into_file(p, new, title="acme")
    assert sum(e.value == "new.acme.com" for e in merged2.allow) == 1


def test_hg_placeholder_scope_md_parses_empty(tmp_path):
    hg_default = "# Scope - x\n\n## In scope\n\n- \n\n## Out of scope\n\n- \n\n## Notes\n\n- \n"
    scope = parse(hg_default)
    assert scope.entries == []

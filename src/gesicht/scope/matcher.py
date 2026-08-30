"""Low-level rule matching. No policy here - :mod:`gesicht.scope.guard` owns that.

Every function is pure and side-effect free so the property tests in
``tests/scope/`` can hammer it.
"""

from __future__ import annotations

import ipaddress

from publicsuffix2 import get_sld, get_tld

from ..core.models import ScopeEntry, ScopeType
from .model import Target


def is_public_suffix(host: str) -> bool:
    """True if ``host`` is itself a public suffix (``com``, ``co.uk``, ``s3.amazonaws.com``)."""
    host = host.strip(".").lower()
    if not host:
        return True
    if "." not in host:
        return True  # bare TLD
    return get_tld(host, strict=False) == host or get_sld(host) is None


def wildcard_base_is_safe(base: str) -> bool:
    """A ``*.<base>`` wildcard is only safe when ``<base>`` is a real registrable
    domain (or deeper), never a bare eTLD like ``com`` or ``co.uk``."""
    base = base.strip(".").lower()
    return bool(base) and "." in base and not is_public_suffix(base)


def registrable_domain(host: str) -> str | None:
    try:
        return get_sld(host.strip(".").lower())
    except Exception:  # noqa: BLE001 - psl is defensive but never trust it
        return None


# --------------------------------------------------------------------------- #
def _host_in_wildcard(host: str | None, wildcard_value: str, *, includes_apex: bool) -> bool:
    if not host:
        return False
    base = wildcard_value[2:].lower() if wildcard_value.startswith("*.") else wildcard_value.lower()
    host = host.lower()
    if host == base:
        return includes_apex
    return host.endswith("." + base)


def _url_match(rule_value: str, target: Target, *, is_deny: bool) -> bool:
    from urllib.parse import urlsplit

    r = urlsplit(rule_value if "://" in rule_value else "https://" + rule_value)
    r_host = (r.hostname or "").lower()
    r_path = r.path or "/"

    if target.kind == "url":
        if target.host != r_host and target.ip != r_host:
            return False
        if r.scheme and target.scheme and target.scheme != r.scheme:
            return False
        return target.path.startswith(r_path)

    # host-only or ip target: path is unknown
    if (target.hostish or "") != r_host:
        return False
    if is_deny:
        # a path-scoped exclusion must not blanket-deny a whole host
        return r_path == "/"
    return True  # allow: the host is at least partially in scope


def match_entry(entry: ScopeEntry, target: Target, *, includes_apex: bool = False) -> bool:
    """Does a single scope rule cover ``target``?"""
    t = entry.type
    v = entry.value.strip()

    if t == ScopeType.DOMAIN:
        return (target.hostish or "").lower() == v.lower()

    if t == ScopeType.WILDCARD:
        return _host_in_wildcard(target.host, v, includes_apex=includes_apex)

    if t == ScopeType.URL:
        return _url_match(v, target, is_deny=not entry.in_scope)

    if t == ScopeType.IP:
        if target.ip is None:
            return False
        try:
            return ipaddress.ip_address(target.ip) == ipaddress.ip_address(v)
        except ValueError:
            return False

    if t == ScopeType.CIDR:
        if target.ip is None:
            return False
        try:
            return ipaddress.ip_address(target.ip) in ipaddress.ip_network(v, strict=False)
        except ValueError:
            return False

    # mobile-app / source-repo / other: not something a network tool targets
    return False


def first_match(
    entries: list[ScopeEntry], target: Target, *, includes_apex: bool = False
) -> ScopeEntry | None:
    for e in entries:
        if match_entry(e, target, includes_apex=includes_apex):
            return e
    return None

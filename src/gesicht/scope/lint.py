"""Static checks over a ScopeSet - catch dangerous or useless rules early."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..core.models import ScopeEntry, ScopeType
from .matcher import is_public_suffix, wildcard_base_is_safe
from .model import ScopeSet

LEVELS = ("error", "warn", "info")


@dataclass(slots=True)
class LintIssue:
    level: str
    message: str
    entry: ScopeEntry | None = None

    def __str__(self) -> str:
        where = f"  [{self.entry.type}:{self.entry.value}]" if self.entry else ""
        return f"{self.level.upper():5} {self.message}{where}"


def _private_cidr_or_ip(value: str) -> bool:
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False).is_private
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def lint(scope: ScopeSet) -> list[LintIssue]:
    issues: list[LintIssue] = []
    apex_setting = bool(scope.setting("wildcard_includes_apex"))

    if not scope.allow:
        issues.append(LintIssue("warn", "no in-scope rules - every target will be rejected"))

    seen: dict[tuple[str, str, bool], ScopeEntry] = {}
    allow_values = {e.value.lower() for e in scope.allow}
    deny_values = {e.value.lower() for e in scope.deny}

    for e in scope.entries:
        key = (e.type, e.value.lower(), e.in_scope)
        if key in seen:
            issues.append(LintIssue("info", "duplicate rule", e))
        seen[key] = e

        if e.type == ScopeType.WILDCARD:
            base = e.value[2:] if e.value.startswith("*.") else e.value
            if not wildcard_base_is_safe(base):
                issues.append(
                    LintIssue(
                        "error",
                        f"wildcard base '{base}' is a public suffix / bare TLD - this would "
                        "put a huge shared namespace in scope",
                        e,
                    )
                )
            elif e.in_scope and not apex_setting and f"{base}".lower() not in allow_values:
                issues.append(
                    LintIssue(
                        "info",
                        f"apex '{base}' is NOT covered by '*.{base}' (wildcard_includes_apex "
                        "is off) - add it explicitly if it should be tested",
                        e,
                    )
                )

        if e.type == ScopeType.DOMAIN and is_public_suffix(e.value):
            issues.append(
                LintIssue("error", f"'{e.value}' is a public suffix, not a single asset", e)
            )

        if e.in_scope and e.type in {ScopeType.IP, ScopeType.CIDR} and _private_cidr_or_ip(e.value):
            issues.append(
                LintIssue(
                    "warn",
                    "private (RFC1918) range in scope - usually unreachable and a sign of a "
                    "copy-paste error",
                    e,
                )
            )

        if e.in_scope and e.value.lower() in deny_values:
            issues.append(
                LintIssue("error", "same value appears in both in-scope and out-of-scope", e)
            )

    return issues


def worst_level(issues: list[LintIssue]) -> str | None:
    for lvl in LEVELS:
        if any(i.level == lvl for i in issues):
            return lvl
    return None

"""The scope chokepoint.

``ScopeGuard.check()`` is pure and returns a decision per target.
``ScopeGuard.authorize()`` adds the side effects the orchestrator needs: it
appends every rejected target to ``.gesicht/violations.log`` and raises
:class:`~gesicht.core.errors.ScopeViolation` (exit code 2).

Policy, in order:
  1. a matching **deny** rule always wins  -> OUT
  2. otherwise a matching **allow** rule    -> IN
  3. otherwise (no rule matches)            -> OUT   (fail closed)
  4. for an ACTIVE action, if the host resolves to an IP covered by a deny
     ip/cidr rule                            -> OUT   (shared-infra trap)
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..core.errors import ScopeViolation
from ..core.models import Activity, ScopeEntry, ScopeType
from .matcher import first_match
from .model import ScopeSet, Target, parse_target

Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos})


@dataclass(slots=True)
class ScopeDecision:
    target: str
    allowed: bool
    reason: str
    activity: Activity = Activity.PASSIVE
    matched_rule: ScopeEntry | None = None
    requires_confirmation: bool = False
    resolved_ips: list[str] = field(default_factory=list)

    def rule_str(self) -> str:
        r = self.matched_rule
        return f"{r.type}:{r.value}" if r else "-"


class ScopeGuard:
    def __init__(self, scope: ScopeSet, *, resolver: Resolver | None = None) -> None:
        self.scope = scope
        self._resolver = resolver or _default_resolver

    # -- pure ----------------------------------------------------------- #
    def check_one(
        self,
        raw_target: str,
        activity: Activity = Activity.PASSIVE,
        *,
        resolve: bool = True,
    ) -> ScopeDecision:
        target = parse_target(raw_target)
        allow_apex = bool(self.scope.setting("wildcard_includes_apex"))
        # Deny is always maximal: a deny wildcard blocks its apex too, regardless
        # of the setting.
        deny_hit = first_match(self.scope.deny, target, includes_apex=True)
        if deny_hit:
            return ScopeDecision(
                raw_target, False,
                f"matches out-of-scope rule {deny_hit.type}:{deny_hit.value}",
                activity, deny_hit,
            )

        allow_hit = first_match(self.scope.allow, target, includes_apex=allow_apex)
        if not allow_hit:
            return ScopeDecision(
                raw_target, False,
                "no scope rule matches this target (fail-closed)",
                activity, None,
            )

        decision = ScopeDecision(
            raw_target, True,
            f"in scope via {allow_hit.type}:{allow_hit.value}",
            activity, allow_hit,
            requires_confirmation=(activity == Activity.ACTIVE),
        )

        if resolve and activity == Activity.ACTIVE and self.scope.setting("resolve_before_active"):
            self._apply_resolution_guard(target, decision)
        return decision

    def _apply_resolution_guard(self, target: Target, decision: ScopeDecision) -> None:
        if target.kind not in {"host", "url"} or not target.host:
            return
        ips = self._resolver(target.host)
        decision.resolved_ips = ips
        ip_rules = [e for e in self.scope.deny if e.type in {ScopeType.IP, ScopeType.CIDR}]
        for ip in ips:
            hit = first_match(ip_rules, parse_target(ip))
            if hit:
                decision.allowed = False
                decision.requires_confirmation = False
                decision.matched_rule = hit
                decision.reason = (
                    f"host resolves to {ip}, which matches out-of-scope rule "
                    f"{hit.type}:{hit.value}"
                )
                return

    def check(
        self,
        targets: Iterable[str] | str,
        activity: Activity = Activity.PASSIVE,
        *,
        resolve: bool = True,
    ) -> list[ScopeDecision]:
        if isinstance(targets, str):
            targets = [targets]
        return [self.check_one(t, activity, resolve=resolve) for t in targets]

    # -- side-effecting ----------------------------------------------------- #
    def authorize(
        self,
        targets: Iterable[str] | str,
        activity: Activity = Activity.PASSIVE,
        *,
        violations_log: Path | None = None,
        actor: str = "gesicht",
    ) -> list[ScopeDecision]:
        """Return decisions, logging and raising on the first out-of-scope target."""
        decisions = self.check(targets, activity)
        bad = [d for d in decisions if not d.allowed]
        if bad and violations_log is not None:
            _log_violations(violations_log, bad, actor)
        if bad:
            d = bad[0]
            raise ScopeViolation(d.target, d.reason)
        return decisions


def _log_violations(path: Path, decisions: list[ScopeDecision], actor: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    with path.open("a") as fh:
        for d in decisions:
            fh.write(
                f"{ts}\t{actor}\t{d.activity}\t{d.target}\t{d.rule_str()}\t{d.reason}\n"
            )

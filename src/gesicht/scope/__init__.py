"""Fail-closed scope safety - the chokepoint every active action passes through.

A target that matches no rule is OUT of scope. A deny rule always beats an allow
rule. Nothing in :mod:`gesicht.tools` may launch a process without a
:class:`~gesicht.scope.guard.ScopeDecision` from :func:`~gesicht.scope.guard.ScopeGuard.check`.
"""

from .guard import ScopeDecision, ScopeGuard
from .model import ScopeSet

__all__ = ["ScopeDecision", "ScopeGuard", "ScopeSet"]

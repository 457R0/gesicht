"""Scope data structures and target parsing."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..core.models import ScopeEntry, ScopeType, to_dict

DEFAULT_SETTINGS: dict[str, Any] = {
    # Most HackerOne programs intend ``*.acme.com`` to include the apex
    # ``acme.com``, so that is the default. Set to false for a program whose
    # policy explicitly excludes the apex; `gesicht scope lint` will remind you the
    # apex is uncovered in that case.
    "wildcard_includes_apex": True,
    # Before an ACTIVE action, resolve the hostname and re-check every resolved
    # IP against deny ip/cidr rules (catches shared-infra traps).
    "resolve_before_active": True,
    # ``gesicht recon`` runs only passive adapters unless told otherwise.
    "passive_default": True,
}


@dataclass(slots=True)
class Target:
    """A parsed thing we might point a tool at."""

    raw: str
    kind: str  # "ip" | "host" | "url"
    host: str | None = None
    ip: str | None = None
    scheme: str | None = None
    path: str = "/"

    @property
    def hostish(self) -> str | None:
        """The host or IP to match host/domain/ip rules against."""
        return self.ip or self.host


def parse_target(value: str) -> Target:
    value = value.strip()
    if "://" in value:
        parts = urlsplit(value)
        host = parts.hostname or ""
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            ip = None
        return Target(
            raw=value,
            kind="url",
            host=None if ip else host.lower(),
            ip=ip,
            scheme=parts.scheme.lower(),
            path=parts.path or "/",
        )
    try:
        ip = str(ipaddress.ip_address(value))
        return Target(raw=value, kind="ip", ip=ip)
    except ValueError:
        pass
    # strip an accidental :port on a bare host
    host = value.split("/", 1)[0]
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":", 1)[0]
    return Target(raw=value, kind="host", host=host.lower())


@dataclass(slots=True)
class ScopeSet:
    entries: list[ScopeEntry] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_SETTINGS))
    program: str | None = None
    imported_from: str | None = None
    imported_at: str | None = None

    @property
    def allow(self) -> list[ScopeEntry]:
        return [e for e in self.entries if e.in_scope]

    @property
    def deny(self) -> list[ScopeEntry]:
        return [e for e in self.entries if not e.in_scope]

    def setting(self, key: str) -> Any:
        return self.settings.get(key, DEFAULT_SETTINGS.get(key))

    def add(self, entry: ScopeEntry) -> bool:
        """Add an entry unless an identical one is already present."""
        if any(e.id == entry.id for e in self.entries):
            return False
        self.entries.append(entry)
        return True

    def remove(self, value: str, *, in_scope: bool | None = None) -> int:
        before = len(self.entries)
        self.entries = [
            e
            for e in self.entries
            if not (e.value == value and (in_scope is None or e.in_scope == in_scope))
        ]
        return before - len(self.entries)

    # -- persistence (.gesicht/scope.json) ---------------------------------- #
    def to_json(self) -> str:
        return json.dumps(
            {
                "program": self.program,
                "imported_from": self.imported_from,
                "imported_at": self.imported_at,
                "settings": self.settings,
                "rules": [to_dict(e) for e in self.entries],
            },
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> ScopeSet:
        data = json.loads(text)
        entries = [
            ScopeEntry(
                type=ScopeType(r["type"]),
                value=r["value"],
                in_scope=r.get("in_scope", True),
                bounty=r.get("bounty", True),
                max_severity=r.get("max_severity"),
                source=r.get("source", "scope.json"),
                note=r.get("note"),
            )
            for r in data.get("rules", [])
        ]
        settings = dict(DEFAULT_SETTINGS)
        settings.update(data.get("settings", {}))
        return cls(
            entries=entries,
            settings=settings,
            program=data.get("program"),
            imported_from=data.get("imported_from"),
            imported_at=data.get("imported_at"),
        )

    def write_cache(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(self.to_json())
        tmp.replace(path)

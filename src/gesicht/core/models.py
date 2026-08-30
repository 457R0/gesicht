"""Normalized entities shared by every layer of gesicht.

Plain stdlib dataclasses (no pydantic - its Rust core lags new CPython, and
Kali ships Python 3.14). Validation that matters lives in ``scope/`` and the
tool adapters; these types are mostly structured records with a deterministic
``id`` and a couple of convenience constructors.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, StrEnum
from typing import Any

from .ids import entity_id


def utcnow() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses / enums / datetimes into JSON-safe data."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_dict(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (list, tuple, set)):
        return [to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
class ScopeType(StrEnum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    MOBILE_APP = "mobile-app"
    SOURCE_REPO = "source-repo"
    OTHER = "other"


class Activity(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


@dataclass(slots=True)
class ScopeEntry:
    type: ScopeType
    value: str
    in_scope: bool = True
    bounty: bool = True
    max_severity: str | None = None
    source: str = "scope.md"
    note: str | None = None

    @property
    def id(self) -> str:
        return entity_id("scope", self.type, self.value, self.in_scope)


# --------------------------------------------------------------------------- #
# Recon entities
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Host:
    hostname: str
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    in_scope: bool | None = None
    tags: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow)
    last_seen: str = field(default_factory=utcnow)

    @property
    def id(self) -> str:
        return entity_id("host", self.hostname)


@dataclass(slots=True)
class Service:
    host: str
    ip: str
    port: int
    proto: str = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    source: str | None = None
    tls: dict[str, Any] | None = None

    @property
    def id(self) -> str:
        return entity_id("service", self.ip, self.port, self.proto)


@dataclass(slots=True)
class Endpoint:
    url: str
    method: str = "GET"
    host: str = ""
    path_signature: str = ""
    status: int | None = None
    length: int | None = None
    content_type: str | None = None
    title: str | None = None
    tech: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    screenshot_ref: str | None = None
    in_scope: bool | None = None

    @property
    def id(self) -> str:
        return entity_id("endpoint", self.method, self.url)


class ParamLoc(StrEnum):
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


@dataclass(slots=True)
class Param:
    endpoint_id: str
    name: str
    location: ParamLoc = ParamLoc.QUERY
    example_value: str | None = None
    reflected: bool = False
    discovered_by: str | None = None

    @property
    def id(self) -> str:
        return entity_id("param", self.endpoint_id, self.location, self.name)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
class FindingStatus(StrEnum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "n/a"


SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def severity_rank(sev: str | None) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return 0


@dataclass(slots=True)
class VulnHit:
    """A raw scanner observation, before a human turns it into a Finding."""

    scanner: str
    signature: str  # template-id / check-id
    name: str
    severity: str = "info"
    url: str = ""
    host: str = ""
    cwe: str | None = None
    cve: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    tags: list[str] = field(default_factory=list)
    description: str = ""
    extracted: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    raw_ref: str | None = None
    seen_at: str = field(default_factory=utcnow)

    @property
    def id(self) -> str:
        return entity_id("vuln", self.scanner, self.signature, self.url or self.host)


@dataclass(slots=True)
class Finding:
    number: int
    slug: str
    title: str
    target: str
    program: str = ""
    vuln_class: str | None = None  # CWE id, e.g. "CWE-89"
    weakness: str | None = None
    severity: str | None = None  # info/low/medium/high/critical
    cvss_vector: str | None = None
    cvss_score: float | None = None
    status: FindingStatus = FindingStatus.DRAFT
    summary: str = ""
    steps_to_reproduce: str = ""
    poc: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    found_via: str | None = None
    #: opaque key used to avoid drafting the same scanner hit twice
    source_key: str | None = None
    h1_report_id: str | None = None
    created: str = field(default_factory=utcnow)
    updated: str = field(default_factory=utcnow)

    @property
    def fid(self) -> str:
        return f"{self.number:04d}"

    @property
    def filename(self) -> str:
        return f"{self.fid}-{self.slug}.md"


# --------------------------------------------------------------------------- #
# Tool bookkeeping
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ToolRun:
    tool: str
    argv: list[str]
    targets: list[str]
    activity: Activity
    version: str | None = None
    scope_decision: str | None = None
    fallback_for: str | None = None
    started_at: str = field(default_factory=utcnow)
    ended_at: str | None = None
    exit_code: int | None = None
    raw_stdout_path: str | None = None
    raw_stderr_path: str | None = None
    records_emitted: int = 0

    @property
    def id(self) -> str:
        return entity_id("run", self.tool, self.started_at, *self.targets)

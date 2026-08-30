"""Import scope from HackerOne.

Two inputs are supported:

* **structured JSON** - the body of
  ``GET /v1/hackers/programs/{handle}/structured_scopes`` (or the ``data`` list
  from it, or a single object). This is the reliable path.
* **pasted text** - whatever the user copied off the program's scope table.
  Best-effort: one asset per line, type inferred, ``#``/``(...)`` annotations
  honoured just like ``scope.md``.

No network calls happen here - fetching the JSON (with ``GESICHT_H1_TOKEN``) is the
command layer's job.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from ..core.models import ScopeEntry, ScopeType
from .model import ScopeSet
from .scope_md import parse_bullet

# HackerOne asset_type -> our ScopeType
_ASSET_TYPE = {
    "URL": ScopeType.URL,
    "WILDCARD": ScopeType.WILDCARD,
    "CIDR": ScopeType.CIDR,
    "IP_ADDRESS": ScopeType.IP,
    "DOMAIN": ScopeType.DOMAIN,
    "GOOGLE_PLAY_APP_ID": ScopeType.MOBILE_APP,
    "APPLE_STORE_APP_ID": ScopeType.MOBILE_APP,
    "WINDOWS_APP_STORE_APP_ID": ScopeType.MOBILE_APP,
    "TESTFLIGHT": ScopeType.MOBILE_APP,
    "OTHER_APK": ScopeType.MOBILE_APP,
    "OTHER_IPA": ScopeType.MOBILE_APP,
    "SOURCE_CODE": ScopeType.SOURCE_REPO,
}


def _iter_structured(payload: object):
    if isinstance(payload, dict) and "data" in payload:
        yield from payload["data"]
    elif isinstance(payload, list):
        yield from payload
    elif isinstance(payload, dict):
        yield payload


def from_structured_json(text: str, *, handle: str | None = None) -> ScopeSet:
    payload = json.loads(text)
    entries: list[ScopeEntry] = []
    for item in _iter_structured(payload):
        attrs = item.get("attributes", item) if isinstance(item, dict) else {}
        ident = (attrs.get("asset_identifier") or attrs.get("identifier") or "").strip()
        if not ident:
            continue
        atype = (attrs.get("asset_type") or "").upper()
        stype = _ASSET_TYPE.get(atype, ScopeType.OTHER)
        # H1 often stores wildcards as DOMAIN with a leading '*.'
        if stype == ScopeType.DOMAIN and ident.startswith("*."):
            stype = ScopeType.WILDCARD
        in_scope = bool(attrs.get("eligible_for_submission", True))
        entries.append(
            ScopeEntry(
                type=stype,
                value=ident.rstrip("/") if stype != ScopeType.URL else ident,
                in_scope=in_scope,
                bounty=bool(attrs.get("eligible_for_bounty", in_scope)),
                max_severity=(attrs.get("max_severity") or None),
                source="h1-api",
                note=(attrs.get("instruction") or "").strip()[:200] or None,
            )
        )
    return ScopeSet(
        entries=entries,
        program=handle,
        imported_from="h1-api",
        imported_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


def from_pasted_text(text: str, *, handle: str | None = None, in_scope: bool = True) -> ScopeSet:
    entries: list[ScopeEntry] = []
    for line in text.splitlines():
        # strip a leading bullet marker ("- ", "* ", "+ ") but never a bare
        # wildcard asterisk in "*.example.com"
        s = re.sub(r"^\s*[-*+]\s+", "", line).strip()
        if not s or s.startswith(("#", "//")) or s.lower() in {"in scope", "out of scope"}:
            continue
        # a two-column "value <spaces/tab> TYPE" paste
        forced = None
        parts = s.split("\t") if "\t" in s else s.rsplit("  ", 1)
        if len(parts) == 2 and parts[1].strip().upper() in _ASSET_TYPE:
            s = parts[0].strip()
            forced = _ASSET_TYPE[parts[1].strip().upper()]
        entry = parse_bullet(s, in_scope=in_scope, source="h1-paste")
        if entry:
            if forced:
                entry.type = forced
            entries.append(entry)
    return ScopeSet(
        entries=entries,
        program=handle,
        imported_from="h1-paste",
        imported_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )

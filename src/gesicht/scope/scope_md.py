"""Read and write the ``## In scope`` / ``## Out of scope`` lists in ``scope.md``.

``scope.md`` in the workspace root stays the human-editable source of truth.
``.gesicht/scope.json`` is a derived cache refreshed whenever we parse it.

Bullet grammar (all optional except the value)::

    - <value>                              e.g. *.acme.com
    - <value> (bounty, max:critical)       parenthetical annotations
    - <value> (type:mobile-app)            force the type
    - <value>  # free-form trailing note

Recognised annotation tokens: ``bounty`` / ``no-bounty``,
``max:<sev>`` / ``max-severity:<sev>``, ``type:<scope-type>``. Anything else
becomes the entry's note.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from ..core.models import ScopeEntry, ScopeType
from .model import DEFAULT_SETTINGS, ScopeSet

_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$")
_BULLET = re.compile(r"^\s*[-*+]\s+(.*\S)\s*$")
_IN_ALIASES = {"in scope", "in-scope", "inscope", "scope", "targets", "assets"}
_OUT_ALIASES = {"out of scope", "out-of-scope", "outofscope", "not in scope", "excluded"}


def infer_type(value: str) -> ScopeType:
    v = value.strip()
    if v.startswith(("http://", "https://")) or ("://" in v):
        return ScopeType.URL
    if v.startswith("*."):
        return ScopeType.WILDCARD
    if "/" in v:
        head = v.split("/", 1)[0]
        try:
            ipaddress.ip_network(v, strict=False)
            return ScopeType.CIDR
        except ValueError:
            if _is_ip(head):
                return ScopeType.CIDR
            return ScopeType.URL
    if _is_ip(v):
        return ScopeType.IP
    if v.count(".") >= 1 and re.fullmatch(r"[A-Za-z0-9.\-_]+", v):
        return ScopeType.DOMAIN
    if re.fullmatch(r"[a-z]+(\.[a-z0-9]+){2,}", v):  # com.example.app
        return ScopeType.MOBILE_APP
    return ScopeType.OTHER


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse_bullet(text: str, *, in_scope: bool, source: str = "scope.md") -> ScopeEntry | None:
    """Turn one bullet's text into a ScopeEntry, or None for an empty placeholder."""
    note: str | None = None
    if "#" in text and not text.startswith("#"):
        text, _, trailing = text.partition("#")
        note = trailing.strip() or None
    text = text.strip()

    forced_type: ScopeType | None = None
    bounty = in_scope  # default: in-scope assets are bounty-eligible unless said otherwise
    max_sev: str | None = None

    m = re.search(r"\(([^)]*)\)\s*$", text)
    if m:
        text = text[: m.start()].strip()
        for tok in (t.strip() for t in m.group(1).split(",")):
            low = tok.lower()
            if low in {"bounty", "eligible"}:
                bounty = True
            elif low in {"no-bounty", "nobounty", "no bounty", "vdp"}:
                bounty = False
            elif low.startswith(("max:", "max-severity:", "maxseverity:")):
                max_sev = low.split(":", 1)[1].strip() or None
            elif low.startswith("type:"):
                try:
                    forced_type = ScopeType(low.split(":", 1)[1].strip())
                except ValueError:
                    forced_type = None
            elif tok:
                note = f"{note}; {tok}" if note else tok

    value = text.strip().rstrip("/") if text.strip() != "/" else text.strip()
    if not value or value in {"-", "TODO", "..."}:
        return None

    return ScopeEntry(
        type=forced_type or infer_type(value),
        value=value,
        in_scope=in_scope,
        bounty=bounty,
        max_severity=max_sev,
        source=source,
        note=note,
    )


def parse(md_text: str) -> ScopeSet:
    section: str | None = None
    entries: list[ScopeEntry] = []
    for line in md_text.splitlines():
        h = _HEADING.match(line)
        if h:
            name = h.group(1).strip().lower()
            if name in _IN_ALIASES:
                section = "in"
            elif name in _OUT_ALIASES:
                section = "out"
            else:
                section = None
            continue
        if section is None:
            continue
        b = _BULLET.match(line)
        if not b:
            continue
        entry = parse_bullet(b.group(1), in_scope=(section == "in"))
        if entry:
            entries.append(entry)
    return ScopeSet(entries=entries, settings=dict(DEFAULT_SETTINGS))


def load(scope_md: Path) -> ScopeSet:
    if not scope_md.is_file():
        return ScopeSet()
    return parse(scope_md.read_text())


# --------------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------------- #
def _format_entry(e: ScopeEntry) -> str:
    ann: list[str] = []
    if e.in_scope and not e.bounty:
        ann.append("no-bounty")
    if e.max_severity:
        ann.append(f"max:{e.max_severity}")
    if e.type in {ScopeType.MOBILE_APP, ScopeType.SOURCE_REPO, ScopeType.OTHER}:
        ann.append(f"type:{e.type}")
    line = f"- {e.value}"
    if ann:
        line += f"  ({', '.join(ann)})"
    if e.note:
        line += f"  # {e.note}"
    return line


def render(scope: ScopeSet, *, title: str | None = None) -> str:
    out: list[str] = []
    if title:
        out += [f"# Scope - {title}", ""]
    out += ["## In scope", ""]
    out += [_format_entry(e) for e in scope.allow] or ["- "]
    out += ["", "## Out of scope", ""]
    out += [_format_entry(e) for e in scope.deny] or ["- "]
    out += ["", "## Notes", "", "- "]
    return "\n".join(out) + "\n"


def upsert_into_file(
    scope_md: Path, new_entries: list[ScopeEntry], *, title: str | None = None
) -> ScopeSet:
    """Merge ``new_entries`` into scope.md, preserving anything already there and
    any non-scope sections (## Notes, etc.)."""
    existing = load(scope_md)
    for e in new_entries:
        existing.add(e)

    if not scope_md.is_file():
        scope_md.write_text(render(existing, title=title or scope_md.parent.name))
        return existing

    # rebuild only the two scope sections; leave everything else verbatim
    lines = scope_md.read_text().splitlines()
    result: list[str] = []
    i = 0
    handled_in = handled_out = False
    while i < len(lines):
        h = _HEADING.match(lines[i])
        name = h.group(1).strip().lower() if h else None
        if name in _IN_ALIASES:
            result.append(lines[i])
            result.append("")
            result += [_format_entry(e) for e in existing.allow] or ["- "]
            handled_in = True
            i += 1
            while i < len(lines) and not _HEADING.match(lines[i]):
                i += 1
            if i < len(lines):
                result.append("")
            continue
        if name in _OUT_ALIASES:
            result.append(lines[i])
            result.append("")
            result += [_format_entry(e) for e in existing.deny] or ["- "]
            handled_out = True
            i += 1
            while i < len(lines) and not _HEADING.match(lines[i]):
                i += 1
            if i < len(lines):
                result.append("")
            continue
        result.append(lines[i])
        i += 1

    if not handled_in:
        body = [_format_entry(e) for e in existing.allow] or ["- "]
        result += ["", "## In scope", "", *body]
    if not handled_out:
        body = [_format_entry(e) for e in existing.deny] or ["- "]
        result += ["", "## Out of scope", "", *body]

    scope_md.write_text("\n".join(result).rstrip() + "\n")
    return existing

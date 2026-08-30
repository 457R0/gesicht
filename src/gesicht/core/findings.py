"""The findings store: one Markdown file per bug under ``findings/``.

File shape: YAML frontmatter (all :class:`~gesicht.core.models.Finding` metadata)
followed by ``## <Section>`` headings that map to the free-text fields. The
SQLite ``finding`` table + ``finding_fts`` index are derived from these files.
"""

from __future__ import annotations

import re
from dataclasses import fields
from functools import lru_cache
from pathlib import Path

import yaml

from .ids import dash_slug
from .models import (
    Finding,
    FindingStatus,
    VulnHit,
    severity_rank,
    to_dict,
    utcnow,
)
from .workspace import Workspace

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.S)
_SECTION = re.compile(r"^##\s+(.+?)\s*$", re.M)

# section heading  <->  Finding field
_SECTION_FIELD = {
    "summary": "summary",
    "steps to reproduce": "steps_to_reproduce",
    "proof of concept": "poc",
    "poc": "poc",
    "impact": "impact",
    "remediation": "remediation",
}
_LIST_SECTIONS = {"supporting material / references", "references", "supporting material"}
_META_FIELDS = {f.name for f in fields(Finding)}


# --------------------------------------------------------------------------- #
# severity map
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _severity_map() -> dict:
    p = Path(__file__).resolve().parent.parent / "data" / "severity_map.yml"
    return yaml.safe_load(p.read_text()) if p.is_file() else {}


def normalize_severity(sev: str | None) -> str:
    s = (sev or "info").strip().lower()
    return _severity_map().get("severity_aliases", {}).get(s, s)


def weakness_for_tags(tags: list[str]) -> tuple[str | None, str | None]:
    """Return (cwe, weakness) for the first recognised tag."""
    tw = _severity_map().get("tag_weakness", {})
    for t in tags:
        info = tw.get(t.lower())
        if info:
            return info.get("cwe"), info.get("weakness")
    return None, None


def scanner_default_severity(scanner: str) -> str:
    return _severity_map().get("scanner_default_severity", {}).get(scanner, "info")


# --------------------------------------------------------------------------- #
# parse / render
# --------------------------------------------------------------------------- #
def parse_finding(text: str) -> Finding:
    m = _FRONTMATTER.match(text)
    if not m:
        raise ValueError("finding file has no YAML frontmatter")
    meta = yaml.safe_load(m.group(1)) or {}
    body = m.group(2)

    kw = {k: v for k, v in meta.items() if k in _META_FIELDS}
    if "status" in kw and kw["status"] is not None:
        kw["status"] = FindingStatus(str(kw["status"]))
    kw.setdefault("number", 0)
    kw.setdefault("slug", dash_slug(str(meta.get("title", "finding"))))
    kw.setdefault("title", "untitled")
    kw.setdefault("target", "")

    # body sections
    parts = _SECTION.split(body)
    # parts = [pre, head1, text1, head2, text2, ...]
    it = iter(parts[1:])
    for head, chunk in zip(it, it, strict=False):
        key = head.strip().lower()
        chunk = chunk.strip()
        if key in _LIST_SECTIONS:
            kw["references"] = [
                ln.strip("-* ").strip() for ln in chunk.splitlines() if ln.strip("-* ").strip()
            ]
        elif key in _SECTION_FIELD:
            kw[_SECTION_FIELD[key]] = chunk
    return Finding(**kw)


def render_finding(f: Finding) -> str:
    meta = {
        "number": f.number,
        "slug": f.slug,
        "title": f.title,
        "target": f.target,
        "program": f.program,
        "vuln_class": f.vuln_class,
        "weakness": f.weakness,
        "severity": f.severity,
        "cvss_vector": f.cvss_vector,
        "cvss_score": f.cvss_score,
        "status": f.status.value if isinstance(f.status, FindingStatus) else f.status,
        "found_via": f.found_via,
        "source_key": f.source_key,
        "evidence": f.evidence,
        "h1_report_id": f.h1_report_id,
        "created": f.created,
        "updated": f.updated,
    }
    meta = {k: v for k, v in meta.items() if v not in (None, "", [], {})}
    fm = yaml.safe_dump(meta, sort_keys=False).strip()

    refs = "\n".join(f"- {r}" for r in f.references) or "- "
    return (
        f"---\n{fm}\n---\n\n"
        f"## Summary\n\n{f.summary or ''}\n\n"
        f"## Steps to Reproduce\n\n{f.steps_to_reproduce or ''}\n\n"
        f"## Proof of Concept\n\n{f.poc or ''}\n\n"
        f"## Impact\n\n{f.impact or ''}\n\n"
        f"## Remediation\n\n{f.remediation or ''}\n\n"
        f"## Supporting Material / References\n\n{refs}\n"
    )


# --------------------------------------------------------------------------- #
# store
# --------------------------------------------------------------------------- #
class FindingStore:
    def __init__(self, ws: Workspace) -> None:
        self.ws = ws
        self.dir = ws.findings_dir

    def _files(self) -> list[Path]:
        return sorted(p for p in self.dir.glob("*.md") if p.name[0].isdigit())

    def list(self) -> list[Finding]:
        out = []
        for p in self._files():
            try:
                out.append(parse_finding(p.read_text()))
            except (ValueError, yaml.YAMLError):
                continue
        return sorted(out, key=lambda f: f.number)

    def next_number(self) -> int:
        nums = [f.number for f in self.list()]
        return (max(nums) + 1) if nums else 1

    def path_for(self, f: Finding) -> Path:
        return self.dir / f.filename

    def get(self, key: str) -> Finding | None:
        for f in self.list():
            if key in (str(f.number), f.fid, f.slug) or f.filename == key:
                return f
        return None

    def save(self, f: Finding, *, touch: bool = True) -> Path:
        if touch:
            f.updated = utcnow()
        self.dir.mkdir(parents=True, exist_ok=True)
        p = self.path_for(f)
        tmp = p.with_suffix(".md.tmp")
        tmp.write_text(render_finding(f))
        tmp.replace(p)
        self._index(f)
        return p

    def create(self, title: str, **kw) -> Finding:
        f = Finding(
            number=self.next_number(),
            slug=dash_slug(title),
            title=title,
            target=kw.pop("target", ""),
            program=kw.pop("program", self.ws.slug),
            **{k: v for k, v in kw.items() if k in _META_FIELDS},
        )
        self.save(f, touch=False)
        return f

    def has_source_key(self, key: str) -> bool:
        return any(f.source_key == key for f in self.list())

    # -- db sync ------------------------------------------------------------- #
    def _index(self, f: Finding) -> None:
        from . import db as _db

        conn = _db.connect(self.ws.index_db)
        try:
            with conn:
                row = to_dict(f)
                cols = [
                    "number", "slug", "title", "target", "program", "vuln_class",
                    "weakness", "severity", "cvss_vector", "cvss_score", "status",
                    "found_via", "h1_report_id", "created", "updated", "path", "source_key",
                ]
                row["path"] = str(self.path_for(f))
                conn.execute(
                    f"INSERT OR REPLACE INTO finding ({', '.join(cols)}) "
                    f"VALUES ({', '.join('?' for _ in cols)})",
                    [row.get(c) for c in cols],
                )
                conn.execute("DELETE FROM finding_fts WHERE number = ?", (f.number,))
                conn.execute(
                    "INSERT INTO finding_fts (number, title, body) VALUES (?, ?, ?)",
                    (f.number, f.title, "\n".join(
                        [f.summary, f.steps_to_reproduce, f.poc, f.impact, f.remediation]
                    )),
                )
        finally:
            conn.close()

    def reindex(self) -> int:
        n = 0
        for f in self.list():
            self._index(f)
            n += 1
        return n


# --------------------------------------------------------------------------- #
# auto-draft from a scanner hit
# --------------------------------------------------------------------------- #
def draft_from_vuln(hit: VulnHit, *, program: str) -> Finding:
    sev = normalize_severity(hit.severity) or scanner_default_severity(hit.scanner)
    cwe, weakness = hit.cwe, None
    if not cwe:
        cwe, weakness = weakness_for_tags(hit.tags + [hit.signature])
    title = f"{hit.name} — {hit.host or hit.url}".strip(" —")

    poc = "\n".join(hit.extracted) if hit.extracted else ""
    steps = (
        f"Detected by `{hit.scanner}` (`{hit.signature}`).\n\n"
        f"Request / location:\n\n    {hit.url or hit.host}\n"
    )
    refs = list(dict.fromkeys(hit.reference + [f"CVE: {c}" for c in hit.cve]))

    return Finding(
        number=0,
        slug=dash_slug(title),
        title=title[:180],
        target=hit.url or hit.host,
        program=program,
        vuln_class=cwe,
        weakness=weakness,
        severity=sev,
        cvss_vector=hit.cvss_vector,
        cvss_score=hit.cvss_score,
        status=FindingStatus.DRAFT,
        summary=hit.description or hit.name,
        steps_to_reproduce=steps,
        poc=poc,
        references=refs,
        found_via=hit.scanner,
        source_key=hit.id,
    )


def worst_severity(hits: list[VulnHit]) -> str:
    return max((h.severity for h in hits), key=severity_rank, default="info")


__all__ = [
    "FindingStore",
    "parse_finding",
    "render_finding",
    "draft_from_vuln",
    "normalize_severity",
    "weakness_for_tags",
    "scanner_default_severity",
    "worst_severity",
]

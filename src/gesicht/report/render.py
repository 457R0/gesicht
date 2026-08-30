"""Render a Finding into a report via Jinja templates.

Template lookup: a workspace's ``reports/templates/`` overrides the packaged
``gesicht/report/templates/``.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, select_autoescape

from ..core.errors import UsageError
from ..core.models import Finding
from .cvss import parse_cvss
from .redact import redact, redact_findings_evidence

_PKG_TEMPLATES = Path(__file__).resolve().parent / "templates"


@dataclass(slots=True)
class RenderedReport:
    text: str
    template: str
    redacted: list[str]


def _env(workspace=None) -> Environment:
    search: list[FileSystemLoader] = []
    if workspace is not None:
        ws_tpl = workspace.reports_dir / "templates"
        if ws_tpl.is_dir():
            search.append(FileSystemLoader(str(ws_tpl)))
    search.append(FileSystemLoader(str(_PKG_TEMPLATES)))
    return Environment(
        loader=ChoiceLoader(search),
        autoescape=select_autoescape(enabled_extensions=(), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def available_templates(workspace=None) -> list[str]:
    names: set[str] = set()
    for d in ([workspace.reports_dir / "templates"] if workspace else []) + [_PKG_TEMPLATES]:
        if d and Path(d).is_dir():
            names |= {p.name for p in Path(d).glob("*.j2")}
    return sorted(names)


def render_report(
    finding: Finding,
    *,
    template: str = "h1_report.md.j2",
    workspace=None,
    do_redact: bool = True,
) -> RenderedReport:
    env = _env(workspace)
    if not template.endswith(".j2"):
        template = f"{template}.j2"
    try:
        tpl = env.get_template(template)
    except Exception as e:  # jinja TemplateNotFound and friends
        raise UsageError(
            f"template '{template}' not found (have: {', '.join(available_templates(workspace))})"
        ) from e

    cvss_version = ""
    if finding.cvss_vector:
        try:
            cvss_version = parse_cvss(finding.cvss_vector).version
        except UsageError:
            cvss_version = "?"

    evidence = []
    if finding.evidence and workspace is not None:
        evidence = redact_findings_evidence(
            finding.evidence, workspace.root, enabled=do_redact
        )

    body = tpl.render(
        f=finding,
        meta_block=_meta_block(finding, cvss_version),
        refs_block=_refs_block(finding),
        evidence_block=_evidence_block(evidence),
        severity_label=(finding.severity or "none").capitalize(),
        cvss_version=cvss_version,
        evidence=evidence,
        today=_dt.date.today().isoformat(),
    )

    fired: list[str] = []
    for e in evidence:
        fired += e.get("redacted", [])
    if do_redact:
        body, more = redact(body)
        fired += more

    return RenderedReport(text=body, template=template, redacted=sorted(set(fired)))


def _meta_block(f: Finding, cvss_version: str) -> str:
    lines = []
    weakness = f.weakness or (f.vuln_class or "—")
    if f.weakness and f.vuln_class:
        weakness = f"{f.weakness} ({f.vuln_class})"
    lines.append(f"**Weakness:** {weakness}")
    sev = (f.severity or "none").capitalize()
    if f.cvss_vector:
        sev += f" — CVSS {cvss_version} {f.cvss_score} `{f.cvss_vector}`"
    lines.append(f"**Severity:** {sev}")
    lines.append(f"**Asset:** {f.target or '—'}")
    if f.program:
        lines.append(f"**Program:** {f.program}")
    return "  \n".join(lines)  # two trailing spaces = hard line break in Markdown


def _refs_block(f: Finding) -> str:
    if not f.references:
        return "- _none_"
    return "\n".join(f"- {r}" for r in f.references)


def _evidence_block(evidence: list[dict]) -> str:
    if not evidence:
        return ""
    parts = ["### Attached evidence", ""]
    for e in evidence:
        head = f"**`{e['path']}`**"
        if e.get("redacted"):
            head += f"  _(redacted: {', '.join(e['redacted'])})_"
        parts.append(head)
        parts.append("")
        if e.get("kind") == "text":
            parts += ["```", e["text"], "```", ""]
        else:
            parts += [e.get("note", "_(no preview)_"), ""]
    return "\n".join(parts)

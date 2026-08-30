"""Redact secrets and PII from text before it goes into a report.

Each rule is (name, compiled regex, optional validator). Matches are replaced
with ``[REDACTED-<NAME>]``. ``redact()`` returns the cleaned text plus the list
of rule names that fired, so a command can tell the user what was scrubbed.
"""

from __future__ import annotations

import re

_RULES: list[tuple[str, re.Pattern, object]] = []


def _rule(name: str, pattern: str, flags: int = 0, validator=None) -> None:
    _RULES.append((name, re.compile(pattern, flags), validator))


def _luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(ds) <= 19:
        return False
    total, alt = 0, False
    for d in reversed(ds):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


_KEY_KIND = r"(?:RSA |EC |OPENSSH |DSA |PGP )?"
_rule(
    "PRIVATE-KEY",
    rf"-----BEGIN {_KEY_KIND}PRIVATE KEY-----.*?-----END {_KEY_KIND}PRIVATE KEY-----",
    re.S,
)
_rule("AWS-KEY", r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b")
_rule("GCP-KEY", r"\bAIza[0-9A-Za-z_\-]{35}")
_rule("SLACK-TOKEN", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
_rule("GITHUB-TOKEN", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")
_rule("GITHUB-PAT", r"\bgithub_pat_[0-9A-Za-z_]{60,}\b")
_rule("JWT", r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b")
_rule("BEARER", r"(?i)\b(?:bearer|authorization:\s*bearer)\s+[A-Za-z0-9._\-]{16,}")
_rule("BASIC-AUTH-URL", r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@")
_rule("API-KEY-KV",
      r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|client[_-]?secret)\b\s*[=:]\s*[\"']?[A-Za-z0-9/_\-+.]{12,}[\"']?")
_rule("EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_rule("SSN", r"\b\d{3}-\d{2}-\d{4}\b")
_rule("CREDIT-CARD", r"\b(?:\d[ \-]?){13,19}\b", 0, _luhn_ok)


def _make_sub(name: str, validator, fired: list[str]):
    def _sub(m: re.Match) -> str:
        if validator and not validator(m.group(0)):
            return m.group(0)
        if name not in fired:
            fired.append(name)
        return f"[REDACTED-{name}]"

    return _sub


def redact(text: str, *, enabled: bool = True) -> tuple[str, list[str]]:
    if not enabled or not text:
        return text, []
    fired: list[str] = []
    out = text
    for name, rx, validator in _RULES:
        out = rx.sub(_make_sub(name, validator, fired), out)
    return out, fired


def redact_findings_evidence(
    paths: list[str], base, *, enabled: bool = True, max_bytes: int = 20_000
) -> list[dict]:
    """Read small text evidence files and return redacted excerpts.

    Each entry: ``{path, kind, text|note, redacted:[...]}``.
    """
    from pathlib import Path

    out: list[dict] = []
    for rel in paths:
        p = (Path(base) / rel) if not str(rel).startswith("/") else Path(rel)
        item: dict = {"path": str(rel)}
        if not p.is_file():
            item["note"] = "(file not found)"
            out.append(item)
            continue
        raw = p.read_bytes()[: max_bytes + 1]
        truncated = len(raw) > max_bytes
        try:
            body, fired = redact(raw[:max_bytes].decode("utf-8"), enabled=enabled)
            item.update(
                kind="text",
                text=body + ("\n… (truncated)" if truncated else ""),
                redacted=fired,
            )
        except UnicodeDecodeError:
            size = p.stat().st_size
            item.update(kind="binary", note=f"(binary, {size} bytes - attach separately)")
        out.append(item)
    return out

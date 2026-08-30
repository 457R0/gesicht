"""Deterministic identifiers and slugs.

Every normalized entity gets an ``id`` that is a stable hash of its identity
tuple, so re-running a tool upserts the same rows instead of duplicating them.
"""

from __future__ import annotations

import hashlib
import re

_SLUG_STRIP = re.compile(r"[^\w.\- ]")
_SLUG_SPACE = re.compile(r"[\s_]+")


def slugify(name: str, *, max_len: int = 60) -> str:
    """Filesystem-safe slug for a workspace folder name.

    Strips anything outside ``[\\w.\\- ]``, trims, and turns spaces into
    underscores - so ``"Acme Web App"`` becomes ``Acme_Web_App``.
    """
    s = _SLUG_STRIP.sub("", name).strip().replace(" ", "_")
    return (s or "target")[:max_len]


def dash_slug(text: str, *, max_len: int = 50) -> str:
    """Lowercase dash-joined slug, used for finding filenames (NNNN-<slug>.md)."""
    s = _SLUG_STRIP.sub("", text.lower()).strip()
    s = _SLUG_SPACE.sub("-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return (s or "item")[:max_len]


def entity_id(*parts: object, length: int = 16) -> str:
    """Short hex id derived from a normalized identity tuple.

    ``None`` parts are skipped; everything else is lower-cased and joined with a
    NUL so ``("a", "bc")`` and ``("ab", "c")`` never collide.
    """
    norm = "\x00".join(str(p).strip().lower() for p in parts if p is not None)
    return hashlib.sha256(norm.encode("utf-8", "surrogatepass")).hexdigest()[:length]

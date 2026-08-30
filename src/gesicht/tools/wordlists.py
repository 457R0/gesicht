"""Locate a usable wordlist for content / DNS / parameter discovery.

Order of preference: an explicit path from the workspace config, then SecLists
(if installed), then Kali's stock ``/usr/share/wordlists`` lists, then a tiny
bundled fallback so a command never hard-fails for lack of a list.
"""

from __future__ import annotations

from pathlib import Path

_SECLISTS_ROOTS = (
    Path("/usr/share/seclists"),
    Path("/usr/share/wordlists/seclists"),
    Path("/usr/share/SecLists"),
    Path.home() / "SecLists",
)

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "content": (
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
    ),
    "dns": (
        "Discovery/DNS/subdomains-top1million-20000.txt",
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/namelist.txt",
    ),
    "params": (
        "Discovery/Web-Content/burp-parameter-names.txt",
        "Discovery/Web-Content/raft-medium-words.txt",
    ),
}

_STOCK: dict[str, tuple[str, ...]] = {
    "content": (
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ),
    "dns": (
        "/usr/share/wordlists/dnsmap.txt",
        "/usr/share/wordlists/dirb/vulns/apache.txt",
    ),
    "params": (),
}

_BUNDLED_PARAMS = [
    "id", "page", "q", "search", "query", "url", "next", "redirect", "return",
    "return_url", "returnurl", "r", "u", "dest", "destination", "continue",
    "file", "path", "dir", "folder", "download", "name", "user", "username",
    "email", "token", "access_token", "api_key", "apikey", "key", "secret",
    "callback", "jsonp", "debug", "test", "admin", "lang", "locale", "format",
    "type", "action", "cmd", "exec", "template", "view", "include", "src",
    "data", "json", "xml", "order", "sort", "filter", "limit", "offset",
    "start", "end", "from", "to", "date", "year", "month", "day", "week",
]


def _bundled_dir() -> Path:
    d = Path.home() / ".local" / "share" / "gesicht" / "wordlists"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ensure_bundled_params() -> Path:
    p = _bundled_dir() / "params-min.txt"
    if not p.is_file():
        p.write_text("\n".join(_BUNDLED_PARAMS) + "\n")
    return p


def find_wordlist(kind: str, *, override: str | None = None) -> Path | None:
    if override:
        p = Path(override).expanduser()
        return p if p.is_file() else None

    for root in _SECLISTS_ROOTS:
        if not root.is_dir():
            continue
        for rel in _CANDIDATES.get(kind, ()):
            cand = root / rel
            if cand.is_file():
                return cand

    for path in _STOCK.get(kind, ()):
        p = Path(path)
        if p.is_file():
            return p

    if kind == "params":
        return _ensure_bundled_params()
    return None


def seclists_root() -> Path | None:
    return next((r for r in _SECLISTS_ROOTS if r.is_dir()), None)

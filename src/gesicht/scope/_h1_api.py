"""Minimal HackerOne API client - only what ``gesicht scope import --h1`` needs.

Auth: HackerOne uses HTTP Basic with ``<api-username>:<api-token>``. Provide it
as ``GESICHT_H1_TOKEN`` in either ``user:token`` form or just ``token`` combined
with ``GESICHT_H1_USER``. The token is read from the environment (or the system
keyring if ``keyring`` is installed) and never written to disk.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request

from ..core.errors import UsageError

_API = "https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"


def _credentials() -> tuple[str, str]:
    token = os.environ.get("GESICHT_H1_TOKEN", "")
    user = os.environ.get("GESICHT_H1_USER", "")
    if not token:
        try:  # optional
            import keyring

            token = keyring.get_password("gesicht", "h1_token") or ""
            user = user or (keyring.get_password("gesicht", "h1_user") or "")
        except Exception:  # noqa: BLE001
            token = ""
    if not token:
        raise UsageError(
            "set GESICHT_H1_TOKEN (\"api-username:api-token\" or the token alone with "
            "GESICHT_H1_USER) to import scope from the HackerOne API, or use "
            "`gesicht scope import --file <export.json>`"
        )
    if ":" in token and not user:
        user, token = token.split(":", 1)
    if not user:
        raise UsageError("HackerOne needs the API username too - set GESICHT_H1_USER")
    return user, token


def fetch_structured_scopes(handle: str, *, timeout: float = 20.0) -> str:
    user, token = _credentials()
    creds = base64.b64encode(f"{user}:{token}".encode()).decode()
    scopes: list[dict] = []
    url: str | None = _API.format(handle=handle) + "?page[size]=100"
    while url:
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Basic {creds}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:  # pragma: no cover - network
            raise UsageError(f"HackerOne API returned HTTP {e.code} for '{handle}'") from e
        except urllib.error.URLError as e:  # pragma: no cover - network
            raise UsageError(f"could not reach the HackerOne API: {e.reason}") from e
        scopes.extend(body.get("data", []))
        url = (body.get("links") or {}).get("next")
    return json.dumps({"data": scopes})

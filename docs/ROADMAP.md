# Roadmap

Planned work, not yet started. Kept out of the user-facing docs
([`OVERVIEW.md`](OVERVIEW.md), [`DESIGN.md`](DESIGN.md)) until it lands.

## Traffic analysis — `gesicht traffic import`

Import HAR / Burp / mitmproxy captures and mine them for leads, feeding the
results back into recon and findings.

Heuristics to run over each request/response pair:

- reflected parameters (value echoed in the response body/headers)
- IDOR candidates (sequential / guessable IDs in path or query)
- tokens / secrets in URLs (query-string auth, session IDs)
- CORS misconfig (permissive `Access-Control-Allow-Origin`, credentials + wildcard)
- secrets in responses (API keys, private keys, JWTs, cloud credentials)

Output: new `Endpoint` / `Param` records into the store, and auto-drafted
findings for the high-confidence hits — same path scanner hits take today.

Scope: every imported host goes through `ScopeGuard` before anything is stored,
same as a live tool run.

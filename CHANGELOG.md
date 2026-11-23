# Changelog

All notable changes to APIShield are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-24

First public release.

### Added
- Reverse-proxy gateway core on the Python standard library only
  (`http.server` front, `http.client` upstream), zero runtime dependencies.
- Monitor mode (log only) and enforce mode (block on critical rules with a
  structured 403 before the request reaches the upstream).
- Identity/principal extraction: JWT `sub` claim, API-key fingerprint,
  `X-User-Id` header, client-IP fallback.
- Detection rules:
  - BOLA/IDOR — cross-principal object access (path ids, UUIDs, `*_id`
    query parameters) and sequential-id probing sweeps.
  - JWT — `alg=none`/empty signature, missing `exp`, expired tokens,
    malformed bearer values, tokens in query strings.
  - Auth abuse — sliding-window rate anomalies per (IP, auth path),
    escalating to critical at 2× the configured limit.
  - Sensitive-data exposure in responses — email addresses, Luhn-valid
    card-like numbers, API-key/JWT shapes, secret fields.
  - Security headers — HSTS, CSP, `X-Content-Type-Options`,
    `X-Frame-Options` auditing.
- JSONL event store with redaction by construction: evidence carries
  truncated values with SHA-256 fingerprints; raw secrets are rejected.
- `apishield report` CLI — totals, blocked count, breakdowns by rule,
  severity and principal, plus a `--json` mode.
- JSON config file with strict validation (unknown keys rejected).
- Bundled deliberately-vulnerable demo upstream and a scripted attack
  replay (`apishield demo`) covering IDOR, `alg=none` and stuffing.
- Docker image and docker-compose stack; GitHub Actions CI on
  Python 3.11 and 3.12; 59-test pytest suite.

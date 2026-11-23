"""Detection rules.

All rules are deterministic and stateful only in small, explicit trackers
(object ownership, probe windows, auth-rate windows). No ML, no magic:
every event names the exact pattern that fired.

Request-phase rules run before forwarding (their critical events can block
in enforce mode); response-phase rules run on the way back.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping
from urllib.parse import parse_qsl, urlsplit

from .config import Config
from .events import Event
from .identity import bearer_token, decode_jwt, is_jwt_shaped
from .redact import fingerprint, redact_value

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NUMERIC_RE = re.compile(r"^\d+$")
_ID_PARAM_RE = re.compile(r"(?i)(^id$|_id$|Id$)")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_TOKEN_PATTERNS = (
    ("api_key", re.compile(r"\b(sk-[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("generic_secret_field", re.compile(r'(?i)"(password|secret|private_key)"\s*:\s*"[^"]+"')),
)

REQUIRED_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
)


@dataclass
class RequestContext:
    method: str
    path: str  # path only, no query string
    query: str
    headers: Mapping[str, str]
    client_ip: str
    principal: str
    body: bytes = b""


@dataclass
class ResponseContext:
    status: int
    headers: Mapping[str, str]
    body: bytes = b""


@dataclass
class _Window:
    """Sliding-window counter keyed by an arbitrary string."""

    limit_seconds: float
    hits: dict[str, list[float]] = field(default_factory=dict)

    def add(self, key: str, now: float) -> int:
        bucket = [t for t in self.hits.get(key, []) if now - t < self.limit_seconds]
        bucket.append(now)
        self.hits[key] = bucket
        return len(bucket)


def _luhn_ok(digits: str) -> bool:
    total = 0
    alt = False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def extract_object_refs(path: str, query: str) -> list[tuple[str, str]]:
    """Extract (resource, object_id) references from a path and query string.

    A path segment that is a bare number or a UUID is an object id; the
    resource is the path prefix before it. Query parameters whose name looks
    like an identifier (``id``, ``user_id``, ``orderId`` …) count too.
    """
    refs: list[tuple[str, str]] = []
    segments = [s for s in path.split("/") if s]
    for i, seg in enumerate(segments):
        if _NUMERIC_RE.match(seg) or _UUID_RE.match(seg):
            resource = "/" + "/".join(segments[:i]) if i else "/"
            refs.append((resource, seg))
    for key, value in parse_qsl(query, keep_blank_values=False):
        if _ID_PARAM_RE.search(key) and value:
            refs.append((f"{path}?{key}", value))
    return refs


class Detector:
    """Stateful rule engine. One instance per gateway process."""

    def __init__(self, config: Config, clock: Callable[[], float] = time.monotonic):
        self._cfg = config
        self._clock = clock
        # (resource, object_id) -> first principal seen owning/accessing it
        self._owners: dict[tuple[str, str], str] = {}
        # (resource, object_id, principal) pairs already reported for BOLA
        self._bola_reported: set[tuple[str, str, str]] = set()
        self._probe_window = _Window(config.thresholds.probe_window_seconds)
        self._probe_seen: dict[str, set[str]] = {}
        self._probe_reported: set[str] = set()
        self._auth_window = _Window(config.thresholds.auth_window_seconds)

    # ------------------------------------------------------------------ API

    def inspect_request(self, ctx: RequestContext) -> list[Event]:
        events: list[Event] = []
        if self._cfg.rules.enabled("bola"):
            events += self._rule_bola(ctx)
        if self._cfg.rules.enabled("jwt"):
            events += self._rule_jwt(ctx)
        if self._cfg.rules.enabled("auth_abuse"):
            events += self._rule_auth_abuse(ctx)
        return events

    def inspect_response(
        self, req: RequestContext, resp: ResponseContext
    ) -> list[Event]:
        events: list[Event] = []
        if self._cfg.rules.enabled("data_exposure"):
            events += self._rule_data_exposure(req, resp)
        if self._cfg.rules.enabled("security_headers"):
            events += self._rule_security_headers(req, resp)
        return events

    # ----------------------------------------------------------------- BOLA

    def _rule_bola(self, ctx: RequestContext) -> list[Event]:
        events: list[Event] = []
        refs = extract_object_refs(ctx.path, ctx.query)
        now = self._clock()
        for resource, object_id in refs:
            owner = self._owners.setdefault((resource, object_id), ctx.principal)
            if owner != ctx.principal:
                key = (resource, object_id, ctx.principal)
                if key not in self._bola_reported:
                    self._bola_reported.add(key)
                    events.append(Event(
                        rule="bola.cross_principal_access",
                        severity="critical",
                        principal=ctx.principal,
                        method=ctx.method,
                        path=ctx.path,
                        detail=(
                            f"principal {ctx.principal} accessed object {object_id} on "
                            f"{resource} first seen under principal {owner}"
                        ),
                        evidence={
                            "resource": resource,
                            "object_id": object_id,
                            "owner_principal": owner,
                        },
                    ))
            # sequential probing: one principal sweeping many ids on a resource
            if _NUMERIC_RE.match(object_id):
                probe_key = f"{ctx.principal}|{resource}"
                count = self._probe_window.add(probe_key, now)
                seen = self._probe_seen.setdefault(probe_key, set())
                seen.add(object_id)
                threshold = self._cfg.thresholds.probe_distinct_ids_per_window
                if len(seen) >= threshold and count >= threshold and probe_key not in self._probe_reported:
                    self._probe_reported.add(probe_key)
                    events.append(Event(
                        rule="bola.sequential_probing",
                        severity="high",
                        principal=ctx.principal,
                        method=ctx.method,
                        path=ctx.path,
                        detail=(
                            f"principal {ctx.principal} requested {len(seen)} distinct "
                            f"numeric object ids on {resource} within "
                            f"{self._cfg.thresholds.probe_window_seconds}s"
                        ),
                        evidence={"resource": resource, "distinct_ids": len(seen)},
                    ))
        return events

    # ------------------------------------------------------------------ JWT

    def _rule_jwt(self, ctx: RequestContext) -> list[Event]:
        events: list[Event] = []

        def add(rule: str, severity: str, detail: str, evidence: dict | None = None) -> None:
            events.append(Event(
                rule=rule, severity=severity, principal=ctx.principal,
                method=ctx.method, path=ctx.path, detail=detail,
                evidence=evidence or {},
            ))

        # tokens must never travel in query strings (logged, cached, leaked)
        for key, value in parse_qsl(ctx.query, keep_blank_values=False):
            if key.lower() in {"token", "access_token", "jwt", "id_token"} and is_jwt_shaped(value):
                add(
                    "jwt.token_in_query", "high",
                    f"JWT-shaped token passed in query parameter {key!r} "
                    "(URLs are logged by proxies and browsers)",
                    {"param": key, "token_fingerprint": fingerprint(value)},
                )

        token = bearer_token(ctx.headers)
        if token is None:
            return events
        decoded = decode_jwt(token)
        if decoded is None:
            add("jwt.malformed", "medium",
                "Bearer token is not a structurally valid JWT",
                {"token_fingerprint": fingerprint(token)})
            return events
        header, payload = decoded
        fp = fingerprint(token)
        alg = header.get("alg")
        if not isinstance(alg, str) or alg.lower() == "none" or not token.rsplit(".", 1)[-1]:
            add("jwt.alg_none", "critical",
                "JWT uses alg=none or carries an empty signature — "
                "accepted only by a broken verifier",
                {"alg": str(alg), "token_fingerprint": fp})
        if "exp" not in payload:
            add("jwt.missing_exp", "medium",
                "JWT has no exp claim — the token never expires",
                {"token_fingerprint": fp})
        else:
            exp = payload.get("exp")
            if isinstance(exp, (int, float)) and exp < time.time():
                add("jwt.expired", "medium",
                    "JWT is expired but was presented to the API",
                    {"token_fingerprint": fp})
        return events

    # ------------------------------------------------------------ auth abuse

    def _rule_auth_abuse(self, ctx: RequestContext) -> list[Event]:
        auth_paths = self._cfg.thresholds.auth_paths
        if not any(ctx.path.startswith(p) for p in auth_paths):
            return []
        if ctx.method.upper() not in {"POST", "GET"}:
            return []
        key = f"{ctx.client_ip}|{ctx.path}"
        count = self._auth_window.add(key, self._clock())
        limit = self._cfg.thresholds.auth_requests_per_window
        if count > limit:
            severity = "critical" if count >= 2 * limit else "high"
            return [Event(
                rule="auth_abuse.rate_anomaly",
                severity=severity,
                principal=ctx.principal,
                method=ctx.method,
                path=ctx.path,
                detail=(
                    f"{count} requests to auth path {ctx.path} from {ctx.client_ip} "
                    f"within {self._cfg.thresholds.auth_window_seconds}s "
                    f"(limit {limit}) — possible credential stuffing"
                ),
                evidence={"client_ip": ctx.client_ip, "count": count, "limit": limit},
            )]
        return []

    # ---------------------------------------------------------- data exposure

    def _rule_data_exposure(self, req: RequestContext, resp: ResponseContext) -> list[Event]:
        if not resp.body or len(resp.body) > self._cfg.max_scan_bytes:
            return []
        ctype = resp.headers.get("Content-Type", "")
        if ctype and not any(t in ctype for t in ("json", "text", "xml", "html")):
            return []
        text = resp.body.decode("utf-8", "replace")
        events: list[Event] = []

        emails = _EMAIL_RE.findall(text)
        if emails:
            events.append(Event(
                rule="data_exposure.email_addresses",
                severity="medium",
                principal=req.principal,
                method=req.method,
                path=req.path,
                detail=f"response contains {len(emails)} email address(es)",
                evidence={
                    "count": len(emails),
                    "sample_redacted": redact_value(emails[0], keep=2),
                },
            ))

        cards = []
        for match in _CARD_CANDIDATE_RE.findall(text):
            digits = re.sub(r"\D", "", match)
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                cards.append(digits)
        if cards:
            events.append(Event(
                rule="data_exposure.card_number",
                severity="high",
                principal=req.principal,
                method=req.method,
                path=req.path,
                detail=f"response contains {len(cards)} Luhn-valid card-like number(s)",
                evidence={
                    "count": len(cards),
                    "sample_redacted": redact_value(cards[0], keep=2),
                },
            ))

        for name, pattern in _TOKEN_PATTERNS:
            found = pattern.findall(text)
            if found:
                sample = found[0] if isinstance(found[0], str) else str(found[0])
                events.append(Event(
                    rule=f"data_exposure.{name}",
                    severity="high",
                    principal=req.principal,
                    method=req.method,
                    path=req.path,
                    detail=f"response contains {len(found)} {name} pattern(s)",
                    evidence={"count": len(found), "sample_redacted": redact_value(sample)},
                ))
        return events

    # -------------------------------------------------------- security headers

    def _rule_security_headers(self, req: RequestContext, resp: ResponseContext) -> list[Event]:
        present = {k.lower() for k in resp.headers}
        missing = [h for h in REQUIRED_HEADERS if h not in present]
        nosniff_ok = resp.headers.get("X-Content-Type-Options", "").lower() == "nosniff"
        if "x-content-type-options" in present and not nosniff_ok:
            missing.append("x-content-type-options!=nosniff")
        if not missing:
            return []
        return [Event(
            rule="security_headers.missing",
            severity="low",
            principal=req.principal,
            method=req.method,
            path=req.path,
            detail=f"response is missing security headers: {', '.join(missing)}",
            evidence={"missing": missing, "status": resp.status},
        )]


def split_target(target: str) -> tuple[str, str]:
    """Split a raw request target into (path, query)."""
    parts = urlsplit(target)
    return parts.path or "/", parts.query

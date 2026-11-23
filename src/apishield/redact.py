"""Redaction helpers.

The event store must never contain raw secrets. Every piece of evidence that
APIShield records passes through here first: values are truncated and paired
with a short SHA-256 fingerprint so events stay correlatable without being
usable credentials.
"""

from __future__ import annotations

import hashlib
import re

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_API_KEY_RE = re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})\b")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")


def fingerprint(value: str) -> str:
    """Short, non-reversible fingerprint of a sensitive value."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def redact_value(value: str, keep: int = 4) -> str:
    """Redact a single sensitive value: keep a tiny prefix, add fingerprint."""
    if not value:
        return ""
    if len(value) <= keep:
        return "***"
    return f"{value[:keep]}…[{fingerprint(value)}]"


def redact_text(text: str) -> str:
    """Redact emails, bearer tokens, API keys and long tokens in free text."""
    out = _BEARER_RE.sub(lambda m: "Bearer " + redact_value(m.group(0).split(None, 1)[1]), text)
    out = _EMAIL_RE.sub(lambda m: redact_value(m.group(0), keep=2), out)
    out = _API_KEY_RE.sub(lambda m: redact_value(m.group(0)), out)
    out = _LONG_TOKEN_RE.sub(lambda m: redact_value(m.group(0)), out)
    return out

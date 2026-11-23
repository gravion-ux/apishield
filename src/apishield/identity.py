"""Principal (caller identity) extraction.

Cross-principal detection (BOLA) is only possible if the gateway knows *who*
is calling. APIShield extracts a stable principal string, in priority order:

1. ``Authorization: Bearer <jwt>`` — the ``sub`` claim if the JWT payload is
   decodable, otherwise a fingerprint of the token (never the raw token).
2. ``X-API-Key`` header — a fingerprint of the key.
3. ``X-User-Id`` header — used verbatim (it is an identifier, not a secret).
4. Fallback: ``ip:<client ip>``.
"""

from __future__ import annotations

import base64
import json
from typing import Mapping

from .redact import fingerprint


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    """Decode a JWT's header and payload WITHOUT verifying the signature.

    Returns None when the token is not a structurally valid JWT. Signature
    verification is the upstream's job; the gateway only inspects.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def is_jwt_shaped(value: str) -> bool:
    return value.count(".") == 2 and all(value.split("."))


def extract_principal(headers: Mapping[str, str], client_ip: str) -> str:
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        decoded = decode_jwt(token)
        if decoded is not None:
            sub = decoded[1].get("sub")
            if isinstance(sub, str) and sub:
                return f"user:{sub}"
        return f"token:{fingerprint(token)}"
    api_key = headers.get("X-API-Key")
    if api_key:
        return f"key:{fingerprint(api_key)}"
    user_id = headers.get("X-User-Id")
    if user_id:
        return f"user:{user_id}"
    return f"ip:{client_ip}"


def bearer_token(headers: Mapping[str, str]) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None

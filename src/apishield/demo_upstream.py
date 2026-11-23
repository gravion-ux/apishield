"""A tiny, deliberately vulnerable demo upstream API.

Exists only to demonstrate APIShield. It performs **no** authorisation
checks: any caller can read any user's profile by id (classic BOLA), it
returns email addresses and a test card number in responses, it sets no
security headers, and its /login accepts anything. Never deploy this.
"""

from __future__ import annotations

import base64
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PROFILES = {
    "101": {
        "id": 101, "name": "Alice Example", "email": "alice@example.com",
        "card_on_file": "4111111111111111",  # well-known test card number
    },
    "102": {
        "id": 102, "name": "Bob Example", "email": "bob@example.com",
        "card_on_file": "5500005555555559",  # well-known test card number
    },
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def demo_token(sub: str, *, alg_none: bool = False, expires_in: int = 3600) -> str:
    """Mint an unsigned demo JWT (the demo upstream never verifies)."""
    header = {"alg": "none" if alg_none else "HS256", "typ": "JWT"}
    payload: dict[str, Any] = {"sub": sub, "iat": int(time.time())}
    if expires_in is not None:
        payload["exp"] = int(time.time()) + expires_in
    head = _b64url(json.dumps(header).encode())
    body = _b64url(json.dumps(payload).encode())
    signature = "" if alg_none else _b64url(b"demo-signature")
    return f"{head}.{body}.{signature}"


def make_demo_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parts = [p for p in self.path.split("/") if p]
            if self.path == "/health":
                self._send(200, {"status": "ok"})
            elif len(parts) == 3 and parts[0] == "users" and parts[2] == "profile":
                profile = PROFILES.get(parts[1])
                if profile:
                    # deliberately no authorisation check — this is the bug
                    self._send(200, profile)
                else:
                    self._send(404, {"error": "not_found"})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            if self.path == "/login":
                # deliberately accepts everything — stuffing looks identical
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not_found"})

        def log_message(self, fmt: str, *args: Any) -> None:
            pass

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    import os

    port = int(os.environ.get("DEMO_UPSTREAM_PORT", "9000"))
    server = make_demo_server("0.0.0.0", port)
    print(f"demo upstream listening on 0.0.0.0:{port} (deliberately vulnerable)")
    server.serve_forever()


if __name__ == "__main__":
    main()

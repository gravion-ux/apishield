"""The reverse-proxy gateway core.

Built on the standard library only: ``http.server.ThreadingHTTPServer`` on
the front, ``http.client`` to the upstream. Request-phase rules run before
forwarding; in enforce mode a critical request-phase event short-circuits
the request with a 403 and the event is marked ``blocked``.
"""

from __future__ import annotations

import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .config import Config
from .events import Event, EventStore
from .identity import extract_principal
from .rules import Detector, RequestContext, ResponseContext, split_target

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}
BLOCK_SEVERITY = "critical"
MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024


def parse_content_length(raw: str | None) -> int:
    """Return a validated Content-Length, or -1 when the header is invalid."""
    if raw is None:
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return -1
    return value if value >= 0 else -1


class Gateway:
    """Owns config, detector and store; builds the HTTP server."""

    def __init__(self, config: Config, store: EventStore | None = None):
        self.config = config
        self.detector = Detector(config)
        self.store = store if store is not None else EventStore(config.event_log)
        upstream = urlsplit(config.upstream)
        self._upstream_host = upstream.hostname or "127.0.0.1"
        self._upstream_port = upstream.port or (443 if upstream.scheme == "https" else 80)
        self._upstream_scheme = upstream.scheme
        self._upstream_base = upstream.path.rstrip("/")

    # ------------------------------------------------------------- handling

    def handle(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        """Process one request end-to-end. Transport-agnostic for testing."""
        path, query = split_target(target)
        principal = extract_principal(headers, client_ip)
        req_ctx = RequestContext(
            method=method, path=path, query=query,
            headers=headers, client_ip=client_ip, principal=principal, body=body,
        )

        request_events = self.detector.inspect_request(req_ctx)
        blocking = [e for e in request_events if e.severity == BLOCK_SEVERITY]
        if blocking and self.config.mode == "enforce":
            for event in request_events:
                event.blocked = event in blocking
            self.store.record_many(request_events)
            payload = {
                "error": "blocked_by_apishield",
                "rules": sorted({e.rule for e in blocking}),
                "detail": "request blocked by APIShield policy (critical rule match)",
            }
            return 403, {"Content-Type": "application/json"}, json.dumps(payload).encode()

        status, resp_headers, resp_body = self._forward(method, target, headers, body)
        resp_ctx = ResponseContext(status=status, headers=resp_headers, body=resp_body)
        response_events = self.detector.inspect_response(req_ctx, resp_ctx)
        self.store.record_many(request_events)
        self.store.record_many(response_events)
        return status, resp_headers, resp_body

    def _forward(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        conn_cls = (
            http.client.HTTPSConnection if self._upstream_scheme == "https"
            else http.client.HTTPConnection
        )
        conn = conn_cls(self._upstream_host, self._upstream_port, timeout=30)
        fwd_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in HOP_BY_HOP and k.lower() != "host"
        }
        fwd_headers["Host"] = f"{self._upstream_host}:{self._upstream_port}"
        upstream_target = self._upstream_base + target if self._upstream_base else target
        try:
            conn.request(method, upstream_target, body=body or None, headers=fwd_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_headers = {
                k: v for k, v in resp.getheaders() if k.lower() not in HOP_BY_HOP
            }
            return resp.status, resp_headers, resp_body
        except OSError as exc:
            payload = {"error": "upstream_unreachable", "detail": str(exc)}
            return 502, {"Content-Type": "application/json"}, json.dumps(payload).encode()
        finally:
            conn.close()

    # --------------------------------------------------------------- server

    def make_server(self) -> ThreadingHTTPServer:
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _dispatch(self) -> None:
                length = parse_content_length(self.headers.get("Content-Length"))
                if length < 0:
                    self.send_response(400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if length > MAX_REQUEST_BODY_BYTES:
                    self.send_response(413)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = self.rfile.read(length) if length else b""
                headers = {k: v for k, v in self.headers.items()}
                status, resp_headers, resp_body = gateway.handle(
                    self.command, self.path, headers, body,
                    self.client_address[0],
                )
                self.send_response(status)
                for key, value in resp_headers.items():
                    if key.lower() == "content-length":
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(resp_body)))
                self.send_header("X-APIShield", "1")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(resp_body)

            do_GET = _dispatch
            do_POST = _dispatch
            do_PUT = _dispatch
            do_PATCH = _dispatch
            do_DELETE = _dispatch
            do_HEAD = _dispatch
            do_OPTIONS = _dispatch

            def log_message(self, fmt: str, *args: Any) -> None:  # keep stdout clean
                pass

        return ThreadingHTTPServer(
            (self.config.listen_host, self.config.listen_port), Handler
        )

    def serve_forever(self) -> None:
        server = self.make_server()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()

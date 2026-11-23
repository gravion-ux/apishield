"""Scripted attack replay against the bundled demo upstream.

Starts the vulnerable demo API and an APIShield gateway in front of it,
then replays:

1. legitimate traffic (Alice reads her own profile) — passes, no BOLA event;
2. a cross-user IDOR read (Bob reads Alice's profile) — BOLA critical;
3. an ``alg=none`` JWT — JWT critical;
4. a credential-stuffing burst against /login — auth-abuse events;
5. shows the sensitive data + missing headers flagged in Alice's response.

In enforce mode the critical attacks are blocked with 403; in monitor mode
they are only logged. Returns a list of human-readable result lines.
"""

from __future__ import annotations

import http.client
import json
import threading

from .config import Config
from .demo_upstream import demo_token, make_demo_server
from .events import EventStore
from .gateway import Gateway


def _request(port: int, method: str, path: str, token: str | None = None,
             body: dict | None = None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    payload = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        payload = json.dumps(body)
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {}
    return resp.status, parsed


def run_demo(mode: str = "enforce") -> list[str]:
    upstream = make_demo_server()
    upstream_port = upstream.server_address[1]
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    config = Config(
        upstream=f"http://127.0.0.1:{upstream_port}",
        listen_host="127.0.0.1",
        listen_port=0,
        mode=mode,
        event_log="",
    )
    config.thresholds.auth_requests_per_window = 5
    store = EventStore(None)
    gateway = Gateway(config, store=store)
    server = gateway.make_server()
    # rebind to an ephemeral port chosen by the OS
    port = server.server_address[1]
    gateway_thread = threading.Thread(target=server.serve_forever, daemon=True)
    gateway_thread.start()

    lines: list[str] = []
    try:
        alice = demo_token("alice")
        bob = demo_token("bob")

        status, _ = _request(port, "GET", "/users/101/profile", token=alice)
        lines.append(f"[ok]     Alice reads her own profile        -> HTTP {status}")

        status, _ = _request(port, "GET", "/users/101/profile", token=bob)
        verdict = "BLOCKED" if status == 403 else f"HTTP {status} (logged)"
        lines.append(f"[attack] Bob reads Alice's profile (IDOR)   -> {verdict}")

        status, _ = _request(port, "GET", "/users/101/profile",
                             token=demo_token("mallory", alg_none=True))
        verdict = "BLOCKED" if status == 403 else f"HTTP {status} (logged)"
        lines.append(f"[attack] alg=none JWT presented             -> {verdict}")

        last_status = 0
        for i in range(12):
            last_status, _ = _request(
                port, "POST", "/login",
                body={"username": "alice", "password": f"guess-{i}"},
            )
        verdict = "BLOCKED" if last_status == 403 else f"HTTP {last_status} (logged)"
        lines.append(f"[attack] credential-stuffing burst x12      -> {verdict}")

        events = store.all()
        lines.append("")
        lines.append(f"events recorded: {len(events)}")
        for event in events:
            flag = " BLOCKED" if event.blocked else ""
            lines.append(
                f"  [{event.severity}] {event.rule} "
                f"{event.method} {event.path} ({event.principal}){flag}"
            )
    finally:
        server.shutdown()
        upstream.shutdown()
    return lines


def main() -> None:
    for mode in ("monitor", "enforce"):
        print(f"--- APIShield demo (mode: {mode}) ---")
        for line in run_demo(mode):
            print(line)
        print()


if __name__ == "__main__":
    main()

import json
import threading

import pytest

from apishield.demo_upstream import demo_token, make_demo_server
from apishield.events import EventStore
from apishield.gateway import Gateway
from conftest import make_config


@pytest.fixture
def upstream():
    server = make_demo_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def make_gateway(upstream_port: int, mode: str = "monitor"):
    cfg = make_config(upstream=f"http://127.0.0.1:{upstream_port}", mode=mode)
    store = EventStore(None)
    return Gateway(cfg, store=store), store


def bearer(sub: str) -> dict:
    return {"Authorization": f"Bearer {demo_token(sub)}"}


def test_forwarding_correctness(upstream):
    gateway, _ = make_gateway(upstream)
    status, headers, body = gateway.handle(
        "GET", "/users/101/profile", bearer("alice"), b"", "10.0.0.1")
    assert status == 200
    profile = json.loads(body)
    assert profile["name"] == "Alice Example"
    assert headers["Content-Type"] == "application/json"


def test_forwarding_post_and_404(upstream):
    gateway, _ = make_gateway(upstream)
    status, _, body = gateway.handle(
        "POST", "/login", {"Content-Type": "application/json"},
        json.dumps({"username": "a", "password": "b"}).encode(), "10.0.0.1")
    assert status == 200 and json.loads(body)["ok"] is True
    status, _, _ = gateway.handle("GET", "/nope", {}, b"", "10.0.0.1")
    assert status == 404


def test_upstream_down_gives_502():
    cfg = make_config(upstream="http://127.0.0.1:1")
    gateway = Gateway(cfg, store=EventStore(None))
    status, _, body = gateway.handle("GET", "/health", {}, b"", "10.0.0.1")
    assert status == 502
    assert json.loads(body)["error"] == "upstream_unreachable"


def test_monitor_mode_logs_but_passes(upstream):
    gateway, store = make_gateway(upstream, mode="monitor")
    gateway.handle("GET", "/users/101/profile", bearer("alice"), b"", "10.0.0.1")
    status, _, body = gateway.handle(
        "GET", "/users/101/profile", bearer("bob"), b"", "10.0.0.2")
    assert status == 200  # attack reaches the upstream in monitor mode
    assert json.loads(body)["name"] == "Alice Example"
    bola = [e for e in store.all() if e.rule == "bola.cross_principal_access"]
    assert len(bola) == 1 and bola[0].blocked is False


def test_enforce_mode_blocks_idor(upstream):
    gateway, store = make_gateway(upstream, mode="enforce")
    gateway.handle("GET", "/users/101/profile", bearer("alice"), b"", "10.0.0.1")
    status, _, body = gateway.handle(
        "GET", "/users/101/profile", bearer("bob"), b"", "10.0.0.2")
    assert status == 403
    assert json.loads(body)["error"] == "blocked_by_apishield"
    bola = [e for e in store.all() if e.rule == "bola.cross_principal_access"]
    assert len(bola) == 1 and bola[0].blocked is True


def test_enforce_mode_blocks_alg_none(upstream):
    gateway, _ = make_gateway(upstream, mode="enforce")
    status, _, body = gateway.handle(
        "GET", "/health",
        {"Authorization": f"Bearer {demo_token('mallory', alg_none=True)}"},
        b"", "10.0.0.9")
    assert status == 403
    assert "jwt.alg_none" in json.loads(body)["rules"]


def test_enforce_mode_passes_legitimate(upstream):
    gateway, _ = make_gateway(upstream, mode="enforce")
    status, _, _ = gateway.handle(
        "GET", "/users/102/profile", bearer("bob"), b"", "10.0.0.2")
    assert status == 200


def test_real_http_round_trip(upstream):
    cfg = make_config(upstream=f"http://127.0.0.1:{upstream}", listen_port=0)
    gateway = Gateway(cfg, store=EventStore(None))
    server = gateway.make_server()
    import http.client
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(
            "127.0.0.1", server.server_address[1], timeout=5)
        conn.request("GET", "/health")
        response = conn.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["status"] == "ok"
        assert response.getheader("X-APIShield") == "1"
        conn.close()
    finally:
        server.shutdown()

"""Secrets must never reach the event store — on disk or in memory."""

import json
import threading

import pytest

from apishield.demo_upstream import demo_token, make_demo_server
from apishield.events import Event, EventStore
from apishield.gateway import Gateway
from apishield.redact import fingerprint, redact_text, redact_value
from conftest import make_config

RAW_CARD = "4111111111111111"
RAW_EMAIL = "alice@example.com"


@pytest.fixture
def upstream():
    server = make_demo_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def test_redact_value_hides_secret():
    out = redact_value("supersecretvalue")
    assert "supersecretvalue" not in out
    assert fingerprint("supersecretvalue") in out


def test_redact_text_strips_tokens_and_emails():
    token = demo_token("alice")
    out = redact_text(f"mail {RAW_EMAIL} with Bearer {token}")
    assert RAW_EMAIL not in out
    assert token not in out


def test_event_rejects_raw_secret_evidence_keys():
    with pytest.raises(ValueError):
        Event(rule="x", severity="low", principal="p", method="GET",
              path="/", detail="d", evidence={"token": "raw"})


def test_stored_events_contain_no_secrets(upstream, tmp_path):
    log_path = tmp_path / "events.jsonl"
    cfg = make_config(upstream=f"http://127.0.0.1:{upstream}", mode="monitor")
    store = EventStore(log_path)
    gateway = Gateway(cfg, store=store)
    token = demo_token("alice")
    gateway.handle("GET", "/users/101/profile",
                   {"Authorization": f"Bearer {token}"}, b"", "10.0.0.1")
    # a token-in-query attempt, whose raw token must not be stored either
    gateway.handle("GET", f"/users/101/profile?access_token={token}",
                   {}, b"", "10.0.0.3")

    on_disk = log_path.read_text()
    assert RAW_CARD not in on_disk
    assert RAW_EMAIL not in on_disk
    assert token not in on_disk
    for event in store.all():
        blob = json.dumps(event.to_dict())
        assert RAW_CARD not in blob
        assert RAW_EMAIL not in blob
        assert token not in blob

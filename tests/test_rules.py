"""Each rule fires on its attack fixture and stays silent on benign traffic."""

import json

from apishield.config import Thresholds
from apishield.demo_upstream import demo_token
from apishield.rules import Detector, extract_object_refs
from conftest import make_config, req, resp


def rules_of(events):
    return [e.rule for e in events]


# --------------------------------------------------------------------- BOLA

def test_bola_cross_principal_fires(detector):
    detector.inspect_request(req(path="/users/101/profile", principal="user:alice"))
    events = detector.inspect_request(req(path="/users/101/profile", principal="user:bob"))
    bola = [e for e in events if e.rule == "bola.cross_principal_access"]
    assert len(bola) == 1
    assert bola[0].severity == "critical"
    assert bola[0].evidence["owner_principal"] == "user:alice"


def test_bola_same_principal_silent(detector):
    assert detector.inspect_request(req(path="/users/101/profile")) == []
    assert detector.inspect_request(req(path="/users/101/profile")) == []


def test_bola_different_objects_silent(detector):
    detector.inspect_request(req(path="/users/101/profile", principal="user:alice"))
    events = detector.inspect_request(req(path="/users/102/profile", principal="user:bob"))
    assert not [e for e in events if e.rule.startswith("bola")]


def test_bola_query_param_id(detector):
    detector.inspect_request(req(path="/profile", query="user_id=101", principal="user:alice"))
    events = detector.inspect_request(req(path="/profile", query="user_id=101", principal="user:bob"))
    assert "bola.cross_principal_access" in rules_of(events)


def test_bola_sequential_probing_fires():
    cfg = make_config()
    cfg.thresholds = Thresholds(probe_distinct_ids_per_window=5, probe_window_seconds=60)
    detector = Detector(cfg)
    fired = []
    for i in range(1, 9):
        fired += detector.inspect_request(req(path=f"/items/{i}"))
    probes = [e for e in fired if e.rule == "bola.sequential_probing"]
    assert len(probes) == 1
    assert probes[0].severity == "high"


def test_bola_few_ids_silent():
    cfg = make_config()
    cfg.thresholds = Thresholds(probe_distinct_ids_per_window=5, probe_window_seconds=60)
    detector = Detector(cfg)
    fired = []
    for i in range(1, 4):
        fired += detector.inspect_request(req(path=f"/items/{i}"))
    assert not [e for e in fired if e.rule == "bola.sequential_probing"]


def test_extract_object_refs():
    refs = extract_object_refs("/users/101/profile", "order_id=55&x=1")
    assert ("/users", "101") in refs
    assert ("/users/101/profile?order_id", "55") in refs


# ---------------------------------------------------------------------- JWT

def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_jwt_alg_none_fires(detector):
    events = detector.inspect_request(req(headers=_bearer(demo_token("mallory", alg_none=True))))
    alg = [e for e in events if e.rule == "jwt.alg_none"]
    assert len(alg) == 1 and alg[0].severity == "critical"


def test_jwt_valid_silent(detector, alice_token):
    assert detector.inspect_request(req(headers=_bearer(alice_token))) == []


def test_jwt_missing_exp_fires(detector):
    events = detector.inspect_request(req(headers=_bearer(demo_token("alice", expires_in=None))))
    assert "jwt.missing_exp" in rules_of(events)


def test_jwt_expired_fires(detector):
    events = detector.inspect_request(req(headers=_bearer(demo_token("alice", expires_in=-60))))
    assert "jwt.expired" in rules_of(events)


def test_jwt_malformed_fires(detector):
    events = detector.inspect_request(req(headers=_bearer("not-a-jwt")))
    assert "jwt.malformed" in rules_of(events)


def test_jwt_in_query_fires(detector, alice_token):
    events = detector.inspect_request(req(path="/x", query=f"access_token={alice_token}"))
    hits = [e for e in events if e.rule == "jwt.token_in_query"]
    assert len(hits) == 1 and hits[0].severity == "high"


# --------------------------------------------------------------- auth abuse

def test_auth_abuse_fires():
    cfg = make_config()
    cfg.thresholds = Thresholds(auth_requests_per_window=3, auth_window_seconds=60)
    detector = Detector(cfg)
    fired = []
    for _ in range(4):
        fired += detector.inspect_request(req(path="/login", method="POST"))
    abuse = [e for e in fired if e.rule == "auth_abuse.rate_anomaly"]
    assert len(abuse) == 1 and abuse[0].severity == "high"


def test_auth_abuse_benign_silent():
    cfg = make_config()
    cfg.thresholds = Thresholds(auth_requests_per_window=3, auth_window_seconds=60)
    detector = Detector(cfg)
    fired = []
    for _ in range(3):
        fired += detector.inspect_request(req(path="/login", method="POST"))
    assert fired == []


def test_auth_abuse_ignores_other_paths(detector):
    fired = []
    for _ in range(50):
        fired += detector.inspect_request(req(path="/health"))
    assert fired == []


# ------------------------------------------------------------ data exposure

def _exposure(detector, body: bytes):
    events = detector.inspect_response(req(), resp(body=body))
    return [e for e in events if e.rule.startswith("data_exposure")]


def test_data_exposure_email_fires(detector):
    body = json.dumps({"email": "alice@example.com"}).encode()
    hits = _exposure(detector, body)
    assert [e.rule for e in hits] == ["data_exposure.email_addresses"]


def test_data_exposure_card_fires(detector):
    body = json.dumps({"card": "4111111111111111"}).encode()
    hits = _exposure(detector, body)
    assert "data_exposure.card_number" in [e.rule for e in hits]
    # the full card number must not appear anywhere in the event
    assert "4111111111111111" not in json.dumps(hits[0].to_dict())


def test_data_exposure_token_fires(detector):
    body = json.dumps({"key": "sk-abcdefghij1234567890"}).encode()
    hits = _exposure(detector, body)
    assert "data_exposure.api_key" in [e.rule for e in hits]


def test_data_exposure_benign_silent(detector):
    body = json.dumps({"status": "ok", "items": [1, 2, 3]}).encode()
    assert _exposure(detector, body) == []


def test_data_exposure_non_luhn_number_silent(detector):
    body = json.dumps({"ref": "4111111111111112"}).encode()  # fails Luhn
    assert _exposure(detector, body) == []


# ----------------------------------------------------------- security headers

ALL_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def test_security_headers_missing_fires(detector):
    events = detector.inspect_response(req(), resp(body=b"{}"))
    hits = [e for e in events if e.rule == "security_headers.missing"]
    assert len(hits) == 1
    assert "content-security-policy" in hits[0].evidence["missing"]


def test_security_headers_complete_silent(detector):
    events = detector.inspect_response(req(), resp(body=b"{}", headers=ALL_HEADERS))
    assert not [e for e in events if e.rule == "security_headers.missing"]


def test_rule_toggle_disables(detector):
    cfg = make_config()
    cfg.rules.bola = False
    detector = Detector(cfg)
    detector.inspect_request(req(path="/users/101/profile", principal="user:alice"))
    events = detector.inspect_request(req(path="/users/101/profile", principal="user:bob"))
    assert events == []

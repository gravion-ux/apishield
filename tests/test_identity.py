from apishield.identity import decode_jwt, extract_principal
from apishield.demo_upstream import demo_token


def test_principal_from_jwt_sub():
    token = demo_token("alice")
    assert extract_principal({"Authorization": f"Bearer {token}"}, "1.2.3.4") == "user:alice"


def test_principal_from_api_key_is_fingerprinted():
    principal = extract_principal({"X-API-Key": "my-secret-key"}, "1.2.3.4")
    assert principal.startswith("key:sha256:")
    assert "my-secret-key" not in principal


def test_principal_from_user_id_header():
    assert extract_principal({"X-User-Id": "u-7"}, "1.2.3.4") == "user:u-7"


def test_principal_fallback_is_ip():
    assert extract_principal({}, "1.2.3.4") == "ip:1.2.3.4"


def test_decode_jwt_rejects_garbage():
    assert decode_jwt("abc") is None
    assert decode_jwt("a.b.c") is None
    header, payload = decode_jwt(demo_token("alice"))
    assert header["alg"] == "HS256"
    assert payload["sub"] == "alice"

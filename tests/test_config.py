import json

import pytest

from apishield.config import Config, ConfigError, load_config
from apishield.gateway import parse_content_length
from apishield.pro import pro_enabled
from conftest import make_config


def write(tmp_path, data) -> str:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return str(path)


def test_defaults_are_valid():
    cfg = make_config()
    assert cfg.mode == "monitor"
    assert cfg.rules.bola is True


def test_load_full_config(tmp_path):
    cfg = load_config(write(tmp_path, {
        "upstream": "http://api.internal:3000",
        "mode": "enforce",
        "listen_port": 9090,
        "rules": {"bola": False},
        "thresholds": {"auth_requests_per_window": 5},
    }))
    assert cfg.upstream == "http://api.internal:3000"
    assert cfg.mode == "enforce"
    assert cfg.listen_port == 9090
    assert cfg.rules.bola is False
    assert cfg.rules.jwt is True
    assert cfg.thresholds.auth_requests_per_window == 5


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "nope.json"))


def test_invalid_json(tmp_path):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, "{not json"))


@pytest.mark.parametrize("data", [
    {"mode": "yolo"},                                  # bad mode
    {"upstream": "ftp://example.com"},                 # bad scheme
    {"listen_port": 70000},                            # bad port
    {"surprise": True},                                # unknown key
    {"rules": {"telepathy": True}},                    # unknown rule
    {"rules": {"bola": "yes"}},                        # non-bool toggle
    {"thresholds": {"auth_requests_per_window": 0}},   # non-positive
    {"thresholds": {"nope": 3}},                       # unknown threshold
])
def test_invalid_configs_rejected(tmp_path, data):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, data))



@pytest.mark.parametrize("upstream", ["ftp://example.com", "http://", "http://user:pass@example.com", "http://example.com:99999"])
def test_upstream_must_be_clean_http_url(upstream):
    with pytest.raises(ConfigError):
        Config(upstream=upstream).validate()


def test_listen_port_bool_is_rejected():
    with pytest.raises(ConfigError):
        Config(listen_port=True).validate()


def test_parse_content_length():
    assert parse_content_length(None) == 0
    assert parse_content_length("42") == 42
    assert parse_content_length("-1") == -1
    assert parse_content_length("not-a-number") == -1


def test_pro_gate_defaults_off():
    assert pro_enabled({}) is False
    assert pro_enabled({"APISHIELD_PRO": "1"}) is True
    assert pro_enabled({"APISHIELD_PRO": "off"}) is False

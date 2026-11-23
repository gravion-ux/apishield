import json

import pytest

from apishield.config import ConfigError, load_config
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

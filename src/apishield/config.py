"""Configuration loading and validation for APIShield.

Config is a single JSON file (stdlib ``json`` only — no YAML dependency).
Every field has a sane default so a minimal config is just an upstream URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MODES = ("monitor", "enforce")
RULE_NAMES = ("bola", "jwt", "auth_abuse", "data_exposure", "security_headers")


class ConfigError(ValueError):
    """Raised when a config file is malformed or fails validation."""


@dataclass
class RuleToggles:
    bola: bool = True
    jwt: bool = True
    auth_abuse: bool = True
    data_exposure: bool = True
    security_headers: bool = True

    def enabled(self, name: str) -> bool:
        return bool(getattr(self, name))


@dataclass
class Thresholds:
    # auth abuse: max requests to auth paths per window, per (ip, path)
    auth_requests_per_window: int = 20
    auth_window_seconds: int = 60
    # BOLA probing: distinct sequential object ids per window, per principal
    probe_distinct_ids_per_window: int = 10
    probe_window_seconds: int = 60
    # paths treated as authentication endpoints for the auth-abuse rule
    auth_paths: tuple[str, ...] = ("/login", "/auth", "/token", "/oauth")


@dataclass
class Config:
    upstream: str = "http://127.0.0.1:9000"
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    mode: str = "monitor"
    event_log: str = "apishield-events.jsonl"
    rules: RuleToggles = field(default_factory=RuleToggles)
    thresholds: Thresholds = field(default_factory=Thresholds)
    # response bodies larger than this are not scanned for data exposure
    max_scan_bytes: int = 1_000_000

    def validate(self) -> "Config":
        if self.mode not in MODES:
            raise ConfigError(f"mode must be one of {MODES}, got {self.mode!r}")
        if not (self.upstream.startswith("http://") or self.upstream.startswith("https://")):
            raise ConfigError(f"upstream must be an http(s) URL, got {self.upstream!r}")
        if not (0 <= self.listen_port <= 65535):
            raise ConfigError(f"listen_port out of range: {self.listen_port}")
        t = self.thresholds
        for name in (
            "auth_requests_per_window",
            "auth_window_seconds",
            "probe_distinct_ids_per_window",
            "probe_window_seconds",
        ):
            if getattr(t, name) <= 0:
                raise ConfigError(f"threshold {name} must be positive")
        if self.max_scan_bytes <= 0:
            raise ConfigError("max_scan_bytes must be positive")
        return self


def _from_dict(data: dict[str, Any]) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config root must be a JSON object")
    unknown = set(data) - {
        "upstream", "listen_host", "listen_port", "mode",
        "event_log", "rules", "thresholds", "max_scan_bytes",
    }
    if unknown:
        raise ConfigError(f"unknown config keys: {sorted(unknown)}")

    rules = RuleToggles()
    raw_rules = data.get("rules", {})
    if not isinstance(raw_rules, dict):
        raise ConfigError("rules must be an object")
    for key, value in raw_rules.items():
        if key not in RULE_NAMES:
            raise ConfigError(f"unknown rule toggle: {key!r}")
        if not isinstance(value, bool):
            raise ConfigError(f"rule toggle {key!r} must be true/false")
        setattr(rules, key, value)

    thresholds = Thresholds()
    raw_t = data.get("thresholds", {})
    if not isinstance(raw_t, dict):
        raise ConfigError("thresholds must be an object")
    for key, value in raw_t.items():
        if key == "auth_paths":
            if not isinstance(value, list) or not all(isinstance(p, str) for p in value):
                raise ConfigError("thresholds.auth_paths must be a list of strings")
            thresholds.auth_paths = tuple(value)
        elif hasattr(thresholds, key):
            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigError(f"threshold {key!r} must be an integer")
            setattr(thresholds, key, value)
        else:
            raise ConfigError(f"unknown threshold: {key!r}")

    cfg = Config(
        upstream=data.get("upstream", Config.upstream),
        listen_host=data.get("listen_host", Config.listen_host),
        listen_port=data.get("listen_port", Config.listen_port),
        mode=data.get("mode", Config.mode),
        event_log=data.get("event_log", Config.event_log),
        rules=rules,
        thresholds=thresholds,
        max_scan_bytes=data.get("max_scan_bytes", Config.max_scan_bytes),
    )
    return cfg.validate()


def load_config(path: str | Path | None) -> Config:
    """Load config from a JSON file, or return defaults when path is None."""
    if path is None:
        return Config().validate()
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {p}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file {p} is not valid JSON: {exc}") from exc
    return _from_dict(data)


def default_config() -> Config:
    return Config().validate()

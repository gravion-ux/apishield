import pytest

from apishield.config import Config, Thresholds
from apishield.demo_upstream import demo_token
from apishield.rules import Detector, RequestContext, ResponseContext


def make_config(**overrides) -> Config:
    cfg = Config(event_log="")
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg.validate()


def req(path="/", query="", headers=None, principal="user:alice",
        method="GET", ip="10.0.0.1", body=b"") -> RequestContext:
    return RequestContext(
        method=method, path=path, query=query, headers=headers or {},
        client_ip=ip, principal=principal, body=body,
    )


def resp(body=b"", status=200, headers=None) -> ResponseContext:
    return ResponseContext(status=status, headers=headers or {}, body=body)


@pytest.fixture
def detector() -> Detector:
    return Detector(make_config())


@pytest.fixture
def alice_token() -> str:
    return demo_token("alice")


@pytest.fixture
def bob_token() -> str:
    return demo_token("bob")

from apishield.demo import run_demo


def test_demo_enforce_blocks_attacks():
    lines = run_demo("enforce")
    text = "\n".join(lines)
    assert "BLOCKED" in text
    assert "bola.cross_principal_access" in text
    assert "jwt.alg_none" in text
    assert "auth_abuse.rate_anomaly" in text
    assert "data_exposure" in text


def test_demo_monitor_logs_attacks():
    lines = run_demo("monitor")
    text = "\n".join(lines)
    assert "bola.cross_principal_access" in text
    assert "jwt.alg_none" in text
    assert "auth_abuse.rate_anomaly" in text

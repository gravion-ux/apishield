from apishield.cli import main
from apishield.events import Event, EventStore, load_events
from apishield.report import format_report, summarise


def sample_events() -> list[Event]:
    return [
        Event(rule="bola.cross_principal_access", severity="critical",
              principal="user:bob", method="GET", path="/users/101/profile",
              detail="d", blocked=True),
        Event(rule="jwt.alg_none", severity="critical",
              principal="user:mallory", method="GET", path="/health", detail="d"),
        Event(rule="security_headers.missing", severity="low",
              principal="user:bob", method="GET", path="/users/101/profile", detail="d"),
    ]


def test_summarise_counts():
    summary = summarise(sample_events())
    assert summary["total"] == 3
    assert summary["blocked"] == 1
    assert summary["by_severity"]["critical"] == 2
    assert summary["by_principal"]["user:bob"] == 2


def test_format_report_mentions_rules():
    text = format_report(sample_events())
    assert "bola.cross_principal_access" in text
    assert "BLOCKED" in text


def test_store_round_trip_and_cli_report(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    store = EventStore(log)
    store.record_many(sample_events())
    loaded = load_events(log)
    assert len(loaded) == 3
    assert loaded[0].rule == "bola.cross_principal_access"

    assert main(["report", "--log", str(log)]) == 0
    out = capsys.readouterr().out
    assert "total events : 3" in out

    assert main(["report", "--log", str(log), "--json"]) == 0
    out = capsys.readouterr().out
    assert '"total": 3' in out


def test_load_events_missing_file(tmp_path):
    assert load_events(tmp_path / "absent.jsonl") == []

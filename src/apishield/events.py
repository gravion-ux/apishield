"""Security event model and the JSONL event store.

Events are append-only JSON lines. Evidence is redacted at construction time
(see :mod:`apishield.redact`); the store itself refuses dict evidence that
still contains keys known to carry raw secrets.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

_FORBIDDEN_EVIDENCE_KEYS = {"password", "token", "authorization", "api_key", "secret", "raw_body"}


@dataclass
class Event:
    rule: str
    severity: str
    principal: str
    method: str
    path: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    blocked: bool = False

    def __post_init__(self) -> None:
        if self.severity not in _SEVERITY_RANK:
            raise ValueError(f"unknown severity {self.severity!r}")
        bad = _FORBIDDEN_EVIDENCE_KEYS & {k.lower() for k in self.evidence}
        if bad:
            raise ValueError(f"evidence must not contain raw-secret keys: {sorted(bad)}")

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        return cls(**data)


class EventStore:
    """Thread-safe append-only JSONL store with an in-memory mirror."""

    def __init__(self, path: str | Path | None):
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._events: list[Event] = []
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: Event) -> None:
        with self._lock:
            self._events.append(event)
            if self._path:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict()) + "\n")

    def record_many(self, events: Iterable[Event]) -> None:
        for event in events:
            self.record(event)

    def all(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


def load_events(path: str | Path) -> list[Event]:
    """Read events back from a JSONL file (used by the report CLI)."""
    events: list[Event] = []
    p = Path(path)
    if not p.exists():
        return events
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(Event.from_dict(json.loads(line)))
    return events

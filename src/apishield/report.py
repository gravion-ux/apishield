"""Event summarisation for the ``apishield report`` command."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from .events import Event


def summarise(events: Iterable[Event]) -> dict:
    events = list(events)
    return {
        "total": len(events),
        "blocked": sum(1 for e in events if e.blocked),
        "by_rule": Counter(e.rule for e in events),
        "by_severity": Counter(e.severity for e in events),
        "by_principal": Counter(e.principal for e in events),
    }


def format_report(events: Iterable[Event], recent: int = 10) -> str:
    events = list(events)
    summary = summarise(events)
    lines = [
        "APIShield event report",
        "=" * 60,
        f"total events : {summary['total']}",
        f"blocked      : {summary['blocked']}",
        "",
        "by severity:",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        count = summary["by_severity"].get(severity, 0)
        if count:
            lines.append(f"  {severity:<10} {count}")
    lines.append("")
    lines.append("by rule:")
    for rule, count in summary["by_rule"].most_common():
        lines.append(f"  {rule:<38} {count}")
    lines.append("")
    lines.append("by principal:")
    for principal, count in summary["by_principal"].most_common():
        lines.append(f"  {principal:<38} {count}")
    if events:
        lines.append("")
        lines.append(f"most recent {min(recent, len(events))} events:")
        for event in events[-recent:]:
            flag = " BLOCKED" if event.blocked else ""
            lines.append(
                f"  [{event.severity}] {event.rule} {event.method} {event.path} "
                f"({event.principal}){flag}"
            )
    return "\n".join(lines)

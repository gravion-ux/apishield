"""APIShield command-line interface.

    apishield run --config apishield.json     # start the gateway
    apishield report --log events.jsonl       # summarise recorded events
    apishield demo                            # replay attacks on the demo API
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import ConfigError, load_config
from .events import load_events
from .gateway import Gateway
from .report import format_report, summarise


def _cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    gateway = Gateway(config)
    print(
        f"APIShield {__version__} listening on "
        f"{config.listen_host}:{config.listen_port} -> {config.upstream} "
        f"(mode: {config.mode}, events: {config.event_log})"
    )
    gateway.serve_forever()
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    events = load_events(args.log)
    if args.json:
        summary = summarise(events)
        print(json.dumps({
            "total": summary["total"],
            "blocked": summary["blocked"],
            "by_rule": dict(summary["by_rule"]),
            "by_severity": dict(summary["by_severity"]),
            "by_principal": dict(summary["by_principal"]),
        }, indent=2))
    else:
        print(format_report(events))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    for mode in ("monitor", "enforce"):
        print(f"--- APIShield demo (mode: {mode}) ---")
        for line in run_demo(mode):
            print(line)
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apishield",
        description="APIShield — zero-dependency API security gateway",
    )
    parser.add_argument("--version", action="version", version=f"apishield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="start the gateway")
    run.add_argument("--config", default=None, help="path to a JSON config file")
    run.set_defaults(func=_cmd_run)

    report = sub.add_parser("report", help="summarise recorded events")
    report.add_argument("--log", default="apishield-events.jsonl",
                        help="path to the JSONL event log")
    report.add_argument("--json", action="store_true", help="emit JSON")
    report.set_defaults(func=_cmd_report)

    demo = sub.add_parser("demo", help="run the attack-replay demo")
    demo.set_defaults(func=_cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Command line interface for syslogrouter."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from . import __version__
from .engine import run as run_engine
from .parser import (
    SEVERITY_NAMES,
    Message,
    ParseError,
    format_timestamp,
    parse_line,
    utcnow,
)
from .report import build_dashboard
from .rules import RulesError, load_rules
from .store import Store, StoreError

__all__ = ["EXIT_ERROR", "EXIT_OK", "EXIT_USAGE", "build_parser", "main"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def _iso_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO 8601 date-time: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return number


def _positive_int(value: str) -> int:
    number = _non_negative_int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with every subcommand attached."""
    parser = argparse.ArgumentParser(
        prog="syslogrouter",
        description=(
            "Parse RFC 5424 and RFC 3164 syslog, route events with ordered JSON rules, "
            "store them in SQLite and build a standalone HTML dashboard."
        ),
        epilog="Exit codes: 0 success, 1 runtime or validation error, 2 usage error.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    parse_parser = subparsers.add_parser(
        "parse",
        help="parse one syslog line and print its fields",
        description="Parse one syslog line (RFC 5424, RFC 3164, Cisco-style or lenient).",
    )
    parse_parser.add_argument(
        "line",
        nargs="?",
        help="syslog line to parse; quote it so the shell does not split it",
    )
    parse_parser.add_argument(
        "--stdin",
        action="store_true",
        help="read one message per line from standard input",
    )
    parse_parser.add_argument("--json", action="store_true", help="print the message as JSON")
    parse_parser.set_defaults(func=_cmd_parse)

    run_parser = subparsers.add_parser(
        "run",
        help="route a log file through the rules and store matching events",
        description="Read a syslog file, apply the ordered rules and persist events in SQLite.",
    )
    run_parser.add_argument("--input", required=True, metavar="FILE", help="syslog file to route")
    run_parser.add_argument("--rules", required=True, metavar="FILE", help="JSON routing rules")
    run_parser.add_argument("--db", required=True, metavar="FILE", help="SQLite database path")
    run_parser.add_argument(
        "--keep-unmatched",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="store events that match no rule (default: enabled; counter 'unmatched')",
    )
    run_parser.add_argument(
        "--prune-days",
        type=_non_negative_int,
        default=None,
        metavar="N",
        help="after the run, delete stored events older than N days",
    )
    run_parser.add_argument(
        "--now",
        type=_iso_datetime,
        default=None,
        metavar="ISO",
        help="reference time for RFC 3164 year inference and timestamp-less lines",
    )
    run_parser.add_argument("--json", action="store_true", help="print the run report as JSON")
    run_parser.set_defaults(func=_cmd_run)

    stats_parser = subparsers.add_parser(
        "stats",
        help="print stored event statistics",
        description="Print event counts by severity, top hosts and applications, per-minute "
        "rates and counter totals from the SQLite database.",
    )
    stats_parser.add_argument("--db", required=True, metavar="FILE", help="SQLite database path")
    stats_parser.add_argument(
        "--top",
        type=_positive_int,
        default=10,
        metavar="N",
        help="number of hosts and applications to print (default: 10)",
    )
    stats_parser.add_argument("--json", action="store_true", help="print the statistics as JSON")
    stats_parser.set_defaults(func=_cmd_stats)

    report_parser = subparsers.add_parser(
        "report",
        help="build a standalone HTML dashboard from the store",
        description="Render a self-contained HTML dashboard from the SQLite event database.",
    )
    report_parser.add_argument("--db", required=True, metavar="FILE", help="SQLite database path")
    report_parser.add_argument(
        "--out", required=True, metavar="FILE", help="destination HTML file"
    )
    report_parser.add_argument(
        "--title",
        default="Syslog Router dashboard",
        metavar="TEXT",
        help="dashboard title (default: Syslog Router dashboard)",
    )
    report_parser.add_argument(
        "--now",
        type=_iso_datetime,
        default=None,
        metavar="ISO",
        help="generation timestamp written into the dashboard",
    )
    report_parser.set_defaults(func=_cmd_report)

    rules_parser = subparsers.add_parser(
        "rules",
        help="inspect and validate routing rules",
        description="Validate a JSON routing rule set without running an import.",
    )
    rules_subparsers = rules_parser.add_subparsers(
        dest="rules_command", metavar="command", required=True
    )
    validate_parser = rules_subparsers.add_parser(
        "validate",
        help="validate a JSON rules file",
        description="Check JSON syntax, schema, facility names and regular expressions.",
    )
    validate_parser.add_argument("path", metavar="FILE", help="JSON rules file to validate")
    validate_parser.set_defaults(func=_cmd_rules_validate)

    version_parser = subparsers.add_parser(
        "version",
        help="print the program version",
        description="Print the program name and version.",
    )
    version_parser.set_defaults(func=_cmd_version)

    return parser


def _format_structured_data(elements: list[tuple[str, dict[str, str]]]) -> str:
    if not elements:
        return "-"
    parts = []
    for sd_id, params in elements:
        rendered = " ".join(f"{name}={json.dumps(value)}" for name, value in params.items())
        parts.append(f"{sd_id} {rendered}".rstrip())
    return "; ".join(parts)


def _format_message(message: Message, as_json: bool) -> str:
    if as_json:
        return json.dumps(message.to_dict(), indent=2, ensure_ascii=False)
    rows = [
        ("format", message.format),
        ("pri", str(message.pri)),
        ("facility", f"{message.facility} ({message.facility_name})"),
        ("severity", f"{message.severity} ({message.severity_name})"),
        ("timestamp", format_timestamp(message.timestamp) or "-"),
        ("hostname", message.hostname or "-"),
        ("app_name", message.app_name or "-"),
        ("proc_id", message.proc_id or "-"),
        ("msg_id", message.msg_id or "-"),
        ("structured", _format_structured_data(message.structured_data)),
        ("msg", message.msg),
    ]
    return "\n".join(f"{label:<11}{value}" for label, value in rows)


def _open_database(path: str) -> Store:
    if not Path(path).is_file():
        raise StoreError(f"database not found: {path}")
    return Store(path)


def _cmd_parse(args: argparse.Namespace) -> int:
    if args.stdin and args.line is not None:
        print("error: pass either a LINE argument or --stdin, not both", file=sys.stderr)
        return EXIT_USAGE
    if args.line is None and not args.stdin:
        print("error: pass a LINE argument or --stdin", file=sys.stderr)
        return EXIT_USAGE
    if args.stdin:
        failed = False
        for number, line in enumerate(sys.stdin.read().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                message = parse_line(line)
            except ParseError as exc:
                print(f"line {number}: error: {exc}", file=sys.stderr)
                failed = True
                continue
            if number > 1:
                print()
            print(_format_message(message, args.json))
        return EXIT_ERROR if failed else EXIT_OK
    try:
        message = parse_line(args.line)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(_format_message(message, args.json))
    return EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    reference = args.now or utcnow()
    report = run_engine(
        args.input,
        rules,
        args.db,
        keep_unmatched=args.keep_unmatched,
        now=reference,
        prune_days=args.prune_days,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK
    print(f"input        {args.input}")
    print(f"lines        {report.lines}")
    print(f"parsed       {report.parsed}")
    print(f"parse errors {report.errors}")
    print(f"stored       {report.stored}")
    print(f"dropped      {report.dropped}")
    if report.pruned:
        print(f"pruned       {report.pruned}")
    if report.counters:
        print("counters")
        width = max(len(name) for name in report.counters)
        for name, count in report.counters.items():
            print(f"  {name:<{width}}  {count}")
    if report.files:
        print("files")
        width = max(len(path) for path in report.files)
        for path, count in report.files.items():
            print(f"  {path:<{width}}  {count} lines")
    return EXIT_OK


def _print_rows(rows: list[tuple[str, int]]) -> None:
    if not rows:
        print("  (none)")
        return
    width = max(len(name) for name, _ in rows)
    for name, count in rows:
        print(f"  {name:<{width}}  {count}")


def _cmd_stats(args: argparse.Namespace) -> int:
    with _open_database(args.db) as store:
        stats = store.stats(top=args.top)
    if args.json:
        payload = stats.to_dict()
        payload["database"] = args.db
        print(json.dumps(payload, indent=2))
        return EXIT_OK
    print(f"database   {args.db}")
    print(f"events     {stats.events}")
    window = f"{stats.first_ts or 'n/a'} .. {stats.last_ts or 'n/a'}"
    print(f"window     {window}")
    print("severity")
    width = max(len(name) for name in SEVERITY_NAMES)
    for name in SEVERITY_NAMES:
        print(f"  {name:<{width}}  {stats.severity[name]}")
    print("counters")
    _print_rows(stats.counters)
    print("top hosts")
    _print_rows(stats.top_hosts)
    print("top apps")
    _print_rows(stats.top_apps)
    print("per-minute rates")
    if not stats.per_minute:
        print("  (none)")
    for minute, count in stats.per_minute:
        print(f"  {minute}  {count}")
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    with _open_database(args.db) as store:
        events = store.event_count()
    output = build_dashboard(args.db, args.out, title=args.title, now=args.now)
    print(f"wrote dashboard {output.as_posix()} ({events} events)")
    return EXIT_OK


def _cmd_rules_validate(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.path)
    except RulesError as exc:
        for line in str(exc).splitlines():
            print(f"error: {line}", file=sys.stderr)
        return EXIT_ERROR
    print(f"rules OK: {len(rules.rules)} rules in {args.path}")
    return EXIT_OK


def _cmd_version(args: argparse.Namespace) -> int:
    print(f"syslogrouter {__version__}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RulesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (StoreError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

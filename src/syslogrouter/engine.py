"""Routing engine: read syslog lines, apply rules and persist events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .parser import ParseError, parse_line, utcnow
from .rules import RuleSet
from .store import Store

__all__ = ["RunReport", "run"]


@dataclass
class RunReport:
    """Counters describing one routing run."""

    lines: int = 0
    parsed: int = 0
    errors: int = 0
    stored: int = 0
    dropped: int = 0
    counters: dict[str, int] = field(default_factory=dict)
    files: dict[str, int] = field(default_factory=dict)
    pruned: int = 0
    parse_errors: list[tuple[int, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the run report."""
        return {
            "lines": self.lines,
            "parsed": self.parsed,
            "errors": self.errors,
            "stored": self.stored,
            "dropped": self.dropped,
            "pruned": self.pruned,
            "counters": dict(sorted(self.counters.items())),
            "files": dict(sorted(self.files.items())),
            "parse_errors": [[number, message] for number, message in self.parse_errors],
        }


def run(
    input_path: str | Path,
    rules: RuleSet,
    db_path: str | Path,
    keep_unmatched: bool = True,
    now: datetime | None = None,
    prune_days: int | None = None,
    base_dir: str | Path | None = None,
) -> RunReport:
    """Route every line of *input_path* through *rules* and store the events.

    ``now`` is the reference time for timestamp-less lines and for RFC 3164
    year inference.  ``file`` actions are resolved against ``base_dir``
    (default: the current working directory) and appended to, one line per
    event.  ``prune_days`` deletes stored events older than that many days
    after the run completes.
    """
    reference = now or utcnow()
    base = Path(base_dir) if base_dir is not None else Path.cwd()
    report = RunReport()
    counters: dict[str, int] = {}
    file_buffers: dict[str, list[str]] = {}

    with Store(db_path) as store:
        with Path(input_path).open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\r\n")
                report.lines += 1
                if not line.strip():
                    continue
                try:
                    message = parse_line(line, now=reference)
                except ParseError as exc:
                    report.errors += 1
                    report.parse_errors.append((line_number, str(exc)))
                    continue
                report.parsed += 1
                event_time = message.timestamp or reference
                store_event = True
                dropped = False
                matched = rules.matching(message)
                for rule in matched:
                    action = rule.action
                    if action.drop:
                        dropped = True
                    if action.store is not None:
                        store_event = action.store
                    if action.counter:
                        counters[action.counter] = counters.get(action.counter, 0) + 1
                    if action.file:
                        file_buffers.setdefault(action.file, []).append(line)
                    if rule.stop:
                        break
                if dropped:
                    store_event = False
                if not matched:
                    counters["unmatched"] = counters.get("unmatched", 0) + 1
                    store_event = keep_unmatched
                if store_event:
                    store.insert_event(message, event_time)
                    report.stored += 1
                else:
                    report.dropped += 1

        for name, amount in counters.items():
            store.add_counter(name, amount)
        report.counters = dict(sorted(counters.items()))

        for relative_path, buffered in file_buffers.items():
            target = base / relative_path
            if target.parent != base:
                target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as output:
                output.write("".join(f"{line}\n" for line in buffered))
            report.files[relative_path] = len(buffered)
        report.files = dict(sorted(report.files.items()))

        if prune_days is not None:
            report.pruned = store.prune(prune_days, reference)
    return report

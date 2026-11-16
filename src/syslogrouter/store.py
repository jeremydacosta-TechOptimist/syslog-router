"""SQLite event store with counters, statistics and retention pruning."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .parser import SEVERITY_NAMES, Message, format_timestamp, utcnow

__all__ = ["DEFAULT_TOP", "SCHEMA_VERSION", "Stats", "Store", "StoreError"]

#: Current schema version stored in the ``meta`` table.
SCHEMA_VERSION = "1"

#: Default number of hosts and applications returned by :meth:`Store.stats`.
DEFAULT_TOP = 10

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    host TEXT,
    app TEXT,
    severity INTEGER NOT NULL,
    facility INTEGER NOT NULL,
    msg TEXT NOT NULL,
    raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_app ON events(app);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    n INTEGER NOT NULL DEFAULT 0
);
"""


class StoreError(RuntimeError):
    """Raised when the SQLite database cannot be opened or is incompatible."""


@dataclass(frozen=True)
class Stats:
    """Aggregated statistics computed from the event store."""

    events: int
    first_ts: str | None
    last_ts: str | None
    severity: dict[str, int]
    top_hosts: list[tuple[str, int]]
    top_apps: list[tuple[str, int]]
    per_minute: list[tuple[str, int]]
    counters: list[tuple[str, int]]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the statistics."""
        return {
            "events": self.events,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "severity": dict(self.severity),
            "top_hosts": [[name, count] for name, count in self.top_hosts],
            "top_apps": [[name, count] for name, count in self.top_apps],
            "per_minute": [[minute, count] for minute, count in self.per_minute],
            "counters": {name: count for name, count in self.counters},
        }


class Store:
    """A SQLite-backed store for parsed syslog events.

    The store keeps normalised events in ``events``, running counters in
    ``counters`` and the schema version in ``meta``.  It can be used as a
    context manager::

        with Store("out/events.db") as store:
            store.insert_event(message, message.timestamp)
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn: sqlite3.Connection | None = None
        try:
            if self.path != ":memory:":
                parent = Path(self.path).expanduser().parent
                if str(parent) not in ("", "."):
                    parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path)
            connection.row_factory = sqlite3.Row
            self._conn = connection
            connection.executescript(_SCHEMA)
            self._initialise_meta()
        except sqlite3.DatabaseError as exc:
            self._close_quietly()
            raise StoreError(f"cannot open event database {self.path}: {exc}") from exc
        except StoreError:
            self._close_quietly()
            raise

    def _close_quietly(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _initialise_meta(self) -> None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,),
            )
            self._conn.commit()
        elif row["value"] != SCHEMA_VERSION:
            raise StoreError(
                f"database {self.path} uses schema version {row['value']}, "
                f"this build expects {SCHEMA_VERSION}"
            )

    @property
    def schema_version(self) -> str:
        """Return the schema version recorded in the database."""
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        return str(row["value"])

    def insert_event(self, message: Message, timestamp: datetime | None = None) -> int:
        """Insert one parsed message and return the new row id."""
        moment = timestamp or message.timestamp or utcnow()
        cursor = self._conn.execute(
            "INSERT INTO events(ts, host, app, severity, facility, msg, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                format_timestamp(moment),
                message.hostname,
                message.app_name,
                message.severity,
                message.facility,
                message.msg,
                message.raw,
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    def add_counter(self, name: str, amount: int = 1) -> int:
        """Add *amount* to the named counter and return the new total."""
        if amount == 0:
            return self.counter(name)
        self._conn.execute("INSERT OR IGNORE INTO counters(name, n) VALUES (?, 0)", (name,))
        self._conn.execute("UPDATE counters SET n = n + ? WHERE name = ?", (amount, name))
        self._conn.commit()
        return self.counter(name)

    def counter(self, name: str) -> int:
        """Return the current value of one counter (0 when it does not exist)."""
        row = self._conn.execute("SELECT n FROM counters WHERE name = ?", (name,)).fetchone()
        return int(row["n"]) if row is not None else 0

    def counters(self) -> list[tuple[str, int]]:
        """Return all counters ordered by decreasing total then by name."""
        rows = self._conn.execute("SELECT name, n FROM counters ORDER BY n DESC, name ASC")
        return [(str(row["name"]), int(row["n"])) for row in rows]

    def event_count(self) -> int:
        """Return the number of stored events."""
        row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def stats(self, top: int = DEFAULT_TOP) -> Stats:
        """Compute severity, host, application, per-minute and counter statistics."""
        total = self.event_count()
        window = self._conn.execute("SELECT MIN(ts) AS first, MAX(ts) AS last FROM events").fetchone()
        severity_rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS n FROM events GROUP BY severity"
        )
        severity_counts = {index: 0 for index in range(len(SEVERITY_NAMES))}
        for row in severity_rows:
            severity_counts[int(row["severity"])] = int(row["n"])
        severity = {SEVERITY_NAMES[index]: severity_counts[index] for index in range(len(SEVERITY_NAMES))}
        top_hosts = self._top_values("host", top)
        top_apps = self._top_values("app", top)
        minute_rows = self._conn.execute(
            "SELECT substr(ts, 1, 16) AS minute, COUNT(*) AS n FROM events "
            "GROUP BY minute ORDER BY minute ASC"
        )
        per_minute = [(str(row["minute"]), int(row["n"])) for row in minute_rows]
        return Stats(
            events=total,
            first_ts=window["first"],
            last_ts=window["last"],
            severity=severity,
            top_hosts=top_hosts,
            top_apps=top_apps,
            per_minute=per_minute,
            counters=self.counters(),
        )

    def _top_values(self, column: str, limit: int) -> list[tuple[str, int]]:
        if column not in ("host", "app"):
            raise StoreError(f"unsupported statistics column: {column}")
        rows = self._conn.execute(
            f"SELECT COALESCE({column}, '') AS value, COUNT(*) AS n FROM events "
            f"GROUP BY COALESCE({column}, '') ORDER BY n DESC, value ASC LIMIT ?",
            (max(0, limit),),
        )
        return [((str(row["value"]) or "(unknown)"), int(row["n"])) for row in rows]

    def prune(self, days: int, now: datetime | None = None) -> int:
        """Delete events older than *days* before *now* and return the row count."""
        cutoff = format_timestamp((now or utcnow()) - timedelta(days=days))
        cursor = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        self._conn.commit()
        return int(cursor.rowcount)

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most recent events as dictionaries, newest first."""
        rows = self._conn.execute(
            "SELECT id, ts, COALESCE(host, '') AS host, COALESCE(app, '') AS app, "
            "severity, facility, msg, raw FROM events ORDER BY ts DESC, id DESC LIMIT ?",
            (max(0, limit),),
        )
        return [dict(row) for row in rows]

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

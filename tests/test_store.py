"""Tests for the SQLite event store."""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from syslogrouter.parser import parse_line
from syslogrouter.store import SCHEMA_VERSION, Store, StoreError

UTC = timezone.utc


def make_message(pri=13, host="host.example", app="app", msg="text"):
    host_field = host or "-"
    app_field = app or "-"
    return parse_line(f"<{pri}>1 - {host_field} {app_field} - - - {msg}")


def add_event(store, timestamp, pri=13, host="host.example", app="app", msg="text"):
    message = make_message(pri=pri, host=host, app=app, msg=msg)
    return store.insert_event(message, timestamp)


class StoreBasicsTests(unittest.TestCase):
    """Schema creation, insertion and raw access."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "events.db"

    def test_creates_database_file(self):
        with Store(self.path):
            pass
        self.assertTrue(self.path.is_file())

    def test_schema_version(self):
        with Store(self.path) as store:
            self.assertEqual(store.schema_version, SCHEMA_VERSION)

    def test_expected_tables_exist(self):
        with Store(self.path) as store:
            rows = store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            names = {row["name"] for row in rows}
        self.assertTrue({"events", "counters", "meta"} <= names)

    def test_insert_returns_incrementing_ids(self):
        moment = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        with Store(self.path) as store:
            first = add_event(store, moment)
            second = add_event(store, moment)
            self.assertGreater(second, first)

    def test_event_count(self):
        moment = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        with Store(self.path) as store:
            for _ in range(3):
                add_event(store, moment)
            self.assertEqual(store.event_count(), 3)

    def test_insert_uses_explicit_timestamp(self):
        moment = datetime(2026, 3, 1, 22, 14, 15, tzinfo=UTC)
        with Store(self.path) as store:
            add_event(store, moment)
            row = store.recent(1)[0]
        self.assertEqual(row["ts"], "2026-03-01T22:14:15.000000Z")

    def test_insert_uses_message_timestamp(self):
        message = parse_line("<13>1 2003-10-11T22:14:15.003Z host app - - - hello")
        with Store(self.path) as store:
            store.insert_event(message)
            row = store.recent(1)[0]
        self.assertEqual(row["ts"], "2003-10-11T22:14:15.003000Z")

    def test_insert_falls_back_to_current_time(self):
        message = parse_line("<13>1 - host app - - - hello")
        with Store(self.path) as store:
            store.insert_event(message)
            row = store.recent(1)[0]
        self.assertTrue(row["ts"].endswith("Z"))

    def test_message_fields_persisted(self):
        message = parse_line("<165>1 - fw-edge-01.example trafficmon - - - BLOCKED TCP")
        with Store(self.path) as store:
            store.insert_event(message, datetime(2026, 3, 1, tzinfo=UTC))
            row = store.recent(1)[0]
        self.assertEqual(row["host"], "fw-edge-01.example")
        self.assertEqual(row["app"], "trafficmon")
        self.assertEqual(row["severity"], 5)
        self.assertEqual(row["facility"], 20)
        self.assertEqual(row["msg"], "BLOCKED TCP")
        self.assertEqual(row["raw"], message.raw)

    def test_missing_host_is_stored_as_null(self):
        message = parse_line("<13>1 - - app - - - hello")
        with Store(self.path) as store:
            store.insert_event(message, datetime(2026, 3, 1, tzinfo=UTC))
            row = store.recent(1)[0]
            self.assertEqual(row["host"], "")
            stats = store.stats()
        self.assertEqual(stats.top_hosts, [("(unknown)", 1)])

    def test_context_manager_closes_connection(self):
        store = Store(self.path)
        with store:
            pass
        with self.assertRaises(sqlite3.ProgrammingError):
            store._conn.execute("SELECT 1")

    def test_reopen_keeps_events(self):
        moment = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        with Store(self.path) as store:
            add_event(store, moment)
        with Store(self.path) as store:
            self.assertEqual(store.event_count(), 1)

    def test_nested_parent_directories_created(self):
        nested = Path(self.directory.name) / "a" / "b" / "events.db"
        with Store(nested) as store:
            add_event(store, datetime(2026, 3, 1, tzinfo=UTC))
        self.assertTrue(nested.is_file())

    def test_schema_version_mismatch_is_reported(self):
        connection = sqlite3.connect(self.path)
        connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO meta VALUES ('schema_version', '99')")
        connection.commit()
        connection.close()
        with self.assertRaises(StoreError) as caught:
            Store(self.path)
        self.assertIn("schema version", str(caught.exception))

    def test_invalid_database_file_is_reported(self):
        self.path.write_bytes(b"this is not a sqlite database")
        with self.assertRaises(StoreError) as caught:
            Store(self.path)
        self.assertIn("cannot open event database", str(caught.exception))

    def test_in_memory_store(self):
        with Store(":memory:") as store:
            add_event(store, datetime(2026, 3, 1, tzinfo=UTC))
            self.assertEqual(store.event_count(), 1)


class CounterTests(unittest.TestCase):
    """Running counters."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "counters.db"

    def test_counter_starts_at_zero(self):
        with Store(self.path) as store:
            self.assertEqual(store.counter("unmatched"), 0)

    def test_add_counter_increments(self):
        with Store(self.path) as store:
            self.assertEqual(store.add_counter("auth_failures"), 1)
            self.assertEqual(store.add_counter("auth_failures"), 2)
            self.assertEqual(store.counter("auth_failures"), 2)

    def test_add_counter_with_amount(self):
        with Store(self.path) as store:
            self.assertEqual(store.add_counter("events", 5), 5)

    def test_add_counter_zero_preserves_value(self):
        with Store(self.path) as store:
            store.add_counter("events", 3)
            self.assertEqual(store.add_counter("events", 0), 3)

    def test_counters_order(self):
        with Store(self.path) as store:
            store.add_counter("b", 2)
            store.add_counter("a", 2)
            store.add_counter("c", 9)
            self.assertEqual(store.counters(), [("c", 9), ("a", 2), ("b", 2)])

    def test_counters_persist_across_reopen(self):
        with Store(self.path) as store:
            store.add_counter("kept", 4)
        with Store(self.path) as store:
            self.assertEqual(store.counter("kept"), 4)

    def test_counters_empty_list(self):
        with Store(self.path) as store:
            self.assertEqual(store.counters(), [])


class StatsTests(unittest.TestCase):
    """Aggregated statistics."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "stats.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.add_event = lambda *args, **kwargs: add_event(self.store, *args, **kwargs)

    def test_event_count(self):
        self.add_event(datetime(2026, 3, 1, 12, 0, tzinfo=UTC))
        self.assertEqual(self.store.stats().events, 1)

    def test_severity_has_every_name(self):
        stats = self.store.stats()
        self.assertEqual(
            list(stats.severity),
            ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
        )

    def test_severity_counts(self):
        base = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        self.add_event(base, pri=0)  # emerg
        self.add_event(base, pri=0)  # emerg
        self.add_event(base, pri=4)  # warning
        stats = self.store.stats()
        self.assertEqual(stats.severity["emerg"], 2)
        self.assertEqual(stats.severity["warning"], 1)
        self.assertEqual(stats.severity["info"], 0)

    def test_top_hosts_order(self):
        base = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        self.add_event(base, host="b.example")
        self.add_event(base, host="a.example")
        self.add_event(base, host="a.example")
        stats = self.store.stats()
        self.assertEqual(stats.top_hosts, [("a.example", 2), ("b.example", 1)])

    def test_top_hosts_limit(self):
        base = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        for index in range(5):
            self.add_event(base, host=f"host-{index}.example")
        self.assertEqual(len(self.store.stats(top=2).top_hosts), 2)

    def test_top_apps_order(self):
        base = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        self.add_event(base, app="sshd")
        self.add_event(base, app="sshd")
        self.add_event(base, app="CRON")
        stats = self.store.stats()
        self.assertEqual(stats.top_apps[0], ("sshd", 2))
        self.assertEqual(stats.top_apps[1], ("CRON", 1))

    def test_top_values_rejects_unknown_column(self):
        with self.assertRaises(StoreError):
            self.store._top_values("msg", 5)

    def test_per_minute_rates(self):
        self.add_event(datetime(2026, 3, 1, 22, 14, 10, tzinfo=UTC))
        self.add_event(datetime(2026, 3, 1, 22, 14, 50, tzinfo=UTC))
        self.add_event(datetime(2026, 3, 1, 22, 15, 1, tzinfo=UTC))
        stats = self.store.stats()
        self.assertEqual(
            stats.per_minute,
            [("2026-03-01T22:14", 2), ("2026-03-01T22:15", 1)],
        )

    def test_window(self):
        self.add_event(datetime(2026, 3, 1, 22, 14, 10, tzinfo=UTC))
        self.add_event(datetime(2026, 3, 1, 22, 15, 1, tzinfo=UTC))
        stats = self.store.stats()
        self.assertEqual(stats.first_ts, "2026-03-01T22:14:10.000000Z")
        self.assertEqual(stats.last_ts, "2026-03-01T22:15:01.000000Z")

    def test_window_empty_store(self):
        stats = self.store.stats()
        self.assertIsNone(stats.first_ts)
        self.assertIsNone(stats.last_ts)

    def test_stats_counters(self):
        self.store.add_counter("auth_failures", 4)
        self.store.add_counter("unmatched", 13)
        self.assertEqual(self.store.stats().counters, [("unmatched", 13), ("auth_failures", 4)])

    def test_stats_to_dict(self):
        self.add_event(datetime(2026, 3, 1, 22, 14, 10, tzinfo=UTC), pri=0)
        payload = self.store.stats().to_dict()
        self.assertEqual(payload["events"], 1)
        self.assertEqual(payload["severity"]["emerg"], 1)
        self.assertEqual(payload["per_minute"], [["2026-03-01T22:14", 1]])
        self.assertEqual(payload["top_hosts"][0][0], "host.example")


class PruneTests(unittest.TestCase):
    """Retention pruning with an injected clock."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "prune.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)

    def test_prune_removes_old_events(self):
        self.store.insert_event(
            make_message(), datetime(2026, 1, 1, tzinfo=UTC)
        )
        removed = self.store.prune(days=30, now=datetime(2026, 3, 2, tzinfo=UTC))
        self.assertEqual(removed, 1)
        self.assertEqual(self.store.event_count(), 0)

    def test_prune_keeps_recent_events(self):
        self.store.insert_event(make_message(), datetime(2026, 3, 1, tzinfo=UTC))
        removed = self.store.prune(days=30, now=datetime(2026, 3, 2, tzinfo=UTC))
        self.assertEqual(removed, 0)
        self.assertEqual(self.store.event_count(), 1)

    def test_prune_returns_deleted_count(self):
        for day in (1, 2, 3):
            self.store.insert_event(
                make_message(), datetime(2026, 1, day, tzinfo=UTC)
            )
        removed = self.store.prune(days=30, now=datetime(2026, 3, 2, tzinfo=UTC))
        self.assertEqual(removed, 3)

    def test_prune_with_injected_now_keeps_boundary(self):
        self.store.insert_event(make_message(), datetime(2026, 2, 1, tzinfo=UTC))
        self.store.insert_event(make_message(), datetime(2026, 1, 30, tzinfo=UTC))
        removed = self.store.prune(days=30, now=datetime(2026, 3, 2, tzinfo=UTC))
        self.assertEqual(removed, 1)
        self.assertEqual(self.store.event_count(), 1)

    def test_prune_zero_days_removes_only_past(self):
        self.store.insert_event(make_message(), datetime(2026, 1, 1, tzinfo=UTC))
        self.store.insert_event(make_message(), datetime(2026, 12, 1, tzinfo=UTC))
        removed = self.store.prune(days=0, now=datetime(2026, 3, 2, tzinfo=UTC))
        self.assertEqual(removed, 1)

    def test_prune_empty_store(self):
        self.assertEqual(self.store.prune(days=7, now=datetime(2026, 3, 2, tzinfo=UTC)), 0)


class RecentTests(unittest.TestCase):
    """Recent-event listing used by the dashboard and JSON output."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "recent.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)

    def test_recent_newest_first(self):
        self.store.insert_event(make_message(), datetime(2026, 3, 1, 10, 0, tzinfo=UTC))
        self.store.insert_event(make_message(), datetime(2026, 3, 1, 12, 0, tzinfo=UTC))
        rows = self.store.recent(10)
        self.assertEqual(rows[0]["ts"], "2026-03-01T12:00:00.000000Z")

    def test_recent_limit(self):
        for index in range(5):
            self.store.insert_event(
                make_message(), datetime(2026, 3, 1, 10, index, tzinfo=UTC)
            )
        self.assertEqual(len(self.store.recent(2)), 2)

    def test_recent_row_keys(self):
        self.store.insert_event(make_message(), datetime(2026, 3, 1, 10, 0, tzinfo=UTC))
        row = self.store.recent(1)[0]
        self.assertEqual(
            set(row),
            {"id", "ts", "host", "app", "severity", "facility", "msg", "raw"},
        )

    def test_recent_empty_store(self):
        self.assertEqual(self.store.recent(10), [])

    def test_recent_coalesces_missing_host(self):
        message = parse_line("<13>1 - - - - - - hello")
        self.store.insert_event(message, datetime(2026, 3, 1, 10, 0, tzinfo=UTC))
        self.assertEqual(self.store.recent(1)[0]["host"], "")


if __name__ == "__main__":
    unittest.main()

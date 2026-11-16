"""Tests for the routing engine."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from syslogrouter.engine import RunReport, run
from syslogrouter.rules import build_ruleset
from syslogrouter.store import Store

UTC = timezone.utc
NOW = datetime(2026, 3, 2, 0, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_LOG = ROOT / "examples" / "lab-logs" / "mixed.log"
EXAMPLE_RULES = ROOT / "examples" / "lab-rules.json"


def ruleset(*rules):
    return build_ruleset({"rules": list(rules)})


def rule(name, match, action=None, stop=None):
    data = {"name": name, "match": match, "action": action if action is not None else {}}
    if stop is not None:
        data["stop"] = stop
    return data


class EngineFixtureTests(unittest.TestCase):
    """End-to-end run over the committed lab fixtures."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.db = self.base / "lab.db"
        rules_data = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
        self.rules = build_ruleset(rules_data)

    def test_counts(self):
        report = run(EXAMPLE_LOG, self.rules, self.db, now=NOW, base_dir=self.base)
        self.assertEqual(report.lines, 30)
        self.assertEqual(report.parsed, 30)
        self.assertEqual(report.errors, 0)
        self.assertEqual(report.stored, 26)
        self.assertEqual(report.dropped, 4)

    def test_counters(self):
        report = run(EXAMPLE_LOG, self.rules, self.db, now=NOW, base_dir=self.base)
        self.assertEqual(
            report.counters,
            {
                "auth_failures": 4,
                "crit_alerts": 2,
                "cron_jobs": 3,
                "firewall_denies": 4,
                "unmatched": 13,
            },
        )

    def test_events_are_stored(self):
        run(EXAMPLE_LOG, self.rules, self.db, now=NOW, base_dir=self.base)
        with Store(self.db) as store:
            self.assertEqual(store.event_count(), 26)
            self.assertEqual(store.counter("auth_failures"), 4)
            self.assertEqual(store.counter("unmatched"), 13)

    def test_file_action_written(self):
        report = run(EXAMPLE_LOG, self.rules, self.db, now=NOW, base_dir=self.base)
        self.assertEqual(report.files, {"out/denied-events.log": 4})
        content = (self.base / "out" / "denied-events.log").read_text(encoding="utf-8")
        lines = content.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(all("fw-edge" in line for line in lines))

    def test_second_run_appends_file_and_counters(self):
        run(EXAMPLE_LOG, self.rules, self.db, now=NOW, base_dir=self.base)
        run(EXAMPLE_LOG, self.rules, self.db, now=NOW, base_dir=self.base)
        content = (self.base / "out" / "denied-events.log").read_text(encoding="utf-8")
        self.assertEqual(len(content.splitlines()), 8)
        with Store(self.db) as store:
            self.assertEqual(store.event_count(), 52)
            self.assertEqual(store.counter("auth_failures"), 8)


class EngineBehaviourTests(unittest.TestCase):
    """Counters, drop/store decisions, stop handling and timestamps."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.db = self.base / "test.db"

    def write_log(self, name, lines):
        path = self.base / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_blank_lines_are_skipped(self):
        path = self.write_log("blank.log", ["<13>Mar  1 10:00:00 host app: one", "", "   "])
        report = run(path, ruleset(), self.db, now=NOW)
        self.assertEqual(report.lines, 3)
        self.assertEqual(report.parsed, 1)
        self.assertEqual(report.errors, 0)
        self.assertEqual(report.stored, 1)

    def test_parse_errors_are_counted(self):
        path = self.write_log(
            "broken.log",
            ["<34>1 not-a-timestamp host app - - - bad", "<13>Mar  1 10:00:00 host app: good"],
        )
        report = run(path, ruleset(), self.db, now=NOW)
        self.assertEqual(report.errors, 1)
        self.assertEqual(report.parsed, 1)
        self.assertEqual(report.stored, 1)
        self.assertEqual(report.parse_errors[0][0], 1)
        self.assertIn("timestamp", report.parse_errors[0][1])

    def test_unmatched_events_stored_by_default(self):
        path = self.write_log("one.log", ["<13>Mar  1 10:00:00 host app: hello"])
        report = run(path, ruleset(), self.db, now=NOW)
        self.assertEqual(report.stored, 1)
        self.assertEqual(report.dropped, 0)
        self.assertEqual(report.counters, {"unmatched": 1})

    def test_unmatched_events_can_be_skipped(self):
        path = self.write_log("one.log", ["<13>Mar  1 10:00:00 host app: hello"])
        report = run(path, ruleset(), self.db, now=NOW, keep_unmatched=False)
        self.assertEqual(report.stored, 0)
        self.assertEqual(report.dropped, 1)
        self.assertEqual(report.counters, {"unmatched": 1})

    def test_drop_action(self):
        path = self.write_log("drop.log", ["<13>Mar  1 10:00:00 host app: noisy"])
        report = run(path, ruleset(rule("drop", {"regex": "noisy"}, {"drop": True})), self.db, now=NOW)
        self.assertEqual(report.stored, 0)
        self.assertEqual(report.dropped, 1)
        with Store(self.db) as store:
            self.assertEqual(store.event_count(), 0)

    def test_store_false_action(self):
        path = self.write_log("skip.log", ["<13>Mar  1 10:00:00 host app: skip me"])
        report = run(path, ruleset(rule("skip", {}, {"store": False})), self.db, now=NOW)
        self.assertEqual(report.stored, 0)
        self.assertEqual(report.dropped, 1)

    def test_stop_prevents_later_rules(self):
        path = self.write_log("stop.log", ["<13>Mar  1 10:00:00 host app: hello"])
        rules = ruleset(
            rule("first", {}, {"counter": "first"}, stop=True),
            rule("second", {}, {"counter": "second"}),
        )
        report = run(path, rules, self.db, now=NOW)
        self.assertEqual(report.counters, {"first": 1})

    def test_all_matching_rules_apply_without_stop(self):
        path = self.write_log("all.log", ["<13>Mar  1 10:00:00 host app: hello"])
        rules = ruleset(
            rule("first", {}, {"counter": "first"}),
            rule("second", {}, {"counter": "second"}),
        )
        report = run(path, rules, self.db, now=NOW)
        self.assertEqual(report.counters, {"first": 1, "second": 1})

    def test_counter_counts_dropped_events(self):
        path = self.write_log("count.log", ["<13>Mar  1 10:00:00 host app: hello"])
        rules = ruleset(
            rule("drop", {}, {"drop": True}),
            rule("count", {}, {"counter": "seen"}),
        )
        report = run(path, rules, self.db, now=NOW)
        self.assertEqual(report.counters, {"seen": 1})
        self.assertEqual(report.dropped, 1)

    def test_timestamp_less_line_uses_reference_time(self):
        path = self.write_log("lenient.log", ["line without a syslog header"])
        report = run(path, ruleset(), self.db, now=NOW)
        self.assertEqual(report.stored, 1)
        with Store(self.db) as store:
            self.assertEqual(store.recent(1)[0]["ts"], "2026-03-02T00:00:00.000000Z")

    def test_rfc3164_year_uses_reference_time(self):
        path = self.write_log("legacy.log", ["<13>Mar  1 10:00:00 host app: hello"])
        later = datetime(2031, 6, 1, tzinfo=UTC)
        run(path, ruleset(), self.db, now=later)
        with Store(self.db) as store:
            self.assertTrue(store.recent(1)[0]["ts"].startswith("2031-03-01"))

    def test_prune_days(self):
        path = self.write_log("old.log", ["<13>1 2026-01-01T10:00:00Z host app - - - old event"])
        report = run(path, ruleset(), self.db, now=NOW, prune_days=30)
        self.assertEqual(report.stored, 1)
        self.assertEqual(report.pruned, 1)
        with Store(self.db) as store:
            self.assertEqual(store.event_count(), 0)

    def test_prune_days_keeps_recent_events(self):
        path = self.write_log("new.log", ["<13>1 2026-03-01T10:00:00Z host app - - - new event"])
        report = run(path, ruleset(), self.db, now=NOW, prune_days=30)
        self.assertEqual(report.pruned, 0)
        with Store(self.db) as store:
            self.assertEqual(store.event_count(), 1)

    def test_empty_file(self):
        path = self.base / "empty.log"
        path.write_text("", encoding="utf-8")
        report = run(path, ruleset(), self.db, now=NOW)
        self.assertEqual(report.lines, 0)
        self.assertEqual(report.stored, 0)

    def test_missing_input_file(self):
        with self.assertRaises(OSError):
            run(self.base / "absent.log", ruleset(), self.db, now=NOW)

    def test_report_to_dict(self):
        path = self.write_log("one.log", ["<13>Mar  1 10:00:00 host app: hello"])
        report = run(path, ruleset(), self.db, now=NOW)
        payload = report.to_dict()
        self.assertEqual(payload["lines"], 1)
        self.assertEqual(payload["parsed"], 1)
        self.assertEqual(payload["stored"], 1)
        self.assertEqual(payload["counters"], {"unmatched": 1})
        self.assertEqual(payload["files"], {})
        self.assertEqual(payload["parse_errors"], [])

    def test_report_to_dict_is_json_serialisable(self):
        path = self.write_log("one.log", ["<13>Mar  1 10:00:00 host app: hello"])
        report = run(path, ruleset(), self.db, now=NOW)
        self.assertIsInstance(json.dumps(report.to_dict()), str)

    def test_run_report_defaults(self):
        report = RunReport()
        self.assertEqual(report.lines, 0)
        self.assertEqual(report.counters, {})
        self.assertEqual(report.parse_errors, [])

    def test_rule_file_actions_relative_to_base_dir(self):
        path = self.write_log("one.log", ["<13>Mar  1 10:00:00 host app: hello"])
        rules = ruleset(rule("capture", {}, {"file": "logs/captured.log"}))
        report = run(path, rules, self.db, now=NOW, base_dir=self.base)
        self.assertEqual(report.files, {"logs/captured.log": 1})
        self.assertTrue((self.base / "logs" / "captured.log").is_file())


if __name__ == "__main__":
    unittest.main()

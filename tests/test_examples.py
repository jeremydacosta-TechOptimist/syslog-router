"""Tests that keep the committed lab fixtures honest and deterministic."""

import json
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path

from syslogrouter.engine import run
from syslogrouter.parser import parse_line
from syslogrouter.rules import build_ruleset, validate_rules
from syslogrouter.store import Store

UTC = timezone.utc
NOW = datetime(2026, 3, 2, 0, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
MIXED_LOG = EXAMPLES / "lab-logs" / "mixed.log"
LAB_RULES = EXAMPLES / "lab-rules.json"

RFC5737 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
EXPECTED_FORMATS = {"rfc5424": 10, "rfc3164": 13, "cisco": 6, "lenient": 1}


class MixedLogTests(unittest.TestCase):
    """The committed log file."""

    def setUp(self):
        self.lines = MIXED_LOG.read_text(encoding="utf-8").splitlines()

    def test_fixture_exists_and_is_small(self):
        self.assertTrue(MIXED_LOG.is_file())
        self.assertLess(MIXED_LOG.stat().st_size, 200 * 1024)

    def test_line_count(self):
        self.assertEqual(len(self.lines), 30)

    def test_no_blank_lines(self):
        self.assertTrue(all(line.strip() for line in self.lines))

    def test_all_lines_parse(self):
        messages = [parse_line(line, now=NOW) for line in self.lines]
        self.assertEqual(len(messages), 30)

    def test_format_distribution(self):
        counts = {}
        for line in self.lines:
            message = parse_line(line, now=NOW)
            counts[message.format] = counts.get(message.format, 0) + 1
        self.assertEqual(counts, EXPECTED_FORMATS)

    def test_hostnames_use_reserved_domain(self):
        for index, line in enumerate(self.lines, start=1):
            message = parse_line(line, now=NOW)
            if message.hostname is None:
                continue
            with self.subTest(line=index):
                self.assertTrue(
                    message.hostname.endswith(".example"),
                    f"line {index} uses hostname {message.hostname!r}",
                )

    def test_only_documentation_addresses(self):
        ranges = set()
        for line in self.lines:
            for match in RFC5737.finditer(line):
                ranges.add(".".join(match.groups()[:3]))
        self.assertTrue(ranges)
        self.assertTrue(
            ranges <= {"192.0.2", "198.51.100", "203.0.113"},
            f"unexpected address ranges: {sorted(ranges - {'192.0.2', '198.51.100', '203.0.113'})}",
        )

    def test_no_private_network_addresses(self):
        for line in self.lines:
            for match in RFC5737.finditer(line):
                octets = [int(part) for part in match.groups()]
                first, second = octets[0], octets[1]
                private = (
                    first == 10
                    or (first == 172 and 16 <= second <= 31)
                    or (first == 192 and second == 168)
                )
                self.assertFalse(private, f"private address in fixture: {match.group(0)}")

    def test_every_line_has_content_after_parsing(self):
        for index, line in enumerate(self.lines, start=1):
            message = parse_line(line, now=NOW)
            with self.subTest(line=index):
                self.assertTrue(message.msg, f"line {index} has an empty message")


class LabRulesTests(unittest.TestCase):
    """The committed routing rule set."""

    def test_rules_fixture_exists_and_is_small(self):
        self.assertTrue(LAB_RULES.is_file())
        self.assertLess(LAB_RULES.stat().st_size, 200 * 1024)

    def test_rules_are_valid(self):
        payload = json.loads(LAB_RULES.read_text(encoding="utf-8"))
        self.assertEqual(validate_rules(payload), [])

    def test_rule_names_and_order(self):
        payload = json.loads(LAB_RULES.read_text(encoding="utf-8"))
        ruleset = build_ruleset(payload)
        self.assertEqual(
            [rule.name for rule in ruleset.rules],
            [
                "auth-failures",
                "firewall-denies",
                "critical-alerts",
                "cron-jobs",
                "drop-debug-noise",
            ],
        )

    def test_last_rule_stops_evaluation(self):
        payload = json.loads(LAB_RULES.read_text(encoding="utf-8"))
        ruleset = build_ruleset(payload)
        self.assertTrue(ruleset.rules[-1].stop)
        self.assertTrue(ruleset.rules[-1].action.drop)


class FixturePipelineTests(unittest.TestCase):
    """Running the fixtures end to end."""

    def setUp(self):
        import tempfile

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.db = self.base / "fixtures.db"
        payload = json.loads(LAB_RULES.read_text(encoding="utf-8"))
        self.ruleset = build_ruleset(payload)
        self.report = run(MIXED_LOG, self.ruleset, self.db, now=NOW, base_dir=self.base)

    def test_run_counts_are_deterministic(self):
        self.assertEqual(self.report.lines, 30)
        self.assertEqual(self.report.parsed, 30)
        self.assertEqual(self.report.errors, 0)
        self.assertEqual(self.report.stored, 26)
        self.assertEqual(self.report.dropped, 4)

    def test_run_counters_are_deterministic(self):
        self.assertEqual(
            self.report.counters,
            {
                "auth_failures": 4,
                "crit_alerts": 2,
                "cron_jobs": 3,
                "firewall_denies": 4,
                "unmatched": 13,
            },
        )

    def test_stored_statistics(self):
        with Store(self.db) as store:
            stats = store.stats()
        self.assertEqual(stats.events, 26)
        self.assertEqual(stats.severity["notice"], 9)
        self.assertEqual(stats.severity["info"], 10)
        self.assertEqual(stats.top_hosts[0], ("db-srv-01.example", 6))

    def test_per_minute_distribution(self):
        with Store(self.db) as store:
            stats = store.stats()
        minutes = dict(stats.per_minute)
        self.assertEqual(minutes["2026-03-01T22:14"], 3)
        self.assertEqual(minutes["2026-03-01T22:18"], 5)
        self.assertEqual(minutes["2026-03-02T00:00"], 2)

    def test_denied_events_file(self):
        captured = self.base / "out" / "denied-events.log"
        self.assertTrue(captured.is_file())
        self.assertEqual(len(captured.read_text(encoding="utf-8").splitlines()), 4)


if __name__ == "__main__":
    unittest.main()

"""Tests for the standalone HTML dashboard."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from syslogrouter.parser import parse_line
from syslogrouter.report import SEVERITY_COLORS, build_dashboard, render_dashboard
from syslogrouter.store import Stats, Store

UTC = timezone.utc
NOW = datetime(2026, 3, 2, 0, 0, 0, tzinfo=UTC)


def make_stats(**overrides):
    defaults = dict(
        events=26,
        first_ts="2026-03-01T22:14:15.003000Z",
        last_ts="2026-03-02T00:00:00.000000Z",
        severity={name: 0 for name in SEVERITY_COLORS},
        top_hosts=[("db-srv-01.example", 6), ("auth-srv-01.example", 5)],
        top_apps=[("sshd", 5), ("CRON", 3)],
        per_minute=[("2026-03-01T22:14", 3), ("2026-03-01T22:15", 3)],
        counters=[("unmatched", 13), ("auth_failures", 4)],
    )
    defaults.update(overrides)
    return Stats(**defaults)


RECENT = [
    {
        "id": 1,
        "ts": "2026-03-01T22:14:15.003000Z",
        "host": "fw-edge-01.example",
        "app": "trafficmon",
        "severity": 5,
        "facility": 20,
        "msg": "BLOCKED TCP 192.0.2.10:51515 -> 198.51.100.20:443",
        "raw": "raw line",
    }
]


class RenderDashboardTests(unittest.TestCase):
    """HTML rendering and escaping."""

    def setUp(self):
        severity = {"emerg": 0, "alert": 0, "crit": 2, "err": 1, "warning": 1, "notice": 9, "info": 13, "debug": 0}
        self.stats = make_stats(severity=severity)
        self.document = render_dashboard(self.stats, RECENT, generated_at=NOW)

    def test_document_structure(self):
        self.assertTrue(self.document.startswith("<!DOCTYPE html>"))
        self.assertIn('<html lang="en">', self.document)
        self.assertIn('<meta charset="utf-8">', self.document)
        self.assertTrue(self.document.rstrip().endswith("</html>"))

    def test_title_is_rendered(self):
        document = render_dashboard(self.stats, RECENT, title="Lab dashboard", generated_at=NOW)
        self.assertIn("<title>Lab dashboard</title>", document)
        self.assertIn("<h1>Lab dashboard</h1>", document)

    def test_title_is_escaped(self):
        document = render_dashboard(self.stats, RECENT, title="<b>Dash</b>", generated_at=NOW)
        self.assertIn("&lt;b&gt;Dash&lt;/b&gt;", document)
        self.assertNotIn("<b>Dash</b>", document)

    def test_generated_timestamp(self):
        self.assertIn("2026-03-02T00:00:00.000000Z", self.document)

    def test_cards(self):
        self.assertIn('<span class="value">26</span>', self.document)
        self.assertIn("stored events", self.document)
        self.assertIn("counter hits", self.document)

    def test_severity_bars_for_every_level(self):
        for name in SEVERITY_COLORS:
            self.assertIn(f'<span class="bar-label">{name}</span>', self.document)

    def test_severity_bar_widths(self):
        self.assertIn("background:#b91c1c", self.document)  # crit
        self.assertIn("width:15.4%;", self.document)  # 2 / 13

    def test_top_hosts_table(self):
        self.assertIn("db-srv-01.example", self.document)
        self.assertIn("auth-srv-01.example", self.document)

    def test_top_apps_table(self):
        self.assertIn("sshd</td>", self.document)
        self.assertIn("CRON</td>", self.document)

    def test_counters_table(self):
        self.assertIn("unmatched", self.document)
        self.assertIn("auth_failures", self.document)

    def test_recent_events_table(self):
        self.assertIn("2026-03-01T22:14:15.003000Z", self.document)
        self.assertIn("BLOCKED TCP", self.document)
        self.assertIn("fw-edge-01.example", self.document)

    def test_severity_badge(self):
        self.assertIn('<span class="badge" style="background:#2563eb">notice</span>', self.document)

    def test_message_is_escaped(self):
        recent = [dict(RECENT[0], msg="<script>alert(1)</script>")]
        document = render_dashboard(self.stats, recent, generated_at=NOW)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", document)
        self.assertNotIn("<script>alert", document)

    def test_host_is_escaped(self):
        recent = [dict(RECENT[0], host='<img src="x" onerror="y">')]
        document = render_dashboard(self.stats, recent, generated_at=NOW)
        self.assertNotIn("<img src=", document)
        self.assertIn("&lt;img src=", document)

    def test_no_external_assets(self):
        self.assertNotIn("http://", self.document)
        self.assertNotIn("https://", self.document)
        self.assertNotIn("<script", self.document)
        self.assertNotIn("<link", self.document)

    def test_inline_css_present(self):
        self.assertIn("<style>", self.document)
        self.assertIn("</style>", self.document)

    def test_empty_store_tables_show_no_data(self):
        empty = make_stats(
            events=0,
            first_ts=None,
            last_ts=None,
            severity={name: 0 for name in SEVERITY_COLORS},
            top_hosts=[],
            top_apps=[],
            per_minute=[],
            counters=[],
        )
        document = render_dashboard(empty, [], generated_at=NOW)
        self.assertIn("No data", document)
        self.assertIn("n/a", document)

    def test_custom_title_default(self):
        document = render_dashboard(self.stats, RECENT)
        self.assertIn("Syslog Router dashboard", document)


class BuildDashboardTests(unittest.TestCase):
    """Dashboard writing from a real SQLite store."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.db = self.base / "events.db"

    def seed(self):
        moment = datetime(2026, 3, 1, 22, 14, 15, tzinfo=UTC)
        with Store(self.db) as store:
            message = parse_line(
                '<165>1 - fw-edge-01.example trafficmon - - - BLOCKED "TCP" <b>'
            )
            store.insert_event(message, moment)
            store.insert_event(parse_line("<13>1 - host.example app - - - plain <script>"), moment)
            store.add_counter("firewall_denies", 1)

    def test_writes_file_and_returns_path(self):
        self.seed()
        output = build_dashboard(self.db, self.base / "dashboard.html", now=NOW)
        self.assertTrue(output.is_file())
        self.assertEqual(output, self.base / "dashboard.html")

    def test_document_contains_store_data(self):
        self.seed()
        output = build_dashboard(self.db, self.base / "dashboard.html", now=NOW)
        document = output.read_text(encoding="utf-8")
        self.assertIn("fw-edge-01.example", document)
        self.assertIn("firewall_denies", document)
        self.assertIn("&lt;script&gt;", document)

    def test_creates_parent_directory(self):
        self.seed()
        output = build_dashboard(self.db, self.base / "nested" / "dir" / "dashboard.html", now=NOW)
        self.assertTrue(output.is_file())

    def test_custom_title(self):
        self.seed()
        output = build_dashboard(self.db, self.base / "d.html", title="Lab", now=NOW)
        self.assertIn("<title>Lab</title>", output.read_text(encoding="utf-8"))

    def test_empty_database(self):
        output = build_dashboard(self.db, self.base / "empty.html", now=NOW)
        document = output.read_text(encoding="utf-8")
        self.assertIn("stored events", document)
        self.assertIn("<span class=\"value\">0</span>", document)


if __name__ == "__main__":
    unittest.main()

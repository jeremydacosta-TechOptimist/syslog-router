"""Tests for the argparse command line interface."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from syslogrouter.cli import EXIT_ERROR, EXIT_OK, EXIT_USAGE, main
from syslogrouter.store import Store

UTC = timezone.utc
NOW_ARG = "2026-03-02T00:00:00Z"
ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_LOG = ROOT / "examples" / "lab-logs" / "mixed.log"
EXAMPLE_RULES = ROOT / "examples" / "lab-rules.json"

LOG_LINES = [
    "<38>Mar  1 22:15:02 auth-srv-01.example sshd[1421]: "
    "Failed password for root from 203.0.113.7 port 51022 ssh2",
    "<13>Mar  1 22:16:00 host.example app: ordinary line",
    "<2>Mar  1 22:17:00 db.example kernel: critical failure",
    "<134>Mar  1 22:18:00 app.example worker[9]: task finished",
]


def invoke(argv, stdin_text=None):
    """Run ``main`` in-process and return (exit code, stdout, stderr)."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_stdin = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = main(argv)
            except SystemExit as exc:  # argparse exits for --help and usage errors
                code = exc.code if isinstance(exc.code, int) else EXIT_ERROR
    finally:
        sys.stdin = previous_stdin
    return code, stdout.getvalue(), stderr.getvalue()


class CliCase(unittest.TestCase):
    """Shared temporary fixtures for CLI tests."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.log = self.base / "syslog.log"
        self.log.write_text("\n".join(LOG_LINES) + "\n", encoding="utf-8")
        self.db = self.base / "events.db"
        self.rules = self.base / "rules.json"
        self.write_rules(
            [
                {
                    "name": "auth-failures",
                    "match": {"regex": "Failed password"},
                    "action": {"counter": "auth_failures"},
                }
            ]
        )

    def write_rules(self, rules):
        self.rules.write_text(json.dumps({"rules": rules}), encoding="utf-8")

    def route(self, *extra, log=None, rules=None, db=None):
        argv = [
            "run",
            "--input",
            str(log or self.log),
            "--rules",
            str(rules or self.rules),
            "--db",
            str(db or self.db),
            "--now",
            NOW_ARG,
            *extra,
        ]
        return invoke(argv)


class VersionTests(CliCase):
    """The version subcommand."""

    def test_version_output(self):
        code, out, err = invoke(["version"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "syslogrouter 1.0.0\n")
        self.assertEqual(err, "")

    def test_version_returns_integer(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsInstance(main(["version"]), int)


class HelpTests(CliCase):
    """Help output and usage exit codes."""

    def test_top_level_help(self):
        code, out, err = invoke(["--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("usage: syslogrouter", out)
        self.assertIn("Exit codes", out)
        for command in ("parse", "run", "stats", "report", "rules", "version"):
            self.assertIn(command, out)
        self.assertEqual(err, "")

    def test_run_help(self):
        code, out, _ = invoke(["run", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("--keep-unmatched", out)
        self.assertIn("--prune-days", out)

    def test_parse_help(self):
        code, out, _ = invoke(["parse", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("--stdin", out)
        self.assertIn("--json", out)


class ParseCommandTests(CliCase):
    """The parse subcommand."""

    def test_parse_text_output(self):
        code, out, _ = invoke(
            ["parse", "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - hello"]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("format     rfc5424", out)
        self.assertIn("pri        34", out)
        self.assertIn("facility   4 (auth)", out)
        self.assertIn("severity   2 (crit)", out)
        self.assertIn("hostname   mymachine.example.com", out)
        self.assertIn("app_name   su", out)
        self.assertIn("msg        hello", out)

    def test_parse_json_output(self):
        code, out, _ = invoke(
            [
                "parse",
                '<165>1 - host.example app - - [ex@1 k="v"] payload',
                "--json",
            ]
        )
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["format"], "rfc5424")
        self.assertEqual(payload["structured_data"], [{"id": "ex@1", "params": {"k": "v"}}])
        self.assertEqual(payload["msg"], "payload")

    def test_parse_rfc3164(self):
        code, out, _ = invoke(["parse", "<13>Mar  1 10:00:00 host.example app[42]: hello", "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["format"], "rfc3164")
        self.assertEqual(payload["proc_id"], "42")

    def test_parse_structured_data_text(self):
        code, out, _ = invoke(
            ["parse", '<13>1 - host app - - [ex@1 a="1" b="two"] body']
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn('structured ex@1 a="1" b="two"', out)

    def test_parse_invalid_line(self):
        code, out, err = invoke(["parse", ""])
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("error:", err)

    def test_parse_without_arguments(self):
        code, _, err = invoke(["parse"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("error:", err)

    def test_parse_line_and_stdin_conflict(self):
        code, _, err = invoke(["parse", "<13>1 - h a - - - x", "--stdin"], stdin_text="")
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("not both", err)

    def test_parse_stdin_multiple_lines(self):
        code, out, err = invoke(
            ["parse", "--stdin"],
            stdin_text="<13>Mar  1 10:00:00 a.example app: one\n<14>Mar  1 10:00:01 b.example app: two\n",
        )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out.count("format     rfc3164"), 2)
        self.assertIn("one", out)
        self.assertIn("two", out)
        self.assertEqual(err, "")

    def test_parse_stdin_reports_bad_line(self):
        code, _, err = invoke(
            ["parse", "--stdin"],
            stdin_text="<13>Mar  1 10:00:00 a.example app: one\n<34>1 bad-timestamp h a - - - x\n",
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("line 2: error:", err)


class RulesCommandTests(CliCase):
    """The rules validate subcommand."""

    def test_validate_example_rules(self):
        code, out, err = invoke(["rules", "validate", str(EXAMPLE_RULES)])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("rules OK: 5 rules", out)

    def test_validate_temp_rules(self):
        code, out, _ = invoke(["rules", "validate", str(self.rules)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("rules OK: 1 rules", out)

    def test_validate_reports_schema_errors(self):
        broken = self.base / "broken.json"
        broken.write_text(json.dumps({"rules": [{"name": "x", "match": {}}]}), encoding="utf-8")
        code, out, err = invoke(["rules", "validate", str(broken)])
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out, "")
        self.assertIn('missing the "action"', err)

    def test_validate_reports_regex_errors(self):
        broken = self.base / "bad-regex.json"
        broken.write_text(
            json.dumps({"rules": [{"match": {"regex": "(oops"}, "action": {}}]}),
            encoding="utf-8",
        )
        code, _, err = invoke(["rules", "validate", str(broken)])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("valid regular expression", err)

    def test_validate_invalid_json(self):
        broken = self.base / "invalid.json"
        broken.write_text('{"rules": [', encoding="utf-8")
        code, _, err = invoke(["rules", "validate", str(broken)])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("invalid JSON", err)

    def test_validate_missing_file(self):
        code, _, err = invoke(["rules", "validate", str(self.base / "absent.json")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot read rules file", err)

    def test_rules_requires_subcommand(self):
        code, _, err = invoke(["rules"])
        self.assertEqual(code, EXIT_USAGE)


class RunCommandTests(CliCase):
    """The run subcommand."""

    def test_run_summary(self):
        code, out, err = self.route()
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("lines        4", out)
        self.assertIn("parsed       4", out)
        self.assertIn("parse errors 0", out)
        self.assertIn("stored       4", out)
        self.assertIn("dropped      0", out)
        self.assertIn("auth_failures", out)
        self.assertIn("unmatched", out)

    def test_run_json(self):
        code, out, _ = self.route("--json")
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["lines"], 4)
        self.assertEqual(payload["stored"], 4)
        self.assertEqual(payload["counters"], {"auth_failures": 1, "unmatched": 3})

    def test_run_without_keep_unmatched(self):
        code, out, _ = self.route("--no-keep-unmatched", "--json")
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["stored"], 1)
        self.assertEqual(payload["dropped"], 3)

    def test_run_counter_persisted(self):
        code, _, _ = self.route()
        self.assertEqual(code, EXIT_OK)
        with Store(self.db) as store:
            self.assertEqual(store.counter("auth_failures"), 1)
            self.assertEqual(store.event_count(), 4)

    def test_run_prune_days(self):
        code, out, _ = self.route("--prune-days", "30", "--json")
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["pruned"], 0)

    def test_run_file_action(self):
        capture = self.base / "captured.log"
        self.write_rules([{"name": "capture", "match": {}, "action": {"file": str(capture)}}])
        code, out, _ = self.route("--json")
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["files"], {str(capture): 4})
        self.assertEqual(len(capture.read_text(encoding="utf-8").splitlines()), 4)

    def test_run_parse_errors(self):
        broken = self.base / "broken.log"
        broken.write_text("<34>1 not-a-timestamp h a - - - bad\n", encoding="utf-8")
        code, out, _ = self.route("--json", log=broken)
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["errors"], 1)
        self.assertEqual(payload["stored"], 0)
        self.assertEqual(payload["parse_errors"][0][0], 1)

    def test_run_invalid_rules(self):
        broken = self.base / "rules-bad.json"
        broken.write_text('{"rules": "nope"}', encoding="utf-8")
        code, _, err = self.route(rules=broken)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)

    def test_run_missing_input(self):
        code, _, err = self.route(log=self.base / "absent.log")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)

    def test_run_invalid_now(self):
        code, _, err = invoke(
            [
                "run",
                "--input",
                str(self.log),
                "--rules",
                str(self.rules),
                "--db",
                str(self.db),
                "--now",
                "not-a-date",
            ]
        )
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("--now", err)


class StatsCommandTests(CliCase):
    """The stats subcommand."""

    def route_data(self):
        code, _, _ = self.route()
        self.assertEqual(code, EXIT_OK)

    def test_stats_text(self):
        self.route_data()
        code, out, err = invoke(["stats", "--db", str(self.db)])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("events     4", out)
        self.assertIn("severity", out)
        self.assertIn("counters", out)
        self.assertIn("top hosts", out)
        self.assertIn("per-minute rates", out)
        self.assertIn("auth_failures", out)

    def test_stats_json(self):
        self.route_data()
        code, out, _ = invoke(["stats", "--db", str(self.db), "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["events"], 4)
        self.assertEqual(payload["database"], str(self.db))
        self.assertIn("notice", payload["severity"])
        self.assertEqual(payload["counters"]["auth_failures"], 1)

    def test_stats_top_option(self):
        self.route_data()
        code, out, _ = invoke(["stats", "--db", str(self.db), "--top", "1"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("top hosts", out)

    def test_stats_missing_database(self):
        code, _, err = invoke(["stats", "--db", str(self.base / "absent.db")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("database not found", err)

    def test_stats_empty_database(self):
        empty = self.base / "empty.db"
        with Store(empty):
            pass
        code, out, _ = invoke(["stats", "--db", str(empty)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("events     0", out)


class ReportCommandTests(CliCase):
    """The report subcommand."""

    def route_data(self):
        code, _, _ = self.route()
        self.assertEqual(code, EXIT_OK)

    def test_report_writes_dashboard(self):
        self.route_data()
        output = self.base / "dashboard.html"
        code, out, err = invoke(
            ["report", "--db", str(self.db), "--out", str(output), "--now", NOW_ARG]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("wrote dashboard", out)
        self.assertIn("4 events", out)
        document = output.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", document)
        self.assertIn("auth-srv-01.example", document)

    def test_report_custom_title(self):
        self.route_data()
        output = self.base / "dashboard.html"
        code, _, _ = invoke(
            ["report", "--db", str(self.db), "--out", str(output), "--title", "Lab dashboard"]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("<title>Lab dashboard</title>", output.read_text(encoding="utf-8"))

    def test_report_missing_database(self):
        code, _, err = invoke(
            ["report", "--db", str(self.base / "absent.db"), "--out", str(self.base / "d.html")]
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("database not found", err)

    def test_report_creates_parent_directory(self):
        self.route_data()
        output = self.base / "nested" / "dashboard.html"
        code, _, _ = invoke(["report", "--db", str(self.db), "--out", str(output)])
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(output.is_file())


class UsageTests(CliCase):
    """Generic usage errors."""

    def test_no_command(self):
        code, _, err = invoke([])
        self.assertEqual(code, EXIT_USAGE)
        self.assertTrue(err)

    def test_unknown_command(self):
        code, _, err = invoke(["bogus"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("invalid choice", err)

    def test_run_missing_required_option(self):
        code, _, err = invoke(["run", "--input", str(self.log)])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("--rules", err)

    def test_parse_stdin_skips_blank_lines(self):
        code, out, _ = invoke(
            ["parse", "--stdin"], stdin_text="\n<13>Mar  1 10:00:00 a.example app: one\n\n"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out.count("format     rfc3164"), 1)


if __name__ == "__main__":
    unittest.main()

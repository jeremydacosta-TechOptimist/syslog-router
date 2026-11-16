"""Tests for ordered JSON routing rules."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from syslogrouter.parser import parse_line
from syslogrouter.rules import (
    ActionSpec,
    MatchSpec,
    RuleSet,
    RulesError,
    build_ruleset,
    load_rules,
    validate_rules,
)

UTC = timezone.utc
NOW = datetime(2026, 3, 2, 0, 0, 0, tzinfo=UTC)


def message(line):
    return parse_line(line, now=NOW)


SSHD = message(
    "<38>Mar  1 22:15:02 auth-srv-01.example sshd[1421]: "
    "Failed password for invalid user admin from 203.0.113.7 port 51022 ssh2"
)
SSHD_CRIT = message(
    "<34>Mar  1 22:16:10 auth-srv-01.example sshd[1503]: "
    "Failed password for root from 203.0.113.7 port 51023 ssh2"
)
FIREWALL = message(
    '<165>1 2026-03-01T22:14:15.003Z fw-edge-01.example trafficmon - - '
    '[lab@32473 action="deny"] BLOCKED TCP 192.0.2.10:51515 -> 198.51.100.20:443'
)
CRON = message("<86>Mar  1 22:17:00 db-srv-01.example CRON[1601]: (root) CMD (/usr/local/bin/backup.sh)")
CISCO = message(
    "<189>*Mar  1 22:18:12.345: core-sw-01.example %LINK-3-UPDOWN: "
    "Interface GigabitEthernet0/1, changed state to down"
)


def make_rule(name, match, action=None, stop=None):
    data = {"name": name, "match": match, "action": action if action is not None else {}}
    if stop is not None:
        data["stop"] = stop
    return data


def make_ruleset(*rules):
    return build_ruleset({"rules": list(rules)})


class MatchingTests(unittest.TestCase):
    """Rule matching against parsed messages."""

    def test_host_glob(self):
        ruleset = make_ruleset(make_rule("fw", {"hosts": ["fw-*.example"]}))
        self.assertEqual(len(ruleset.matching(FIREWALL)), 1)
        self.assertEqual(ruleset.matching(SSHD), [])

    def test_host_match_is_case_insensitive(self):
        ruleset = make_ruleset(make_rule("fw", {"hosts": ["FW-*.EXAMPLE"]}))
        self.assertEqual(len(ruleset.matching(FIREWALL)), 1)

    def test_app_glob(self):
        ruleset = make_ruleset(make_rule("sshd", {"apps": ["ssh*"]}))
        self.assertEqual(len(ruleset.matching(SSHD)), 1)
        self.assertEqual(ruleset.matching(CRON), [])

    def test_app_match_is_case_insensitive(self):
        ruleset = make_ruleset(make_rule("cron", {"apps": ["cron"]}))
        self.assertEqual(len(ruleset.matching(CRON)), 1)

    def test_facility_name(self):
        ruleset = make_ruleset(make_rule("authpriv", {"facilities": ["authpriv"]}))
        self.assertEqual(len(ruleset.matching(CRON)), 1)
        self.assertEqual(ruleset.matching(SSHD), [])

    def test_facility_number(self):
        ruleset = make_ruleset(make_rule("auth", {"facilities": [4]}))
        self.assertEqual(len(ruleset.matching(SSHD)), 1)

    def test_severity_max_boundary(self):
        ruleset = make_ruleset(make_rule("critical", {"severity_max": 2}))
        self.assertEqual(len(ruleset.matching(SSHD_CRIT)), 1)

    def test_severity_max_excludes_below_threshold(self):
        ruleset = make_ruleset(make_rule("critical", {"severity_max": 1}))
        self.assertEqual(ruleset.matching(SSHD_CRIT), [])

    def test_regex_search_on_message(self):
        ruleset = make_ruleset(make_rule("failed", {"regex": "Failed password"}))
        self.assertEqual(len(ruleset.matching(SSHD)), 1)
        self.assertEqual(ruleset.matching(CRON), [])

    def test_regex_is_search_not_match(self):
        ruleset = make_ruleset(make_rule("password", {"regex": "password"}))
        self.assertEqual(len(ruleset.matching(SSHD)), 1)

    def test_all_matchers_are_anded(self):
        ruleset = make_ruleset(
            make_rule("combo", {"hosts": ["auth-*.example"], "regex": "Failed password"})
        )
        self.assertEqual(len(ruleset.matching(SSHD)), 1)
        ruleset = make_ruleset(
            make_rule("combo", {"hosts": ["db-*.example"], "regex": "Failed password"})
        )
        self.assertEqual(ruleset.matching(SSHD), [])

    def test_empty_match_matches_everything(self):
        ruleset = make_ruleset(make_rule("all", {}))
        for sample in (SSHD, FIREWALL, CRON, CISCO):
            self.assertEqual(len(ruleset.matching(sample)), 1)

    def test_multiple_rules_keep_file_order(self):
        ruleset = make_ruleset(
            make_rule("first", {"hosts": ["*"]}),
            make_rule("second", {"regex": "Failed"}),
            make_rule("third", {}),
        )
        self.assertEqual([rule.name for rule in ruleset.matching(SSHD)], ["first", "second", "third"])

    def test_no_match_returns_empty_list(self):
        ruleset = make_ruleset(make_rule("nomatch", {"hosts": ["nothing.example"]}))
        self.assertEqual(ruleset.matching(SSHD), [])

    def test_stop_flag_is_parsed(self):
        ruleset = make_ruleset(make_rule("stopper", {}, stop=True))
        self.assertTrue(ruleset.rules[0].stop)
        self.assertFalse(make_ruleset(make_rule("plain", {})).rules[0].stop)

    def test_rule_defaults(self):
        ruleset = make_ruleset(make_rule("plain", {}))
        rule = ruleset.rules[0]
        self.assertEqual(rule.name, "plain")
        self.assertEqual(rule.match, MatchSpec())
        self.assertEqual(rule.action, ActionSpec())
        self.assertIsNone(rule.action.store)
        self.assertFalse(rule.action.drop)

    def test_action_fields_are_parsed(self):
        ruleset = make_ruleset(
            make_rule(
                "actions",
                {"regex": "Failed"},
                {"store": False, "file": "out/auth.log", "counter": "auth_failures", "drop": True},
            )
        )
        action = ruleset.rules[0].action
        self.assertFalse(action.store)
        self.assertTrue(action.drop)
        self.assertEqual(action.file, "out/auth.log")
        self.assertEqual(action.counter, "auth_failures")

    def test_source_attribute(self):
        ruleset = build_ruleset({"rules": [make_rule("x", {})]}, source="lab-rules.json")
        self.assertEqual(ruleset.source, "lab-rules.json")

    def test_default_rule_names(self):
        ruleset = build_ruleset({"rules": [{"match": {}, "action": {}}]})
        self.assertEqual(ruleset.rules[0].name, "rule-1")


class ValidateRulesTests(unittest.TestCase):
    """Precise validation errors for malformed rule documents."""

    def test_valid_document_returns_no_errors(self):
        self.assertEqual(
            validate_rules({"rules": [make_rule("ok", {"hosts": ["*.example"]})]}),
            [],
        )

    def test_valid_bare_list(self):
        self.assertEqual(validate_rules([make_rule("ok", {"regex": "x"})]), [])

    def test_top_level_type_error(self):
        errors = validate_rules("not-a-document")
        self.assertEqual(len(errors), 1)
        self.assertIn("JSON object", errors[0])

    def test_unknown_top_level_key(self):
        errors = validate_rules({"rules": [], "version": 2})
        self.assertTrue(any("unknown key" in error for error in errors))

    def test_missing_rules_key(self):
        errors = validate_rules({"rulez": []})
        self.assertTrue(any('missing the "rules" list' in error for error in errors))

    def test_rules_must_be_a_list(self):
        errors = validate_rules({"rules": {"name": "x"}})
        self.assertTrue(any("must be a list" in error for error in errors))

    def test_rule_must_be_an_object(self):
        errors = validate_rules({"rules": ["nope"]})
        self.assertTrue(any("must be a JSON object" in error for error in errors))

    def test_unknown_rule_key(self):
        rule = make_rule("x", {})
        rule["matches"] = {}
        errors = validate_rules({"rules": [rule]})
        self.assertTrue(any("unknown key(s): matches" in error for error in errors))

    def test_missing_match(self):
        errors = validate_rules({"rules": [{"name": "x", "action": {}}]})
        self.assertTrue(any('missing the "match"' in error for error in errors))

    def test_missing_action(self):
        errors = validate_rules({"rules": [{"name": "x", "match": {}}]})
        self.assertTrue(any('missing the "action"' in error for error in errors))

    def test_match_must_be_an_object(self):
        errors = validate_rules({"rules": [{"name": "x", "match": [], "action": {}}]})
        self.assertTrue(any("match must be a JSON object" in error for error in errors))

    def test_unknown_match_key(self):
        errors = validate_rules({"rules": [make_rule("x", {"host": ["a"]})]})
        self.assertTrue(any("match has unknown key(s): host" in error for error in errors))

    def test_hosts_must_be_a_list(self):
        errors = validate_rules({"rules": [make_rule("x", {"hosts": "fw-*.example"})]})
        self.assertTrue(any("match.hosts" in error for error in errors))

    def test_hosts_must_not_be_empty(self):
        errors = validate_rules({"rules": [make_rule("x", {"hosts": []})]})
        self.assertTrue(any("match.hosts" in error for error in errors))

    def test_hosts_elements_must_be_strings(self):
        errors = validate_rules({"rules": [make_rule("x", {"hosts": ["ok", 3]})]})
        self.assertTrue(any("match.hosts" in error for error in errors))

    def test_apps_elements_must_be_strings(self):
        errors = validate_rules({"rules": [make_rule("x", {"apps": [None]})]})
        self.assertTrue(any("match.apps" in error for error in errors))

    def test_unknown_facility_name(self):
        errors = validate_rules({"rules": [make_rule("x", {"facilities": ["kernell"]})]})
        self.assertTrue(any("unknown name" in error for error in errors))

    def test_facility_number_out_of_range(self):
        errors = validate_rules({"rules": [make_rule("x", {"facilities": [24]})]})
        self.assertTrue(any("out of range" in error for error in errors))

    def test_facility_boolean_rejected(self):
        errors = validate_rules({"rules": [make_rule("x", {"facilities": [True]})]})
        self.assertTrue(any("invalid value" in error for error in errors))

    def test_facility_wrong_type_rejected(self):
        errors = validate_rules({"rules": [make_rule("x", {"facilities": [1.5]})]})
        self.assertTrue(any("invalid value" in error for error in errors))

    def test_severity_max_out_of_range(self):
        errors = validate_rules({"rules": [make_rule("x", {"severity_max": 8})]})
        self.assertTrue(any("severity_max" in error for error in errors))

    def test_severity_max_boolean_rejected(self):
        errors = validate_rules({"rules": [make_rule("x", {"severity_max": True})]})
        self.assertTrue(any("severity_max" in error for error in errors))

    def test_invalid_regex(self):
        errors = validate_rules({"rules": [make_rule("x", {"regex": "(unclosed"})]})
        self.assertTrue(any("valid regular expression" in error for error in errors))

    def test_regex_must_be_a_string(self):
        errors = validate_rules({"rules": [make_rule("x", {"regex": 42})]})
        self.assertTrue(any("match.regex" in error for error in errors))

    def test_unknown_action_key(self):
        errors = validate_rules({"rules": [make_rule("x", {}, {"store_it": True})]})
        self.assertTrue(any("action has unknown key(s)" in error for error in errors))

    def test_action_store_must_be_boolean(self):
        errors = validate_rules({"rules": [make_rule("x", {}, {"store": "yes"})]})
        self.assertTrue(any("action.store" in error for error in errors))

    def test_action_drop_must_be_boolean(self):
        errors = validate_rules({"rules": [make_rule("x", {}, {"drop": 1})]})
        self.assertTrue(any("action.drop" in error for error in errors))

    def test_action_counter_must_be_non_empty(self):
        errors = validate_rules({"rules": [make_rule("x", {}, {"counter": ""})]})
        self.assertTrue(any("action.counter" in error for error in errors))

    def test_action_file_must_be_non_empty(self):
        errors = validate_rules({"rules": [make_rule("x", {}, {"file": "   "})]})
        self.assertTrue(any("action.file" in error for error in errors))

    def test_stop_must_be_boolean(self):
        errors = validate_rules({"rules": [make_rule("x", {}, stop="yes")]})
        self.assertTrue(any("stop must be true or false" in error for error in errors))

    def test_rule_name_must_be_a_string(self):
        errors = validate_rules({"rules": [make_rule("", {})]})
        self.assertTrue(any("name must be a non-empty string" in error for error in errors))

    def test_duplicate_rule_names_rejected(self):
        errors = validate_rules(
            {"rules": [make_rule("same", {}), make_rule("same", {"regex": "x"})]}
        )
        self.assertTrue(any("duplicate rule name" in error for error in errors))

    def test_multiple_errors_are_reported(self):
        errors = validate_rules(
            {
                "rules": [
                    {"name": "a", "match": {"hosts": "x"}, "action": {"store": 1}},
                    {"name": "b", "match": {"regex": "["}, "action": {}},
                ]
            }
        )
        self.assertGreaterEqual(len(errors), 3)

    def test_error_messages_include_rule_index(self):
        errors = validate_rules({"rules": [make_rule("x", {"hosts": 5})]})
        self.assertTrue(errors)
        self.assertTrue(errors[0].startswith("rule 0:"))


class LoadRulesTests(unittest.TestCase):
    """File loading, JSON errors and UTF-8 handling."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)

    def write(self, name, content):
        path = self.base / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_load_valid_file(self):
        path = self.write(
            "rules.json", json.dumps({"rules": [make_rule("a", {"regex": "Failed"})]})
        )
        ruleset = load_rules(path)
        self.assertIsInstance(ruleset, RuleSet)
        self.assertEqual(len(ruleset.rules), 1)
        self.assertEqual(ruleset.source, str(path))

    def test_load_file_with_utf8_bom(self):
        path = self.write("rules.json", "\ufeff" + json.dumps({"rules": [make_rule("a", {})]}))
        self.assertEqual(len(load_rules(path).rules), 1)

    def test_missing_file(self):
        with self.assertRaises(RulesError) as caught:
            load_rules(self.base / "absent.json")
        self.assertIn("cannot read rules file", str(caught.exception))

    def test_invalid_json(self):
        path = self.write("rules.json", '{"rules": [')
        with self.assertRaises(RulesError) as caught:
            load_rules(path)
        self.assertIn("invalid JSON", str(caught.exception))
        self.assertIn("line 1", str(caught.exception))

    def test_invalid_schema(self):
        path = self.write("rules.json", json.dumps({"rules": [{"name": "x"}]}))
        with self.assertRaises(RulesError) as caught:
            load_rules(path)
        message = str(caught.exception)
        self.assertIn('missing the "match"', message)
        self.assertIn('missing the "action"', message)

    def test_build_ruleset_raises_on_invalid_data(self):
        with self.assertRaises(RulesError):
            build_ruleset({"rules": [{"name": "x"}]})

    def test_load_nested_directory(self):
        nested = self.base / "nested"
        nested.mkdir()
        path = nested / "rules.json"
        path.write_text(json.dumps({"rules": [make_rule("a", {})]}), encoding="utf-8")
        self.assertEqual(len(load_rules(path).rules), 1)


class ExampleRulesTests(unittest.TestCase):
    """The committed example rule set must load and validate."""

    def test_example_rules_load(self):
        root = Path(__file__).resolve().parents[1]
        ruleset = load_rules(root / "examples" / "lab-rules.json")
        self.assertEqual(len(ruleset.rules), 5)
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

    def test_example_rules_match_real_messages(self):
        root = Path(__file__).resolve().parents[1]
        ruleset = load_rules(root / "examples" / "lab-rules.json")
        self.assertEqual([rule.name for rule in ruleset.matching(SSHD)], ["auth-failures"])
        self.assertEqual([rule.name for rule in ruleset.matching(FIREWALL)], ["firewall-denies"])
        self.assertEqual([rule.name for rule in ruleset.matching(CRON)], ["cron-jobs"])
        self.assertEqual([rule.name for rule in ruleset.matching(CISCO)], [])


if __name__ == "__main__":
    unittest.main()

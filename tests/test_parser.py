"""Tests for the syslog line parser (RFC 5424, RFC 3164, Cisco and lenient)."""

import unittest
from datetime import datetime, timedelta, timezone

from syslogrouter.parser import (
    FACILITY_NAMES,
    FACILITY_INDEX,
    LENIENT_FACILITY,
    LENIENT_SEVERITY,
    SEVERITY_NAMES,
    ParseError,
    facility_name,
    format_timestamp,
    parse_line,
    severity_name,
    utcnow,
)

UTC = timezone.utc
NOW = datetime(2026, 3, 2, 0, 0, 0, tzinfo=UTC)

# The four RFC 5424 section 6.5 example messages.
RFC5424_SAMPLE_1 = (
    "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 "
    "- \ufeff'su root' failed for lonvick on /dev/pts/8"
)
RFC5424_SAMPLE_2 = (
    "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - "
    "%% It's time to make the do-nuts."
)
RFC5424_SAMPLE_3 = (
    "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
    '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] '
    "\ufeffAn application event log entry..."
)
RFC5424_SAMPLE_4 = (
    "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
    '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]'
    '[examplePriority@32473 class="high"]'
)


def parse(line, now=NOW):
    return parse_line(line, now=now)


class Rfc5424SampleTests(unittest.TestCase):
    """The example messages of RFC 5424 section 6.5 must parse exactly."""

    def test_sample_1_header(self):
        message = parse(RFC5424_SAMPLE_1)
        self.assertEqual(message.format, "rfc5424")
        self.assertEqual(message.pri, 34)
        self.assertEqual(message.facility, 4)
        self.assertEqual(message.facility_name, "auth")
        self.assertEqual(message.severity, 2)
        self.assertEqual(message.severity_name, "crit")

    def test_sample_1_timestamp(self):
        message = parse(RFC5424_SAMPLE_1)
        self.assertIsNotNone(message.timestamp)
        self.assertEqual(message.timestamp.year, 2003)
        self.assertEqual(message.timestamp.month, 10)
        self.assertEqual(message.timestamp.day, 11)
        self.assertEqual(message.timestamp.hour, 22)
        self.assertEqual(message.timestamp.minute, 14)
        self.assertEqual(message.timestamp.second, 15)
        self.assertEqual(message.timestamp.microsecond, 3000)
        self.assertEqual(message.timestamp.utcoffset(), timedelta(0))

    def test_sample_1_fields(self):
        message = parse(RFC5424_SAMPLE_1)
        self.assertEqual(message.hostname, "mymachine.example.com")
        self.assertEqual(message.app_name, "su")
        self.assertIsNone(message.proc_id)
        self.assertEqual(message.msg_id, "ID47")
        self.assertEqual(message.structured_data, [])

    def test_sample_1_bom_is_stripped(self):
        message = parse(RFC5424_SAMPLE_1)
        self.assertEqual(message.msg, "'su root' failed for lonvick on /dev/pts/8")
        self.assertFalse(message.msg.startswith("\ufeff"))

    def test_sample_2_utc_offset(self):
        message = parse(RFC5424_SAMPLE_2)
        self.assertEqual(message.timestamp.hour, 12)
        self.assertEqual(message.timestamp.minute, 14)
        self.assertEqual(message.timestamp.microsecond, 3)
        self.assertEqual(message.timestamp.utcoffset(), timedelta(0))

    def test_sample_2_fields(self):
        message = parse(RFC5424_SAMPLE_2)
        self.assertEqual(message.hostname, "192.0.2.1")
        self.assertEqual(message.app_name, "myproc")
        self.assertEqual(message.proc_id, "8710")
        self.assertIsNone(message.msg_id)
        self.assertIsNotNone(message.timestamp.tzinfo)
        self.assertEqual(message.msg, "%% It's time to make the do-nuts.")

    def test_sample_3_structured_data(self):
        message = parse(RFC5424_SAMPLE_3)
        self.assertEqual(len(message.structured_data), 1)
        sd_id, params = message.structured_data[0]
        self.assertEqual(sd_id, "exampleSDID@32473")
        self.assertEqual(params["iut"], "3")
        self.assertEqual(params["eventSource"], "Application")
        self.assertEqual(params["eventID"], "1011")
        self.assertEqual(message.msg, "An application event log entry...")

    def test_sample_4_two_elements(self):
        message = parse(RFC5424_SAMPLE_4)
        self.assertEqual(len(message.structured_data), 2)
        self.assertEqual(message.structured_data[1][0], "examplePriority@32473")
        self.assertEqual(message.structured_data[1][1], {"class": "high"})
        self.assertEqual(message.msg, "")

    def test_sample_4_sd_dict_helper(self):
        message = parse(RFC5424_SAMPLE_4)
        self.assertEqual(
            message.sd_dict()["exampleSDID@32473"],
            {"iut": "3", "eventSource": "Application", "eventID": "1011"},
        )


class StructuredDataTests(unittest.TestCase):
    """Structured-data escape handling and error reporting."""

    def test_escaped_quote(self):
        message = parse('<13>1 - h app - - [ex@1 a="say \\"hi\\""] text')
        self.assertEqual(message.structured_data[0][1]["a"], 'say "hi"')

    def test_escaped_backslash(self):
        message = parse('<13>1 - h app - - [ex@1 path="c:\\\\tmp"] text')
        self.assertEqual(message.structured_data[0][1]["path"], "c:\\tmp")

    def test_escaped_bracket(self):
        message = parse('<13>1 - h app - - [ex@1 a="list [1,2\\]"] text')
        self.assertEqual(message.structured_data[0][1]["a"], "list [1,2]")

    def test_equals_inside_value(self):
        message = parse('<13>1 - h app - - [ex@1 pair="a=b"] text')
        self.assertEqual(message.structured_data[0][1]["pair"], "a=b")

    def test_multiple_parameters(self):
        message = parse('<13>1 - h app - - [ex@1 a="1" b="2" c="3"] text')
        self.assertEqual(message.structured_data[0][1], {"a": "1", "b": "2", "c": "3"})

    def test_unterminated_element(self):
        with self.assertRaises(ParseError) as caught:
            parse("<13>1 - h app - - [broken")
        self.assertIn("unterminated", str(caught.exception))

    def test_unterminated_value(self):
        with self.assertRaises(ParseError) as caught:
            parse('<13>1 - h app - - [ex@1 a="unclosed] text')
        self.assertIn("parameter", str(caught.exception))

    def test_missing_structured_data(self):
        with self.assertRaises(ParseError) as caught:
            parse("<13>1 - h app - - not-structured-data")
        self.assertIn("structured data", str(caught.exception))

    def test_empty_element_id(self):
        with self.assertRaises(ParseError) as caught:
            parse("<13>1 - h app - - [ x=\"1\"] text")
        self.assertIn("element id", str(caught.exception))

    def test_unquoted_parameter_value(self):
        with self.assertRaises(ParseError) as caught:
            parse("<13>1 - h app - - [ex@1 a=1] text")
        self.assertIn("quoted", str(caught.exception))

    def test_unescaped_bracket_in_value(self):
        with self.assertRaises(ParseError) as caught:
            parse('<13>1 - h app - - [ex@1 a="x]y"] text')
        self.assertIn("unescaped", str(caught.exception))


class PriTests(unittest.TestCase):
    """PRI decomposition and facility/severity lookup tables."""

    def test_pri_zero(self):
        message = parse("<0>1 - - - - - - msg")
        self.assertEqual(message.facility, 0)
        self.assertEqual(message.facility_name, "kern")
        self.assertEqual(message.severity, 0)
        self.assertEqual(message.severity_name, "emerg")

    def test_pri_maximum(self):
        message = parse("<191>1 - - - - - - msg")
        self.assertEqual(message.pri, 191)
        self.assertEqual(message.facility, 23)
        self.assertEqual(message.facility_name, "local7")
        self.assertEqual(message.severity, 7)
        self.assertEqual(message.severity_name, "debug")

    def test_pri_math_table(self):
        for facility in (0, 4, 10, 16, 23):
            for severity in range(8):
                pri = facility * 8 + severity
                message = parse(f"<{pri}>1 - - - - - - msg")
                with self.subTest(pri=pri):
                    self.assertEqual(message.facility, facility)
                    self.assertEqual(message.severity, severity)
                    self.assertEqual(message.facility_name, FACILITY_NAMES[facility])
                    self.assertEqual(message.severity_name, SEVERITY_NAMES[severity])

    def test_facility_table_size(self):
        self.assertEqual(len(FACILITY_NAMES), 24)
        self.assertEqual(len(SEVERITY_NAMES), 8)
        self.assertEqual(FACILITY_INDEX["authpriv"], 10)
        self.assertEqual(SEVERITY_NAMES[4], "warning")

    def test_pri_out_of_range(self):
        with self.assertRaises(ParseError) as caught:
            parse("<192>1 - h app - - - msg")
        self.assertIn("0-191", str(caught.exception))

    def test_facility_name_fallback(self):
        self.assertEqual(facility_name(24), "facility-24")
        self.assertEqual(severity_name(9), "severity-9")


class Rfc3164Tests(unittest.TestCase):
    """BSD syslog (RFC 3164) lines."""

    def test_classic_line(self):
        message = parse("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick")
        self.assertEqual(message.format, "rfc3164")
        self.assertEqual(message.pri, 34)
        self.assertEqual(message.hostname, "mymachine")
        self.assertEqual(message.app_name, "su")
        self.assertEqual(message.msg, "'su root' failed for lonvick")

    def test_timestamp_fields(self):
        message = parse("<34>Oct 11 22:14:15 mymachine su: hello")
        self.assertEqual(message.timestamp.year, NOW.year)
        self.assertEqual(message.timestamp.month, 10)
        self.assertEqual(message.timestamp.day, 11)
        self.assertEqual(message.timestamp.hour, 22)
        self.assertEqual(message.timestamp.utcoffset(), timedelta(0))

    def test_year_comes_from_reference_time(self):
        message = parse("<13>Mar  1 10:00:00 host app: hello", now=datetime(2031, 6, 1, tzinfo=UTC))
        self.assertEqual(message.timestamp.year, 2031)

    def test_single_digit_day(self):
        message = parse("<13>Mar  1 10:00:00 host app: hello")
        self.assertEqual(message.timestamp.day, 1)
        self.assertEqual(message.timestamp.month, 3)

    def test_tag_with_pid(self):
        message = parse("<13>Mar  1 10:00:00 host app[123]: hello world")
        self.assertEqual(message.app_name, "app")
        self.assertEqual(message.proc_id, "123")
        self.assertEqual(message.msg, "hello world")

    def test_tag_without_pid(self):
        message = parse("<13>Mar  1 10:00:00 host sshd: Accepted password")
        self.assertEqual(message.app_name, "sshd")
        self.assertIsNone(message.proc_id)
        self.assertEqual(message.msg, "Accepted password")

    def test_no_tag_keeps_full_message(self):
        message = parse("<13>Mar  1 10:00:00 host plain message without tag")
        self.assertIsNone(message.app_name)
        self.assertEqual(message.msg, "plain message without tag")

    def test_month_is_case_sensitive(self):
        message = parse("<13>mar  1 10:00:00 host app: hello")
        self.assertNotEqual(message.format, "rfc3164")

    def test_invalid_day_falls_back(self):
        message = parse("<13>Feb 31 10:00:00 host app: hello")
        self.assertEqual(message.format, "lenient")

    def test_unknown_month_falls_back_to_cisco_or_lenient(self):
        message = parse("<13>Xyz  1 10:00:00 host app: hello")
        self.assertIn(message.format, ("lenient", "cisco"))


class CiscoTests(unittest.TestCase):
    """Cisco IOS-style lines with a %FACILITY-SEVERITY-MNEMONIC token."""

    STAR_LINE = (
        "<189>*Mar  1 22:18:12.345: core-sw-01.example %LINK-3-UPDOWN: "
        "Interface GigabitEthernet0/1, changed state to down"
    )

    def test_star_prefixed_timestamp(self):
        message = parse(self.STAR_LINE)
        self.assertEqual(message.format, "cisco")
        self.assertEqual(message.timestamp.year, NOW.year)
        self.assertEqual(message.timestamp.month, 3)
        self.assertEqual(message.timestamp.day, 1)
        self.assertEqual(message.timestamp.hour, 22)
        self.assertEqual(message.timestamp.minute, 18)
        self.assertEqual(message.timestamp.microsecond, 345000)

    def test_mnemonic_fields(self):
        message = parse(self.STAR_LINE)
        self.assertEqual(message.app_name, "link")
        self.assertEqual(message.msg_id, "UPDOWN")
        self.assertEqual(message.hostname, "core-sw-01.example")
        self.assertEqual(message.msg, "Interface GigabitEthernet0/1, changed state to down")
        self.assertEqual(message.pri, 189)

    def test_sequence_number_and_host(self):
        message = parse("<189>32: core-sw-01.example: %SYS-5-CONFIG_I: Configured from console")
        self.assertEqual(message.format, "cisco")
        self.assertIsNone(message.timestamp)
        self.assertEqual(message.hostname, "core-sw-01.example")
        self.assertEqual(message.app_name, "sys")
        self.assertEqual(message.msg_id, "CONFIG_I")

    def test_iso_timestamp_prefix(self):
        message = parse(
            "<190>2026-03-01T22:19:30.500Z core-sw-01.example %SYS-5-CONFIG_I: reload requested"
        )
        self.assertEqual(message.format, "cisco")
        self.assertEqual(message.timestamp.hour, 22)
        self.assertEqual(message.timestamp.minute, 19)
        self.assertEqual(message.hostname, "core-sw-01.example")

    def test_mnemonic_severity_digit_is_not_the_pri_severity(self):
        message = parse("<189>*Mar  1 22:18:12.345: core-sw-01.example %LINK-3-UPDOWN: down")
        self.assertEqual(message.severity, 5)
        self.assertEqual(message.severity_name, "notice")


class LenientTests(unittest.TestCase):
    """Fallback parsing for lines that match no known syslog format."""

    def test_line_without_pri(self):
        message = parse("lab-gateway startup complete without syslog priority")
        self.assertEqual(message.format, "lenient")
        self.assertEqual(message.facility, LENIENT_FACILITY)
        self.assertEqual(message.severity, LENIENT_SEVERITY)
        self.assertEqual(message.pri, 13)
        self.assertIsNone(message.timestamp)
        self.assertIsNone(message.hostname)
        self.assertIsNone(message.app_name)
        self.assertEqual(message.msg, "lab-gateway startup complete without syslog priority")

    def test_line_with_pri_but_unknown_body(self):
        message = parse("<13>myapp: hello there")
        self.assertEqual(message.format, "lenient")
        self.assertEqual(message.pri, 13)
        self.assertEqual(message.msg, "myapp: hello there")

    def test_pri_with_nothing_after_it(self):
        message = parse("<13>")
        self.assertEqual(message.format, "lenient")
        self.assertEqual(message.msg, "")

    def test_raw_is_preserved(self):
        line = "<13>myapp: hello there"
        message = parse(line)
        self.assertEqual(message.raw, line)


class ParseErrorTests(unittest.TestCase):
    """Inputs that must be rejected."""

    def test_empty_line(self):
        with self.assertRaises(ParseError):
            parse("")

    def test_whitespace_line(self):
        with self.assertRaises(ParseError):
            parse("   \t ")

    def test_invalid_rfc5424_timestamp(self):
        with self.assertRaises(ParseError) as caught:
            parse("<34>1 not-a-timestamp host app - - - msg")
        self.assertIn("timestamp", str(caught.exception))

    def test_invalid_utc_offset(self):
        with self.assertRaises(ParseError):
            parse("<34>1 2003-10-11T22:14:15.003+25:00 host app - - - msg")

    def test_impossible_calendar_date(self):
        with self.assertRaises(ParseError):
            parse("<34>1 2003-02-31T22:14:15Z host app - - - msg")


class InputHandlingTests(unittest.TestCase):
    """Encoding, BOM and newline handling."""

    def test_bytes_input(self):
        message = parse(b"<13>Mar  1 10:00:00 host app: hello")
        self.assertEqual(message.format, "rfc3164")
        self.assertEqual(message.msg, "hello")

    def test_utf8_bytes_input(self):
        message = parse("<13>1 - host app - - - capteur temperature 21 C".encode("utf-8"))
        self.assertEqual(message.msg, "capteur temperature 21 C")

    def test_trailing_newline_is_stripped(self):
        message = parse("<13>Mar  1 10:00:00 host app: hello\r\n")
        self.assertEqual(message.msg, "hello")
        self.assertNotIn("\n", message.raw)

    def test_leading_utf8_bom_stripped_from_line(self):
        message = parse("\ufeff<13>Mar  1 10:00:00 host app: hello")
        self.assertEqual(message.format, "rfc3164")
        self.assertEqual(message.hostname, "host")
        self.assertTrue(message.raw.startswith("\ufeff"))

    def test_unicode_message_content(self):
        message = parse("<13>1 - host app - - - capteur temperature 21 C")
        self.assertEqual(message.msg, "capteur temperature 21 C")


class SerializationTests(unittest.TestCase):
    """The helper functions exposed by the parser module."""

    def test_format_timestamp(self):
        moment = datetime(2026, 3, 1, 22, 14, 15, 3000, tzinfo=UTC)
        self.assertEqual(format_timestamp(moment), "2026-03-01T22:14:15.003000Z")

    def test_format_timestamp_none(self):
        self.assertIsNone(format_timestamp(None))

    def test_format_timestamp_normalises_naive(self):
        moment = datetime(2026, 3, 1, 22, 14, 15)
        self.assertEqual(format_timestamp(moment), "2026-03-01T22:14:15.000000Z")

    def test_format_timestamp_converts_to_utc(self):
        moment = datetime(2026, 3, 1, 23, 14, 15, tzinfo=timezone(timedelta(hours=2)))
        self.assertEqual(format_timestamp(moment), "2026-03-01T21:14:15.000000Z")

    def test_utcnow_is_aware_utc(self):
        moment = utcnow()
        self.assertIsNotNone(moment.tzinfo)
        self.assertEqual(moment.utcoffset(), timedelta(0))

    def test_to_dict_shape(self):
        message = parse(RFC5424_SAMPLE_3)
        payload = message.to_dict()
        self.assertEqual(payload["format"], "rfc5424")
        self.assertEqual(payload["pri"], 165)
        self.assertEqual(payload["facility_name"], "local4")
        self.assertEqual(payload["severity_name"], "notice")
        self.assertEqual(payload["timestamp"], "2003-10-11T22:14:15.003000Z")
        self.assertIsInstance(payload["structured_data"], list)
        self.assertEqual(payload["structured_data"][0]["id"], "exampleSDID@32473")
        self.assertEqual(payload["structured_data"][0]["params"]["iut"], "3")
        self.assertEqual(payload["msg"], "An application event log entry...")
        self.assertEqual(payload["raw"], RFC5424_SAMPLE_3)

    def test_to_dict_handles_nil_fields(self):
        payload = parse("<13>1 - - - - - - hello").to_dict()
        self.assertIsNone(payload["timestamp"])
        self.assertIsNone(payload["hostname"])
        self.assertIsNone(payload["app_name"])
        self.assertIsNone(payload["proc_id"])
        self.assertIsNone(payload["msg_id"])
        self.assertEqual(payload["structured_data"], [])

    def test_message_defaults(self):
        message = parse("<13>1 - h app - - - hello")
        self.assertEqual(message.pri, 13)
        self.assertEqual(message.format, "rfc5424")
        self.assertEqual(message.facility_name, "user")
        self.assertEqual(message.structured_data, [])


if __name__ == "__main__":
    unittest.main()

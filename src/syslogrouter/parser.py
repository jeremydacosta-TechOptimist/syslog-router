"""Parsers for RFC 5424, RFC 3164 and Cisco-style syslog lines.

The parser is deliberately tolerant: a line that does not match a known
format is still returned as a :class:`Message` through the documented lenient
fallback instead of raising. :class:`ParseError` is raised only for empty
lines and for malformed RFC 5424 headers or structured-data sections.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = [
    "FACILITY_NAMES",
    "SEVERITY_NAMES",
    "FACILITY_INDEX",
    "SEVERITY_INDEX",
    "LENIENT_FACILITY",
    "LENIENT_SEVERITY",
    "Message",
    "ParseError",
    "facility_name",
    "format_timestamp",
    "parse_line",
    "severity_name",
    "utcnow",
]

#: Syslog facility names, indexed by facility number (RFC 5424 section 6.2.1).
FACILITY_NAMES: tuple[str, ...] = (
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "audit",
    "alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)

#: Syslog severity names, indexed by severity number (0 is the most severe).
SEVERITY_NAMES: tuple[str, ...] = (
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
)

FACILITY_INDEX: dict[str, int] = {name: index for index, name in enumerate(FACILITY_NAMES)}
SEVERITY_INDEX: dict[str, int] = {name: index for index, name in enumerate(SEVERITY_NAMES)}

#: Facility used by the lenient fallback for lines without a valid PRI.
LENIENT_FACILITY = FACILITY_INDEX["user"]
#: Severity used by the lenient fallback for lines without a valid PRI.
LENIENT_SEVERITY = SEVERITY_INDEX["notice"]

_MONTHS: dict[str, int] = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424_HEADER_RE = re.compile(
    r"^(?P<version>[1-9]) (?P<timestamp>\S+) (?P<hostname>\S+) (?P<app>\S+) "
    r"(?P<proc>\S+) (?P<msgid>\S+) (?P<rest>.*)$",
    re.DOTALL,
)
_RFC3339_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<offset>Z|[+-]\d{2}:\d{2})$"
)
_RFC3164_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) (?P<day>[ \d]\d) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) (?P<rest>.*)$",
    re.DOTALL,
)
_TAG_RE = re.compile(r"^(?P<app>[^\s:\[]+)(?:\[(?P<pid>[^\]]*)\])?$")
_CISCO_MNEMONIC_RE = re.compile(
    r"%(?P<facility>[A-Za-z0-9_]+)-(?P<severity>[0-7])-"
    r"(?P<mnemonic>[A-Za-z0-9_]+): ?(?P<msg>.*)$",
    re.DOTALL,
)
_CISCO_SHORT_TS_RE = re.compile(
    r"^\*?(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\.(?P<millis>\d{3}):\s*"
)
_CISCO_ISO_TS_RE = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+) ")
_CISCO_SEQ_RE = re.compile(r"^(?P<seq>\d{1,10}):\s*")

_FORMATS = ("rfc5424", "rfc3164", "cisco", "lenient")


class ParseError(ValueError):
    """Raised when a line cannot be parsed at all."""


def utcnow() -> datetime:
    """Return the current UTC time as an aware datetime."""
    return datetime.now(timezone.utc)


def facility_name(number: int) -> str:
    """Return the facility name for *number* (``facility-N`` when unknown)."""
    try:
        return FACILITY_NAMES[number]
    except IndexError:
        return f"facility-{number}"


def severity_name(number: int) -> str:
    """Return the severity name for *number* (``severity-N`` when unknown)."""
    try:
        return SEVERITY_NAMES[number]
    except IndexError:
        return f"severity-{number}"


def format_timestamp(value: datetime | None) -> str | None:
    """Format an aware datetime as an ISO 8601 UTC string with microseconds."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class Message:
    """A parsed syslog message.

    ``timestamp`` is always an aware UTC datetime (``None`` when the line has
    no timestamp, which only happens for lenient and Cisco-style lines without
    a clock prefix).  ``structured_data`` is a list of ``(sd_id, params)``
    tuples in the order they appear in the line.
    """

    raw: str
    pri: int
    facility: int
    facility_name: str
    severity: int
    severity_name: str
    timestamp: datetime | None
    hostname: str | None
    app_name: str | None
    proc_id: str | None
    msg_id: str | None
    structured_data: list[tuple[str, dict[str, str]]] = field(default_factory=list)
    msg: str = ""
    format: str = "lenient"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the message."""
        return {
            "format": self.format,
            "pri": self.pri,
            "facility": self.facility,
            "facility_name": self.facility_name,
            "severity": self.severity,
            "severity_name": self.severity_name,
            "timestamp": format_timestamp(self.timestamp),
            "hostname": self.hostname,
            "app_name": self.app_name,
            "proc_id": self.proc_id,
            "msg_id": self.msg_id,
            "structured_data": [
                {"id": sd_id, "params": dict(params)} for sd_id, params in self.structured_data
            ],
            "msg": self.msg,
            "raw": self.raw,
        }

    def sd_dict(self) -> dict[str, dict[str, str]]:
        """Return the structured data as a mapping of element id to parameters."""
        return {sd_id: dict(params) for sd_id, params in self.structured_data}


def parse_line(line: str | bytes, now: datetime | None = None) -> Message:
    """Parse one syslog line into a :class:`Message`.

    ``now`` is the reference time used to infer the year of RFC 3164
    timestamps and of Cisco log prefixes that omit the year.  It defaults to
    the current UTC time.
    """
    text = _coerce_text(line)
    raw = text
    if text.startswith("\ufeff"):
        text = text[1:]
    if not text.strip():
        raise ParseError("empty line")
    reference = now or utcnow()

    pri_match = _PRI_RE.match(text)
    if not pri_match:
        return _lenient(raw, LENIENT_FACILITY, LENIENT_SEVERITY, body=text)
    pri = int(pri_match.group("pri"))
    if pri > 191:
        raise ParseError(f"PRI {pri} is out of the valid range 0-191")
    facility, severity = divmod(pri, 8)
    rest = text[pri_match.end() :]
    if not rest:
        return _lenient(raw, facility, severity, body="")

    header = _RFC5424_HEADER_RE.match(rest)
    if header:
        return _parse_rfc5424(raw, pri, facility, severity, header)

    legacy = _RFC3164_RE.match(rest)
    if legacy:
        message = _parse_rfc3164(raw, pri, facility, severity, legacy, reference)
        if message is not None:
            return message

    if "%" in rest:
        cisco = _parse_cisco(raw, pri, facility, severity, rest, reference)
        if cisco is not None:
            return cisco

    return _lenient(raw, facility, severity, body=rest.lstrip())


def _coerce_text(line: str | bytes) -> str:
    if isinstance(line, bytes):
        text = line.decode("utf-8", "replace")
    else:
        text = line
    return text.rstrip("\r\n")


def _parse_rfc5424(
    raw: str,
    pri: int,
    facility: int,
    severity: int,
    header: re.Match[str],
) -> Message:
    timestamp_text = header.group("timestamp")
    timestamp = None
    if timestamp_text != "-":
        if not _RFC3339_RE.match(timestamp_text):
            raise ParseError(f"invalid RFC 5424 timestamp: {timestamp_text!r}")
        timestamp = _parse_rfc3339(timestamp_text)
    structured_data, msg = _split_structured_data(header.group("rest"))
    return Message(
        raw=raw,
        pri=pri,
        facility=facility,
        facility_name=facility_name(facility),
        severity=severity,
        severity_name=severity_name(severity),
        timestamp=timestamp,
        hostname=_nil(header.group("hostname")),
        app_name=_nil(header.group("app")),
        proc_id=_nil(header.group("proc")),
        msg_id=_nil(header.group("msgid")),
        structured_data=structured_data,
        msg=msg,
        format="rfc5424",
    )


def _parse_rfc3164(
    raw: str,
    pri: int,
    facility: int,
    severity: int,
    match: re.Match[str],
    now: datetime,
) -> Message | None:
    month = _MONTHS.get(match.group("month"))
    if month is None:
        return None
    try:
        timestamp = datetime(
            now.astimezone(timezone.utc).year,
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None

    rest = match.group("rest")
    if " " in rest:
        hostname, payload = rest.split(" ", 1)
    else:
        hostname, payload = rest, ""
    app_name: str | None = None
    proc_id: str | None = None
    msg = payload
    tag, colon, content = payload.partition(":")
    if colon:
        tag_match = _TAG_RE.match(tag)
        if tag_match is not None:
            app_name = tag_match.group("app")
            proc_id = tag_match.group("pid") or None
            msg = content[1:] if content.startswith(" ") else content
    return Message(
        raw=raw,
        pri=pri,
        facility=facility,
        facility_name=facility_name(facility),
        severity=severity,
        severity_name=severity_name(severity),
        timestamp=timestamp,
        hostname=hostname or None,
        app_name=app_name,
        proc_id=proc_id,
        msg_id=None,
        structured_data=[],
        msg=msg,
        format="rfc3164",
    )


def _parse_cisco(
    raw: str,
    pri: int,
    facility: int,
    severity: int,
    rest: str,
    now: datetime,
) -> Message | None:
    mnemonic = _CISCO_MNEMONIC_RE.search(rest)
    if mnemonic is None:
        return None
    timestamp, hostname = _parse_cisco_prefix(rest[: mnemonic.start()], now)
    return Message(
        raw=raw,
        pri=pri,
        facility=facility,
        facility_name=facility_name(facility),
        severity=severity,
        severity_name=severity_name(severity),
        timestamp=timestamp,
        hostname=hostname,
        app_name=mnemonic.group("facility").lower(),
        proc_id=None,
        msg_id=mnemonic.group("mnemonic"),
        structured_data=[],
        msg=mnemonic.group("msg"),
        format="cisco",
    )


def _parse_cisco_prefix(prefix: str, now: datetime) -> tuple[datetime | None, str | None]:
    text = prefix.strip()
    timestamp: datetime | None = None
    sequence = _CISCO_SEQ_RE.match(text)
    if sequence is not None:
        text = text[sequence.end() :]

    short = _CISCO_SHORT_TS_RE.match(text)
    if short is not None:
        month = _MONTHS.get(short.group("month"))
        if month is not None:
            try:
                timestamp = datetime(
                    now.astimezone(timezone.utc).year,
                    month,
                    int(short.group("day")),
                    int(short.group("hour")),
                    int(short.group("minute")),
                    int(short.group("second")),
                    int(short.group("millis")) * 1000,
                    tzinfo=timezone.utc,
                )
            except ValueError:
                timestamp = None
        text = text[short.end() :]
    else:
        iso = _CISCO_ISO_TS_RE.match(text)
        if iso is not None:
            try:
                timestamp = _parse_rfc3339(iso.group("timestamp"))
            except ParseError:
                timestamp = None
            text = text[iso.end() :]

    hostname: str | None = None
    if text:
        token = text.split()[0]
        hostname = token.rstrip(":") or None
    return timestamp, hostname


def _parse_rfc3339(text: str) -> datetime:
    match = _RFC3339_RE.match(text)
    if match is None:
        raise ParseError(f"invalid RFC 3339 timestamp: {text!r}")
    offset = match.group("offset")
    if offset == "Z":
        tzinfo = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        hours = int(offset[1:3])
        minutes = int(offset[4:6])
        if hours > 23 or minutes > 59:
            raise ParseError(f"invalid UTC offset in timestamp: {text!r}")
        tzinfo = timezone(sign * timedelta(hours=hours, minutes=minutes))
    fraction = (match.group("fraction") or "").ljust(6, "0")[:6]
    try:
        value = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            int(fraction),
            tzinfo=tzinfo,
        )
    except ValueError as exc:
        raise ParseError(f"invalid timestamp {text!r}: {exc}") from exc
    return value.astimezone(timezone.utc)


def _nil(value: str) -> str | None:
    return None if value == "-" else value


def _split_structured_data(rest: str) -> tuple[list[tuple[str, dict[str, str]]], str]:
    elements: list[tuple[str, dict[str, str]]] = []
    if rest.startswith("-"):
        remainder = rest[1:]
        if remainder and not remainder.startswith(" "):
            raise ParseError("malformed structured data section")
        msg = remainder[1:] if remainder else ""
    elif rest.startswith("["):
        elements, position = _parse_sd_elements(rest)
        remainder = rest[position:]
        if remainder and not remainder.startswith(" "):
            raise ParseError("malformed structured data section")
        msg = remainder[1:] if remainder else ""
    else:
        raise ParseError("missing structured data section")
    if msg.startswith("\ufeff"):
        msg = msg[1:]
    return elements, msg


def _parse_sd_elements(text: str) -> tuple[list[tuple[str, dict[str, str]]], int]:
    elements: list[tuple[str, dict[str, str]]] = []
    position = 0
    while position < len(text) and text[position] == "[":
        position += 1
        start = position
        while position < len(text) and text[position] not in " ]":
            position += 1
        sd_id = text[start:position]
        if not sd_id:
            raise ParseError("empty structured data element id")
        params: dict[str, str] = {}
        while True:
            if position >= len(text):
                raise ParseError("unterminated structured data element")
            char = text[position]
            if char == "]":
                position += 1
                break
            if char != " ":
                raise ParseError("invalid structured data parameter separator")
            position += 1
            if position >= len(text):
                raise ParseError("unterminated structured data element")
            if text[position] == "]":
                position += 1
                break
            name_start = position
            while position < len(text) and text[position] not in "= ]":
                position += 1
            if position >= len(text) or text[position] != "=":
                raise ParseError("malformed structured data parameter")
            name = text[name_start:position]
            if not name:
                raise ParseError("empty structured data parameter name")
            position += 1
            if position >= len(text) or text[position] != '"':
                raise ParseError("structured data parameter value must be quoted")
            position += 1
            value_chars: list[str] = []
            while True:
                if position >= len(text):
                    raise ParseError("unterminated structured data parameter value")
                char = text[position]
                if char == '"':
                    position += 1
                    break
                if char == "\\":
                    if position + 1 >= len(text):
                        raise ParseError("dangling escape in structured data parameter")
                    following = text[position + 1]
                    if following in '"\\]':
                        value_chars.append(following)
                        position += 2
                        continue
                    value_chars.append("\\")
                    position += 1
                    continue
                if char == "]":
                    raise ParseError("unescaped ] in structured data parameter value")
                value_chars.append(char)
                position += 1
            params[name] = "".join(value_chars)
        elements.append((sd_id, params))
    return elements, position


def _lenient(
    raw: str,
    facility: int,
    severity: int,
    body: str,
) -> Message:
    return Message(
        raw=raw,
        pri=facility * 8 + severity,
        facility=facility,
        facility_name=facility_name(facility),
        severity=severity,
        severity_name=severity_name(severity),
        timestamp=None,
        hostname=None,
        app_name=None,
        proc_id=None,
        msg_id=None,
        structured_data=[],
        msg=body,
        format="lenient",
    )

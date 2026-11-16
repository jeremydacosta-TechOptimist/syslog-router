"""Ordered JSON routing rules.

A rule set is an ordered list of rules.  Every rule has a ``match`` object
with optional matchers (``hosts``, ``apps``, ``facilities``, ``severity_max``,
``regex``) and an ``action`` object with optional actions (``store``,
``file``, ``counter``, ``drop``).  All matching rules are applied in file
order unless a rule sets ``"stop": true``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .parser import FACILITY_INDEX, Message

__all__ = [
    "ActionSpec",
    "MatchSpec",
    "Rule",
    "RuleSet",
    "RulesError",
    "build_ruleset",
    "load_rules",
    "validate_rules",
]

_ALLOWED_RULE_KEYS = {"name", "match", "action", "stop"}
_ALLOWED_MATCH_KEYS = {"hosts", "apps", "facilities", "severity_max", "regex"}
_ALLOWED_ACTION_KEYS = {"store", "file", "counter", "drop"}
_TOP_LEVEL_KEYS = {"rules"}


class RulesError(ValueError):
    """Raised when a rule set cannot be loaded or is invalid."""


@dataclass(frozen=True)
class MatchSpec:
    """The matching conditions of one rule (all conditions are ANDed)."""

    hosts: tuple[str, ...] = ()
    apps: tuple[str, ...] = ()
    facilities: tuple[int, ...] = ()
    severity_max: int | None = None
    regex: re.Pattern[str] | None = None

    def matches(self, message: Message) -> bool:
        """Return ``True`` when *message* satisfies every configured matcher."""
        if self.hosts:
            host = (message.hostname or "").lower()
            if not any(fnmatchcase(host, pattern.lower()) for pattern in self.hosts):
                return False
        if self.apps:
            app = (message.app_name or "").lower()
            if not any(fnmatchcase(app, pattern.lower()) for pattern in self.apps):
                return False
        if self.facilities and message.facility not in self.facilities:
            return False
        if self.severity_max is not None and message.severity > self.severity_max:
            return False
        if self.regex is not None and self.regex.search(message.msg) is None:
            return False
        return True


@dataclass(frozen=True)
class ActionSpec:
    """Actions applied by one rule.

    ``store`` is tri-state: ``None`` leaves the storage decision untouched,
    ``True`` forces storage and ``False`` suppresses it.  ``drop`` always
    suppresses storage.  ``file`` and ``counter`` are side effects that run
    even for dropped events.
    """

    store: bool | None = None
    file: str | None = None
    counter: str | None = None
    drop: bool = False


@dataclass(frozen=True)
class Rule:
    """One named, ordered routing rule."""

    name: str
    match: MatchSpec = field(default_factory=MatchSpec)
    action: ActionSpec = field(default_factory=ActionSpec)
    stop: bool = False


@dataclass(frozen=True)
class RuleSet:
    """An ordered list of rules loaded from one JSON document."""

    rules: tuple[Rule, ...]
    source: str | None = None

    def matching(self, message: Message) -> list[Rule]:
        """Return the rules that match *message*, in file order."""
        return [rule for rule in self.rules if rule.match.matches(message)]


def validate_rules(data: Any) -> list[str]:
    """Validate a decoded JSON rule document and return a list of errors.

    An empty list means the document is valid.  The function never raises for
    malformed content; it reports every problem it can find so that one run of
    ``syslogrouter rules validate`` shows all the fixes needed.
    """
    errors: list[str] = []
    if isinstance(data, dict):
        unknown = sorted(set(data) - _TOP_LEVEL_KEYS)
        if unknown:
            errors.append(f"rules document has unknown key(s): {', '.join(unknown)}")
        if "rules" not in data:
            errors.append('rules document is missing the "rules" list')
            return errors
        payload = data["rules"]
    elif isinstance(data, list):
        payload = data
    else:
        return ["rules document must be a JSON object with a \"rules\" list or a list of rules"]
    if not isinstance(payload, list):
        return ['"rules" must be a list of rule objects']

    seen_names: set[str] = set()
    for index, raw_rule in enumerate(payload):
        prefix = f"rule {index}"
        if not isinstance(raw_rule, dict):
            errors.append(f"{prefix}: must be a JSON object")
            continue
        unknown = sorted(set(raw_rule) - _ALLOWED_RULE_KEYS)
        if unknown:
            errors.append(f"{prefix}: unknown key(s): {', '.join(unknown)}")
        name = raw_rule.get("name", f"rule-{index + 1}")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix}: name must be a non-empty string")
        elif name in seen_names:
            errors.append(f'{prefix}: duplicate rule name "{name}"')
        else:
            seen_names.add(name)
        if "match" not in raw_rule:
            errors.append(f'{prefix}: missing the "match" object')
        else:
            errors.extend(_validate_match(raw_rule["match"], prefix))
        if "action" not in raw_rule:
            errors.append(f'{prefix}: missing the "action" object')
        else:
            errors.extend(_validate_action(raw_rule["action"], prefix))
        if "stop" in raw_rule and not isinstance(raw_rule["stop"], bool):
            errors.append(f"{prefix}: stop must be true or false")
    return errors


def _validate_match(match: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(match, dict):
        return [f"{prefix}: match must be a JSON object"]
    unknown = sorted(set(match) - _ALLOWED_MATCH_KEYS)
    if unknown:
        errors.append(f"{prefix}: match has unknown key(s): {', '.join(unknown)}")
    for key in ("hosts", "apps"):
        if key in match:
            value = match[key]
            if not isinstance(value, list) or not value:
                errors.append(f"{prefix}: match.{key} must be a non-empty list of strings")
            elif not all(isinstance(item, str) and item.strip() for item in value):
                errors.append(f"{prefix}: match.{key} must contain non-empty strings")
    if "facilities" in match:
        value = match["facilities"]
        if not isinstance(value, list) or not value:
            errors.append(f"{prefix}: match.facilities must be a non-empty list")
        else:
            for item in value:
                if isinstance(item, bool):
                    errors.append(f"{prefix}: match.facilities contains an invalid value: {item!r}")
                elif isinstance(item, int):
                    if not 0 <= item <= 23:
                        errors.append(f"{prefix}: match.facilities number out of range 0-23: {item}")
                elif isinstance(item, str):
                    if item.strip().lower() not in FACILITY_INDEX:
                        errors.append(f"{prefix}: match.facilities has unknown name: {item!r}")
                else:
                    errors.append(f"{prefix}: match.facilities contains an invalid value: {item!r}")
    if "severity_max" in match:
        value = match["severity_max"]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 7:
            errors.append(f"{prefix}: match.severity_max must be an integer between 0 and 7")
    if "regex" in match:
        value = match["regex"]
        if not isinstance(value, str) or not value:
            errors.append(f"{prefix}: match.regex must be a non-empty string")
        else:
            try:
                re.compile(value)
            except re.error as exc:
                errors.append(f"{prefix}: match.regex is not a valid regular expression: {exc}")
    return errors


def _validate_action(action: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(action, dict):
        return [f"{prefix}: action must be a JSON object"]
    unknown = sorted(set(action) - _ALLOWED_ACTION_KEYS)
    if unknown:
        errors.append(f"{prefix}: action has unknown key(s): {', '.join(unknown)}")
    for key in ("store", "drop"):
        if key in action and not isinstance(action[key], bool):
            errors.append(f"{prefix}: action.{key} must be true or false")
    for key in ("file", "counter"):
        if key in action:
            value = action[key]
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{prefix}: action.{key} must be a non-empty string")
    return errors


def build_ruleset(data: Any, source: str | None = None) -> RuleSet:
    """Build a :class:`RuleSet` from an already validated JSON document."""
    errors = validate_rules(data)
    if errors:
        raise RulesError("\n".join(errors))
    payload = data["rules"] if isinstance(data, dict) else data
    rules: list[Rule] = []
    for index, raw_rule in enumerate(payload):
        match_data = raw_rule.get("match") or {}
        action_data = raw_rule.get("action") or {}
        facilities: list[int] = []
        for item in match_data.get("facilities", []):
            if isinstance(item, str):
                facilities.append(FACILITY_INDEX[item.strip().lower()])
            else:
                facilities.append(int(item))
        rule = Rule(
            name=raw_rule.get("name") or f"rule-{index + 1}",
            match=MatchSpec(
                hosts=tuple(match_data.get("hosts", [])),
                apps=tuple(match_data.get("apps", [])),
                facilities=tuple(facilities),
                severity_max=match_data.get("severity_max"),
                regex=(
                    re.compile(match_data["regex"])
                    if isinstance(match_data.get("regex"), str)
                    else None
                ),
            ),
            action=ActionSpec(
                store=action_data.get("store"),
                file=action_data.get("file"),
                counter=action_data.get("counter"),
                drop=bool(action_data.get("drop", False)),
            ),
            stop=bool(raw_rule.get("stop", False)),
        )
        rules.append(rule)
    return RuleSet(rules=tuple(rules), source=source)


def load_rules(path: str | Path) -> RuleSet:
    """Load and validate a rule set from *path*.

    Raises :class:`RulesError` with a precise, multi-line message when the
    file cannot be read, is not JSON, or is not a valid rule set.
    """
    rules_path = Path(path)
    try:
        text = rules_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise RulesError(f"cannot read rules file {rules_path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RulesError(
            f"invalid JSON in {rules_path}: {exc.msg} (line {exc.lineno} column {exc.colno})"
        ) from exc
    return build_ruleset(data, source=str(rules_path))

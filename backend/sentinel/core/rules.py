"""Detection rules: loaded from YAML, validated, and matched against events.

A rule describes *what* to look for. The :mod:`engine` decides *when* it
fires, using a sliding time window per rule and per group key.

Two rule types exist:

``threshold`` (default)
    Fire when at least ``threshold`` matching events share the same
    ``group_by`` value inside ``window`` seconds. With ``distinct`` set, count
    distinct values of that field instead (e.g. distinct usernames tried from
    one IP = password spraying). ``threshold: 1`` turns it into a simple
    single-event signature.

``sequence``
    Fire when an event matching ``then`` arrives after at least ``threshold``
    events matching ``match`` for the same key inside the window – e.g. a
    successful login right after a burst of failures.

Match conditions compare event fields::

    kind: ssh_failed              # equality
    kind: {in: [ssh_failed, ssh_invalid_user]}
    status: {gte: 400, lt: 500}   # numeric comparisons: gt gte lt lte
    path: {regex: '\\.env$'}     # Python regular expression (search)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ("low", "medium", "high", "critical")
_OPS = {"in", "regex", "gt", "gte", "lt", "lte", "not"}


class RuleError(ValueError):
    """Raised when a rule file is invalid. The message names the rule."""


@dataclass(slots=True)
class Condition:
    field: str
    op: str
    value: Any

    def test(self, fields: dict[str, Any]) -> bool:
        v = fields.get(self.field)
        if self.op == "eq":
            return v == self.value
        if self.op == "not":
            return v != self.value
        if self.op == "in":
            return v in self.value
        if self.op == "regex":
            return v is not None and self.value.search(str(v)) is not None
        if v is None:
            return False
        try:
            return {"gt": v > self.value, "gte": v >= self.value,
                    "lt": v < self.value, "lte": v <= self.value}[self.op]
        except TypeError:
            return False


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str = ""
    type: str = "threshold"
    match: list[Condition] = field(default_factory=list)
    then: list[Condition] = field(default_factory=list)
    group_by: str | None = None
    threshold: int = 1
    window: int = 60
    distinct: str | None = None
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    def matches(self, fields: dict[str, Any]) -> bool:
        return all(c.test(fields) for c in self.match)

    def matches_then(self, fields: dict[str, Any]) -> bool:
        return bool(self.then) and all(c.test(fields) for c in self.then)

    def summary(self) -> dict[str, Any]:
        """JSON-friendly view for the API."""
        def cond(c: Condition) -> dict[str, Any]:
            val = c.value.pattern if c.op == "regex" else c.value
            return {"field": c.field, "op": c.op, "value": val}
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "description": self.description, "type": self.type,
            "match": [cond(c) for c in self.match], "then": [cond(c) for c in self.then],
            "group_by": self.group_by, "threshold": self.threshold, "window": self.window,
            "distinct": self.distinct, "enabled": self.enabled, "tags": self.tags,
        }


def _conditions(rule_id: str, spec: Any, key: str) -> list[Condition]:
    if not isinstance(spec, dict) or not spec:
        raise RuleError(f"{rule_id}: '{key}' must be a non-empty mapping")
    out: list[Condition] = []
    for fname, cond in spec.items():
        if isinstance(cond, dict):
            unknown = set(cond) - _OPS
            if unknown:
                raise RuleError(f"{rule_id}: unknown operator(s) {sorted(unknown)} on '{fname}'")
            for op, value in cond.items():
                if op == "regex":
                    try:
                        value = re.compile(value)
                    except re.error as exc:
                        raise RuleError(f"{rule_id}: bad regex on '{fname}': {exc}") from None
                elif op == "in" and not isinstance(value, list):
                    raise RuleError(f"{rule_id}: 'in' on '{fname}' needs a list")
                out.append(Condition(fname, op, value))
        else:
            out.append(Condition(fname, "eq", cond))
    return out


def parse_rule(spec: dict[str, Any]) -> Rule:
    rule_id = str(spec.get("id") or "").strip()
    if not rule_id:
        raise RuleError("every rule needs an 'id'")
    sev = spec.get("severity", "medium")
    if sev not in SEVERITIES:
        raise RuleError(f"{rule_id}: severity must be one of {', '.join(SEVERITIES)}")
    rtype = spec.get("type", "threshold")
    if rtype not in ("threshold", "sequence"):
        raise RuleError(f"{rule_id}: type must be 'threshold' or 'sequence'")
    threshold, window = int(spec.get("threshold", 1)), int(spec.get("window", 60))
    if threshold < 1 or window < 1:
        raise RuleError(f"{rule_id}: threshold and window must be positive")
    rule = Rule(
        id=rule_id, title=str(spec.get("title") or rule_id), severity=sev,
        description=str(spec.get("description", "")).strip(), type=rtype,
        match=_conditions(rule_id, spec.get("match"), "match"),
        group_by=spec.get("group_by"), threshold=threshold, window=window,
        distinct=spec.get("distinct"), enabled=bool(spec.get("enabled", True)),
        tags=list(spec.get("tags", [])),
    )
    if rtype == "sequence":
        rule.then = _conditions(rule_id, spec.get("then"), "then")
        if not rule.group_by:
            raise RuleError(f"{rule_id}: sequence rules need 'group_by'")
    return rule


def load_rules(path: str | Path) -> list[Rule]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    specs = data.get("rules", []) if isinstance(data, dict) else []
    rules = [parse_rule(s) for s in specs]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule ids: {sorted(dupes)}")
    return rules

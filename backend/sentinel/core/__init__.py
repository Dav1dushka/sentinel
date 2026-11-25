"""Pure detection logic: no I/O, no database, no web framework."""
from .engine import AlertDraft, Engine
from .parsers import Event, parse_line
from .rules import Rule, RuleError, load_rules

__all__ = ["AlertDraft", "Engine", "Event", "Rule", "RuleError", "load_rules", "parse_line"]

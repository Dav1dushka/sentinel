"""Sliding-window detection engine.

The engine is deliberately free of I/O: feed it events, get alert drafts
back. That keeps it easy to test and lets the worker decide where alerts go
(database, Telegram, ...).

Time is *event time*, not wall-clock time, so replaying an old log file gives
the same alerts as watching it live.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parsers import Event
from .rules import Rule

EVIDENCE_LINES = 12


@dataclass(slots=True)
class AlertDraft:
    rule_id: str
    title: str
    severity: str
    description: str
    group_by: str | None
    key: str
    count: int
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]


@dataclass(slots=True)
class _State:
    hits: deque = field(default_factory=deque)        # (ts, distinct_value, raw)
    last_fired: datetime | None = None
    last_seen: datetime | None = None


class Engine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = [r for r in rules if r.enabled]
        self._state: dict[tuple[str, str], _State] = {}
        self._seen = 0

    # -- public ------------------------------------------------------------
    def process(self, event: Event) -> list[AlertDraft]:
        f = event.fields()
        out: list[AlertDraft] = []
        for rule in self.rules:
            if rule.type == "sequence":
                draft = self._sequence(rule, event, f)
            else:
                draft = self._threshold(rule, event, f)
            if draft:
                out.append(draft)
        self._seen += 1
        if self._seen % 5000 == 0:
            self.gc(event.ts)
        return out

    def process_many(self, events: Iterable[Event]) -> list[AlertDraft]:
        out: list[AlertDraft] = []
        for ev in events:
            out.extend(self.process(ev))
        return out

    def gc(self, now: datetime) -> int:
        """Forget keys that have been quiet for longer than every window."""
        horizon = max((r.window for r in self.rules), default=60) * 2
        cutoff = now - timedelta(seconds=horizon)
        stale = [k for k, s in self._state.items() if s.last_seen and s.last_seen < cutoff]
        for k in stale:
            del self._state[k]
        return len(stale)

    # -- internals ---------------------------------------------------------
    def _key(self, rule: Rule, f: dict) -> str | None:
        if not rule.group_by:
            return "*"
        v = f.get(rule.group_by)
        return None if v in (None, "") else str(v)

    def _slot(self, rule: Rule, key: str) -> _State:
        return self._state.setdefault((rule.id, key), _State())

    @staticmethod
    def _evict(st: _State, now: datetime, window: int) -> None:
        cutoff = now - timedelta(seconds=window)
        while st.hits and st.hits[0][0] < cutoff:
            st.hits.popleft()

    @staticmethod
    def _cooling(st: _State, now: datetime, window: int) -> bool:
        return st.last_fired is not None and now - st.last_fired < timedelta(seconds=window)

    def _draft(self, rule: Rule, key: str, count: int, st: _State, extra: str | None = None) -> AlertDraft:
        lines = [h[2] for h in st.hits][-EVIDENCE_LINES:]
        if extra:
            lines = (lines + [extra])[-EVIDENCE_LINES:]
        return AlertDraft(
            rule_id=rule.id, title=rule.title, severity=rule.severity, description=rule.description,
            group_by=rule.group_by, key=key, count=count,
            first_seen=st.hits[0][0] if st.hits else st.last_seen, last_seen=st.last_seen,
            evidence=lines,
        )

    def _threshold(self, rule: Rule, ev: Event, f: dict) -> AlertDraft | None:
        if not rule.matches(f):
            return None
        key = self._key(rule, f)
        if key is None:
            return None
        st = self._slot(rule, key)
        st.hits.append((ev.ts, f.get(rule.distinct) if rule.distinct else None, ev.raw))
        st.last_seen = ev.ts
        self._evict(st, ev.ts, rule.window)
        count = len({h[1] for h in st.hits if h[1] is not None}) if rule.distinct else len(st.hits)
        if count < rule.threshold or self._cooling(st, ev.ts, rule.window):
            return None
        st.last_fired = ev.ts
        return self._draft(rule, key, count, st)

    def _sequence(self, rule: Rule, ev: Event, f: dict) -> AlertDraft | None:
        is_first, is_then = rule.matches(f), rule.matches_then(f)
        if not (is_first or is_then):
            return None
        key = self._key(rule, f)
        if key is None:
            return None
        st = self._slot(rule, key)
        st.last_seen = ev.ts
        self._evict(st, ev.ts, rule.window)
        if is_then and len(st.hits) >= rule.threshold and not self._cooling(st, ev.ts, rule.window):
            st.last_fired = ev.ts
            return self._draft(rule, key, len(st.hits), st, extra=ev.raw)
        if is_first:
            st.hits.append((ev.ts, None, ev.raw))
        return None

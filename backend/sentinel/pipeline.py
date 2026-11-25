"""Parse → store → detect → alert → notify.

The same pipeline runs inside the Redis worker (normal setup) and directly
inside the API when no Redis URL is configured (local runs and tests).
Detection state lives in one process, which is why production uses a single
worker consuming the queue.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify
from .config import get_settings
from .core import AlertDraft, Engine, Event, load_rules, parse_line
from .db import Alert
from .db import Event as EventRow

log = logging.getLogger("sentinel.pipeline")
_engine: Engine | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = Engine(load_rules(get_settings().rules_path))
    return _engine


def reset_engine() -> None:
    """Drop detection state (used by tests and after editing rules)."""
    global _engine
    _engine = None


@dataclass
class BatchResult:
    received: int
    parsed: int
    alerts: int


def _aware(dt):
    """SQLite drops tzinfo; treat naive datetimes from the DB as UTC."""
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def _store_alert(db: Session, d: AlertDraft, window: int) -> tuple[Alert, bool]:
    """Merge into an open alert for the same rule and key, or create one."""
    recent = d.first_seen - timedelta(seconds=window)
    existing = db.scalars(
        select(Alert).where(Alert.rule_id == d.rule_id, Alert.key == d.key, Alert.status == "open")
        .order_by(Alert.last_seen.desc()).limit(1)).first()
    if existing and _aware(existing.last_seen) >= recent:
        existing.count += d.count
        existing.last_seen = d.last_seen
        existing.evidence = (list(existing.evidence) + d.evidence)[-30:]
        return existing, False
    alert = Alert(rule_id=d.rule_id, title=d.title, severity=d.severity, description=d.description,
                  group_by=d.group_by, key=d.key, count=d.count, first_seen=d.first_seen,
                  last_seen=d.last_seen, evidence=d.evidence, history=[])
    db.add(alert)
    return alert, True


def process_events(db: Session, events: list[Event], *, send_notifications: bool = True) -> int:
    engine = get_engine()
    windows = {r.id: r.window for r in engine.rules}
    db.add_all(EventRow(ts=e.ts, source=e.source, kind=e.kind, host=e.host, ip=e.ip, user=e.user,
                        method=e.method, path=e.path, status=e.status, command=e.command, raw=e.raw)
               for e in events)
    new_alerts: list[Alert] = []
    for draft in engine.process_many(sorted(events, key=lambda e: e.ts)):
        alert, created = _store_alert(db, draft, windows.get(draft.rule_id, 60))
        if created:
            new_alerts.append(alert)
        db.flush()
    db.commit()
    if send_notifications:
        for a in new_alerts:
            notify.send_alert(a)
    return len(new_alerts)


def process_batch(db: Session, source: str, lines: list[str], host: str | None = None) -> BatchResult:
    events = [e for e in (parse_line(source, ln, host=host) for ln in lines) if e]
    created = process_events(db, events) if events else 0
    log.info("batch source=%s host=%s lines=%d events=%d alerts=%d", source, host, len(lines), len(events), created)
    return BatchResult(received=len(lines), parsed=len(events), alerts=created)

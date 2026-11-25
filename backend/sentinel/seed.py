"""Load demo data: two users and the sample logs, shifted so they end "now".

Run:  python -m sentinel.seed            (safe to run twice: it skips if events exist)
      python -m sentinel.seed --force    (adds the sample again)
"""
from __future__ import annotations

import argparse
import logging
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from .config import BASE_DIR, get_settings
from .core import parse_line
from .db import Alert, Event, SessionLocal, User, init_db
from .pipeline import process_events, reset_engine
from .security import hash_password

log = logging.getLogger("sentinel.seed")
SAMPLES = BASE_DIR / "samples"
DEMO_ANALYST = ("analyst@sentinel.local", "analyst-demo-pass")


def load_sample_events(end: datetime) -> list:
    sample_now = datetime(2026, 11, 26, tzinfo=UTC)  # the samples are dated 25 Nov 2026
    events = []
    for source, name in (("auth", "auth.log"), ("nginx", "access.log")):
        for line in (SAMPLES / name).read_text(encoding="utf-8").splitlines():
            if ev := parse_line(source, line, host="web-01", now=sample_now):
                events.append(ev)
    events.sort(key=lambda e: e.ts)
    shift = end - events[-1].ts
    for ev in events:
        ev.ts += shift
        ev.raw = restamp(ev.raw, ev.source, ev.ts)
    return events


_SYSLOG_TS = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}")
_NGINX_TS = re.compile(r"\[[^\]]+\]")


def restamp(raw: str, source: str, ts: datetime) -> str:
    """Rewrite the timestamp inside a raw line so evidence matches the shifted event time."""
    if source == "auth":
        return _SYSLOG_TS.sub(f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}", raw, count=1)
    return _NGINX_TS.sub(f"[{ts:%d/%b/%Y:%H:%M:%S} +0000]", raw, count=1)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    init_db()
    s = get_settings()
    with SessionLocal() as db:
        for email, password, role in ((s.admin_email, s.admin_password, "admin"), (*DEMO_ANALYST, "analyst")):
            if not db.scalar(select(User).where(User.email == email)):
                db.add(User(email=email, password_hash=hash_password(password), role=role))
        db.commit()

        if db.scalar(select(func.count()).select_from(Event)) and not args.force:
            log.info("events already present, nothing to do (use --force to add the sample again)")
            return
        reset_engine()
        events = load_sample_events(datetime.now(UTC) - timedelta(minutes=3))
        created = process_events(db, events, send_notifications=False)

        # Give the demo some triage history so the dashboard shows every state.
        analyst = db.scalar(select(User).where(User.email == DEMO_ANALYST[0]))
        for rule_id, new_status, note in (
            ("http-5xx-spike", "resolved", "Upstream API restarted, errors stopped."),
            ("ssh-invalid-user-probe", "acknowledged", "Known scanner range, watching."),
        ):
            alert = db.scalar(select(Alert).where(Alert.rule_id == rule_id))
            if alert and analyst:
                alert.history = [*alert.history, {"at": datetime.now(UTC).isoformat(), "by": analyst.email,
                                                  "from": alert.status, "to": new_status, "note": note}]
                alert.status, alert.assignee_id = new_status, analyst.id
        db.commit()
        log.info("loaded %d events and %d alerts", len(events), created)


if __name__ == "__main__":
    main()

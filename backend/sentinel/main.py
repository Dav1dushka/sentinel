"""Sentinel HTTP API.

Run locally:  uvicorn sentinel.main:app --reload
Docs:         http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import logging
from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from . import __version__
from .config import get_settings
from .db import Alert, Event, SessionLocal, User, get_db, init_db, utcnow
from .deps import current_user, ingest_auth, login_limiter, require_admin
from .pipeline import get_engine, process_batch
from .queue import RedisQueue
from .schemas import (
    AlertOut,
    AlertPatch,
    Counted,
    EventOut,
    IngestIn,
    IngestOut,
    Overview,
    Page,
    TimelinePoint,
    TokenOut,
    UserCreate,
    UserOut,
)
from .security import create_access_token, hash_password, verify_password

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel.api")
_queue: RedisQueue | None = None


def get_queue() -> RedisQueue | None:
    global _queue
    url = get_settings().redis_url
    if url and _queue is None:
        _queue = RedisQueue(url)
    return _queue


def ensure_admin() -> None:
    s = get_settings()
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(User)) == 0:
            db.add(User(email=s.admin_email, password_hash=hash_password(s.admin_password), role="admin"))
            db.commit()
            log.info("created first admin user %s", s.admin_email)


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_settings().warn_if_insecure()
    init_db()
    ensure_admin()
    yield


app = FastAPI(title="Sentinel API", version=__version__, lifespan=lifespan,
              description="Collects auth and web logs, runs detection rules and manages alerts.")
app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])


# --- health & auth -----------------------------------------------------------------

@app.get("/api/health", tags=["meta"])
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    q = get_queue()
    return {"status": "ok", "version": __version__, "queue": "redis" if q else "inline",
            "queued": q.size() if q else 0, "rules": len(get_engine().rules)}


@app.post("/api/auth/login", response_model=TokenOut, tags=["auth"])
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    client = request.client.host if request.client else "unknown"
    if login_limiter.blocked(client):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed logins, try again later")
    user = db.scalar(select(User).where(User.email == form.username.strip().lower()))
    if not user or not user.is_active or not verify_password(form.password, user.password_hash):
        login_limiter.fail(client)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong email or password")
    login_limiter.reset(client)
    s = get_settings()
    token = create_access_token(user.id, user.role, s.jwt_secret, s.jwt_ttl_minutes)
    return TokenOut(access_token=token, expires_in=s.jwt_ttl_minutes * 60, user=UserOut.model_validate(user))


@app.get("/api/auth/me", response_model=UserOut, tags=["auth"])
def me(user: User = Depends(current_user)):
    return user


@app.get("/api/users", response_model=list[UserOut], tags=["users"])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.id)).all()


@app.post("/api/users", response_model=UserOut, status_code=201, tags=["users"])
def create_user(body: UserCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(email=body.email, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.commit()
    return user


# --- ingest --------------------------------------------------------------------------

@app.post("/api/ingest", response_model=IngestOut, status_code=202, tags=["ingest"],
          dependencies=[Depends(ingest_auth)])
def ingest(body: IngestIn, db: Session = Depends(get_db)):
    lines = [ln[:8192] for ln in body.lines]
    q = get_queue()
    if q:
        q.push({"source": body.source, "host": body.host, "lines": lines})
        return IngestOut(accepted=len(lines), queued=True)
    result = process_batch(db, body.source, lines, host=body.host)
    return IngestOut(accepted=result.received, queued=False, parsed=result.parsed, alerts=result.alerts)


# --- events ----------------------------------------------------------------------------

@app.get("/api/events", response_model=Page[EventOut], tags=["events"])
def list_events(
    _: User = Depends(current_user), db: Session = Depends(get_db),
    source: str | None = None, kind: str | None = None, ip: str | None = None,
    q: str | None = Query(default=None, max_length=200, description="Search in the raw line"),
    before_id: int | None = Query(default=None, description="Cursor: return events older than this id"),
    limit: int = Query(default=50, ge=1, le=200),
):
    stmt = select(Event).order_by(Event.id.desc()).limit(limit + 1)
    if source:
        stmt = stmt.where(Event.source == source)
    if kind:
        stmt = stmt.where(Event.kind == kind)
    if ip:
        stmt = stmt.where(Event.ip == ip)
    if q:
        stmt = stmt.where(Event.raw.ilike(f"%{q}%"))
    if before_id:
        stmt = stmt.where(Event.id < before_id)
    rows = db.scalars(stmt).all()
    more = len(rows) > limit
    rows = rows[:limit]
    return Page[EventOut](items=[EventOut.model_validate(r) for r in rows],
                          next_cursor=rows[-1].id if more and rows else None)


# --- alerts ----------------------------------------------------------------------------

@app.get("/api/alerts", response_model=Page[AlertOut], tags=["alerts"])
def list_alerts(
    _: User = Depends(current_user), db: Session = Depends(get_db),
    status_: str | None = Query(default=None, alias="status"), severity: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
):
    stmt = select(Alert).order_by(Alert.last_seen.desc()).limit(limit)
    if status_:
        stmt = stmt.where(Alert.status == status_)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Alert.title.ilike(like), Alert.key.ilike(like), Alert.rule_id.ilike(like)))
    return Page[AlertOut](items=[AlertOut.model_validate(a) for a in db.scalars(stmt).all()])


@app.get("/api/alerts/{alert_id}", response_model=AlertOut, tags=["alerts"])
def get_alert(alert_id: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@app.patch("/api/alerts/{alert_id}", response_model=AlertOut, tags=["alerts"])
def update_alert(alert_id: int, body: AlertPatch, user: User = Depends(current_user), db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    entry = {"at": utcnow().isoformat(), "by": user.email}
    if body.status and body.status != alert.status:
        entry.update({"from": alert.status, "to": body.status})
        alert.status = body.status
    if body.assign_to_me:
        alert.assignee_id = user.id
        entry["assigned"] = user.email
    if body.note:
        entry["note"] = body.note.strip()
    if len(entry) > 2:
        alert.history = [*alert.history, entry]  # new list so SQLAlchemy sees the change
    db.commit()
    return alert


# --- stats & rules -----------------------------------------------------------------------

@app.get("/api/stats/overview", response_model=Overview, tags=["stats"])
def overview(hours: int = Query(default=24, ge=1, le=168), _: User = Depends(current_user),
             db: Session = Depends(get_db)):
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    by_source = dict(db.execute(select(Event.source, func.count()).where(Event.ts >= since)
                                .group_by(Event.source)).all())
    open_alerts = dict(db.execute(select(Alert.severity, func.count()).where(Alert.status == "open")
                                  .group_by(Alert.severity)).all())

    start = since.replace(minute=0, second=0, microsecond=0)
    buckets = {start + timedelta(hours=i): Counter() for i in range(hours + 1)}

    def bucket(ts: datetime) -> datetime:
        ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
        return ts.replace(minute=0, second=0, microsecond=0)

    for ts, src in db.execute(select(Event.ts, Event.source).where(Event.ts >= since).limit(500_000)):
        if (b := bucket(ts)) in buckets:
            buckets[b][src] += 1
    alerts_in_window = 0
    for (ts,) in db.execute(select(Alert.first_seen).where(Alert.first_seen >= since)):
        alerts_in_window += 1
        if (b := bucket(ts)) in buckets:
            buckets[b]["alerts"] += 1

    suspicious = or_(Event.kind.in_(["ssh_failed", "ssh_invalid_user"]), Event.status >= 400)
    offenders = db.execute(select(Event.ip, func.count().label("n")).where(Event.ts >= since, suspicious,
                           Event.ip.is_not(None)).group_by(Event.ip).order_by(text("n DESC")).limit(6)).all()
    rules = db.execute(select(Alert.rule_id, func.count().label("n")).where(Alert.first_seen >= since)
                       .group_by(Alert.rule_id).order_by(text("n DESC")).limit(6)).all()
    return Overview(
        since=since, events=sum(by_source.values()), events_by_source=by_source, open_alerts=open_alerts,
        alerts_in_window=alerts_in_window,
        timeline=[TimelinePoint(t=t, auth=c["auth"], nginx=c["nginx"], alerts=c["alerts"]) for t, c in buckets.items()],
        top_offenders=[Counted(key=ip, count=n) for ip, n in offenders],
        top_rules=[Counted(key=r, count=n) for r, n in rules],
    )


@app.get("/api/rules", tags=["rules"])
def list_rules(_: User = Depends(current_user)):
    return [r.summary() for r in get_engine().rules]

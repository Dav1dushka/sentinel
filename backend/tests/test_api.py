"""End-to-end API tests: ingest → detection → alerts → triage.

Needs the full requirements (FastAPI, SQLAlchemy). Skipped automatically when
they are not installed so the pure core tests can still run anywhere.
"""
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from sentinel.db import Base, engine  # noqa: E402
from sentinel.deps import login_limiter  # noqa: E402
from sentinel.main import app  # noqa: E402
from sentinel.pipeline import reset_engine  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
INGEST = {"X-Ingest-Token": "test-ingest-token-0123456789"}


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    reset_engine()
    login_limiter.fails.clear()
    with TestClient(app) as c:  # lifespan creates tables and the first admin
        yield c


def login(c, email="admin@test.local", password="admin-password-123"):
    r = c.post("/api/auth/login", data={"username": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["queue"] == "inline" and r.json()["rules"] >= 8


def test_login_errors_and_rate_limit(client):
    assert client.post("/api/auth/login", data={"username": "admin@test.local", "password": "nope"}).status_code == 401
    for _ in range(10):
        r = client.post("/api/auth/login", data={"username": "x@test.local", "password": "nope"})
    assert r.status_code == 429


def test_protected_routes_need_a_token(client):
    for path in ("/api/events", "/api/alerts", "/api/stats/overview", "/api/rules", "/api/auth/me"):
        assert client.get(path).status_code == 401
    assert client.get("/api/alerts", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_ingest_requires_token_and_validates(client):
    body = {"source": "auth", "lines": ["x"]}
    assert client.post("/api/ingest", json=body).status_code == 401
    assert client.post("/api/ingest", json={"source": "windows", "lines": ["x"]}, headers=INGEST).status_code == 422
    assert client.post("/api/ingest", json={"source": "auth", "lines": []}, headers=INGEST).status_code == 422


def test_bruteforce_flow_end_to_end(client):
    lines = [f"Nov 25 09:20:{i:02d} web-01 sshd[1]: Failed password for root from 203.0.113.45 port {i} ssh2"
             for i in range(0, 30, 3)]
    r = client.post("/api/ingest", json={"source": "auth", "host": "web-01", "lines": lines}, headers=INGEST)
    assert r.status_code == 202 and r.json() == {"accepted": 10, "queued": False, "parsed": 10, "alerts": 1}

    h = login(client)
    alerts = client.get("/api/alerts", headers=h).json()["items"]
    assert len(alerts) == 1
    a = alerts[0]
    assert (a["rule_id"], a["key"], a["severity"], a["status"]) == ("ssh-bruteforce", "203.0.113.45", "high", "open")
    assert a["evidence"] and "203.0.113.45" in a["evidence"][0]

    patch = {"status": "acknowledged", "note": "blocking", "assign_to_me": True}
    r = client.patch(f"/api/alerts/{a['id']}", json=patch, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "acknowledged" and body["assignee_id"] is not None
    assert body["history"][-1]["to"] == "acknowledged" and body["history"][-1]["note"] == "blocking"

    assert client.get("/api/alerts?status=open", headers=h).json()["items"] == []
    events = client.get("/api/events?ip=203.0.113.45&limit=4", headers=h).json()
    assert len(events["items"]) == 4 and events["next_cursor"]
    older = client.get(f"/api/events?ip=203.0.113.45&before_id={events['next_cursor']}", headers=h).json()
    assert len(older["items"]) == 6


def test_sample_logs_and_overview(client):
    for source, name in (("auth", "auth.log"), ("nginx", "access.log")):
        lines = (SAMPLES / name).read_text().splitlines()
        r = client.post("/api/ingest", json={"source": source, "host": "web-01", "lines": lines}, headers=INGEST)
        assert r.status_code == 202
    h = login(client)
    rules = {a["rule_id"] for a in client.get("/api/alerts", headers=h).json()["items"]}
    assert {"ssh-bruteforce", "ssh-password-spray", "ssh-success-after-failures", "http-scanner"} <= rules
    ov = client.get("/api/stats/overview?hours=168", headers=h)
    assert ov.status_code == 200  # sample is dated Nov 2026; counts depend on today's date
    assert len(client.get("/api/rules", headers=h).json()) >= 8


def test_user_admin_only(client):
    h = login(client)
    r = client.post("/api/users", json={"email": "Ana@Test.local", "password": "analyst-pass-1"}, headers=h)
    assert r.status_code == 201 and r.json()["email"] == "ana@test.local" and r.json()["role"] == "analyst"
    assert client.post("/api/users", json={"email": "ana@test.local", "password": "analyst-pass-1"},
                       headers=h).status_code == 409
    ha = login(client, "ana@test.local", "analyst-pass-1")
    assert client.get("/api/users", headers=ha).status_code == 403
    assert client.get("/api/auth/me", headers=ha).json()["role"] == "analyst"

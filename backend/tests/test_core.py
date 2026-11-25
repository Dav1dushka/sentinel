"""Tests for the pure detection core: parsers, rule loading and the engine."""
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.core import Engine, RuleError, load_rules, parse_line
from sentinel.core.parsers import parse_auth, parse_nginx
from sentinel.core.rules import parse_rule

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 26, tzinfo=UTC)
T0 = datetime(2026, 11, 25, 9, 0, tzinfo=UTC)


# --- parsers -------------------------------------------------------------------

@pytest.mark.parametrize("line, kind, user, ip", [
    ("Nov 25 09:20:00 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 50000 ssh2",
     "ssh_failed", "root", "203.0.113.45"),
    ("Nov 25 09:20:00 web-01 sshd[1]: Failed password for invalid user oracle from 203.0.113.77 port 5 ssh2",
     "ssh_failed", "oracle", "203.0.113.77"),
    ("Nov 25 09:20:00 web-01 sshd[1]: Invalid user admin from 203.0.113.77 port 51000",
     "ssh_invalid_user", "admin", "203.0.113.77"),
    ("Nov  5 09:20:00 web-01 sshd[1]: Accepted publickey for davyd from 192.0.2.10 port 4 ssh2: ED25519 SHA256:x",
     "ssh_success", "davyd", "192.0.2.10"),
    ("2026-11-25T09:20:00+00:00 web-01 sshd[9]: Accepted password for deploy from 2001:db8::7 port 22 ssh2",
     "ssh_success", "deploy", "2001:db8::7"),
])
def test_parse_auth_ssh(line, kind, user, ip):
    ev = parse_auth(line, now=NOW)
    assert ev and (ev.kind, ev.user, ev.ip, ev.host) == (kind, user, ip, "web-01")
    assert ev.ts.tzinfo is not None and ev.raw == line


def test_parse_auth_sudo_keeps_command():
    line = "Nov 25 10:06:30 web-01 sudo:  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    ev = parse_auth(line, now=NOW)
    assert ev and ev.kind == "sudo" and ev.user == "deploy" and ev.command == "/bin/bash"


def test_syslog_year_rolls_back_in_january():
    ev = parse_auth("Dec 31 23:59:00 h sshd[1]: Invalid user x from 192.0.2.1 port 1",
                    now=datetime(2027, 1, 1, 0, 5, tzinfo=UTC))
    assert ev and ev.ts.year == 2026


@pytest.mark.parametrize("line", [
    "", "garbage", "Nov 25 09:20:00 web-01 cron[1]: (root) CMD (run-parts /etc/cron.hourly)",
    "Nov 25 09:20:00 web-01 sshd[1]: Connection closed by 192.0.2.1 port 22",
    "Foo 25 09:20:00 web-01 sshd[1]: Invalid user x from 192.0.2.1 port 1",
])
def test_parse_auth_ignores_uninteresting_lines(line):
    assert parse_auth(line, now=NOW) is None


def test_parse_nginx():
    ev = parse_nginx('203.0.113.9 - - [25/Nov/2026:10:20:00 +0100] "GET /.env HTTP/1.1" 404 162 "-" "Nikto/2.5.0"')
    assert ev and (ev.ip, ev.method, ev.path, ev.status) == ("203.0.113.9", "GET", "/.env", 404)
    assert ev.ts == datetime(2026, 11, 25, 9, 20, tzinfo=UTC)  # converted to UTC


def test_parse_line_unknown_source_and_host_override():
    assert parse_line("windows", "anything") is None
    ev = parse_line("auth", "Nov 25 09:20:00 old sshd[1]: Invalid user a from 192.0.2.1 port 1", host="db-01", now=NOW)
    assert ev and ev.host == "db-01"


# --- rules ---------------------------------------------------------------------

def test_default_rules_load():
    rules = load_rules(ROOT / "rules" / "default.yml")
    assert len(rules) >= 8 and all(r.severity in ("low", "medium", "high", "critical") for r in rules)


@pytest.mark.parametrize("spec, message", [
    ({"title": "x", "match": {"kind": "a"}}, "needs an 'id'"),
    ({"id": "r", "severity": "huge", "match": {"kind": "a"}}, "severity"),
    ({"id": "r", "match": {}}, "non-empty"),
    ({"id": "r", "match": {"path": {"regex": "("}}}, "bad regex"),
    ({"id": "r", "match": {"status": {"between": 1}}}, "unknown operator"),
    ({"id": "r", "type": "sequence", "match": {"kind": "a"}, "then": {"kind": "b"}}, "group_by"),
    ({"id": "r", "match": {"kind": "a"}, "threshold": 0}, "positive"),
])
def test_invalid_rules_are_rejected(spec, message):
    with pytest.raises(RuleError, match=message):
        parse_rule(spec)


def test_condition_operators():
    rule = parse_rule({"id": "r", "match": {"status": {"gte": 400, "lt": 500}, "path": {"regex": r"\.env$"},
                                           "method": {"in": ["GET", "HEAD"]}, "source": {"not": "auth"}}})
    assert rule.matches({"status": 404, "path": "/.env", "method": "GET", "source": "nginx"})
    assert not rule.matches({"status": 500, "path": "/.env", "method": "GET", "source": "nginx"})
    assert not rule.matches({"status": None, "path": "/.env", "method": "GET", "source": "nginx"})


# --- engine --------------------------------------------------------------------

def failed(ip: str, user: str, seconds: float):
    ts = T0 + timedelta(seconds=seconds)
    line = f"{ts:%b} {ts.day} {ts:%H:%M:%S} h sshd[1]: Failed password for {user} from {ip} port 1 ssh2"
    return parse_auth(line, now=NOW)


def brute_rule(**kw):
    return parse_rule({"id": "bf", "match": {"kind": "ssh_failed"}, "group_by": "ip",
                       "threshold": 3, "window": 60, **kw})


def test_threshold_fires_once_per_window():
    eng = Engine([brute_rule()])
    alerts = eng.process_many(failed("192.0.2.1", "root", s) for s in range(0, 20, 2))
    assert len(alerts) == 1 and alerts[0].count == 3 and alerts[0].key == "192.0.2.1"
    later = eng.process_many(failed("192.0.2.1", "root", s) for s in (100, 101, 102))
    assert len(later) == 1  # cooldown is over, a new burst is a new alert


def test_events_outside_window_do_not_count():
    eng = Engine([brute_rule()])
    assert eng.process_many(failed("192.0.2.1", "root", s) for s in (0, 70, 140)) == []


def test_keys_are_independent():
    eng = Engine([brute_rule()])
    evs = [failed(ip, "root", s) for s in (0, 1) for ip in ("192.0.2.1", "192.0.2.2")]
    assert eng.process_many(evs) == []


def test_distinct_counts_unique_values():
    eng = Engine([brute_rule(distinct="user")])
    assert eng.process_many(failed("192.0.2.1", "root", s) for s in range(10)) == []
    alerts = eng.process_many(failed("192.0.2.1", u, 20 + i) for i, u in enumerate(["a", "b"]))
    assert len(alerts) == 1 and alerts[0].count == 3


def test_sequence_rule():
    rule = parse_rule({"id": "seq", "type": "sequence", "match": {"kind": "ssh_failed"},
                       "then": {"kind": "ssh_success"}, "group_by": "ip", "threshold": 2, "window": 300})
    eng = Engine([rule])
    ok = parse_auth("Nov 25 09:01:00 h sshd[1]: Accepted password for root from 192.0.2.1 port 1 ssh2", now=NOW)
    assert eng.process(ok) == []                              # success alone is fine
    eng.process_many([failed("192.0.2.1", "root", 61), failed("192.0.2.1", "root", 62)])
    ok2 = parse_auth("Nov 25 09:01:10 h sshd[1]: Accepted password for root from 192.0.2.1 port 1 ssh2", now=NOW)
    alerts = eng.process(ok2)
    assert len(alerts) == 1 and alerts[0].evidence[-1] == ok2.raw


def test_disabled_rules_are_skipped_and_gc_forgets_quiet_keys():
    eng = Engine([brute_rule(enabled=False)])
    assert eng.rules == []
    eng = Engine([brute_rule()])
    eng.process(failed("192.0.2.1", "root", 0))
    assert eng.gc(T0 + timedelta(hours=1)) == 1


def test_demo_logs_produce_exactly_one_alert_per_scenario():
    evs = []
    for src, name in (("auth", "auth.log"), ("nginx", "access.log")):
        for line in (ROOT / "samples" / name).read_text().splitlines():
            if ev := parse_line(src, line, host="web-01", now=NOW):
                evs.append(ev)
    evs.sort(key=lambda e: e.ts)
    alerts = Engine(load_rules(ROOT / "rules" / "default.yml")).process_many(evs)
    got = sorted((a.rule_id, a.key) for a in alerts)
    assert got == sorted([
        ("ssh-bruteforce", "203.0.113.45"), ("ssh-password-spray", "203.0.113.77"),
        ("ssh-invalid-user-probe", "203.0.113.77"), ("ssh-success-after-failures", "198.51.100.23"),
        ("sudo-sensitive-command", "deploy"), ("http-scanner", "203.0.113.9"),
        ("http-sensitive-path", "203.0.113.9"), ("http-5xx-spike", "web-01"),
    ])

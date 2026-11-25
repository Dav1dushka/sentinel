"""Generate the synthetic demo logs in this folder.

Run:  python samples/generate.py

The output is deterministic (fixed seed) so tests can rely on it. All IP
addresses come from the documentation ranges in RFC 5737 (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24): they never belong to real hosts.

Scenarios hidden in the noise:
  * 203.0.113.45  – SSH brute force on root
  * 203.0.113.77  – password spraying with invalid usernames
  * 198.51.100.23 – four failures, then a successful login as deploy
  * deploy        – runs a root shell through sudo
  * 203.0.113.9   – web scanner hitting /.env, /.git/config, wp-login.php
  * web-01        – a burst of 502 errors
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
START = datetime(2026, 11, 24, 14, 0, 0, tzinfo=timezone.utc)
SPAN = 20 * 60  # minutes of log history
rng = random.Random(1337)
auth: list[tuple[datetime, str]] = []
web: list[tuple[datetime, str]] = []
pid = 4000


def sys_line(ts: datetime, prog: str, msg: str, host: str = "web-01") -> None:
    global pid
    pid += 1
    stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
    tag = f"{prog}[{pid}]" if prog == "sshd" else prog
    auth.append((ts, f"{stamp} {host} {tag}: {msg}"))


def nginx(ts: datetime, ip: str, method: str, path: str, status: int, ua: str = "Mozilla/5.0") -> None:
    size = rng.randint(180, 9000) if status < 400 else rng.randint(150, 600)
    web.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'))


def at(minutes: float) -> datetime:
    return START + timedelta(seconds=round(minutes * 60))


# --- background noise -------------------------------------------------------
def busy_minute() -> float:
    """Random minute weighted towards daytime traffic (UTC 08-20)."""
    while True:
        m = rng.uniform(0, SPAN)
        hour = (START + timedelta(minutes=m)).hour
        if rng.random() < (1.0 if 8 <= hour < 20 else 0.35):
            return m


for i in range(30):
    t = at(busy_minute())
    user, ip = rng.choice([("davyd", "192.0.2.10"), ("deploy", "192.0.2.11"), ("ci", "192.0.2.12")])
    sys_line(t, "sshd", f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 60000)} ssh2: ED25519 SHA256:x{i}")
for i in range(10):  # the odd typo: a single failure is not an incident
    t = at(busy_minute())
    sys_line(t, "sshd", f"Failed password for davyd from 192.0.2.10 port {rng.randint(40000, 60000)} ssh2")
for i in range(9):
    t = at(busy_minute())
    sys_line(t, "sudo", "  davyd : TTY=pts/0 ; PWD=/home/davyd ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")

pages = ["/", "/about", "/projects", "/api/health", "/static/app.js", "/static/style.css", "/favicon.ico", "/blog/post-1"]
for i in range(1500):
    t = at(busy_minute())
    ip = f"198.51.100.{rng.randint(30, 200)}"
    path = rng.choice(pages)
    status = 200 if rng.random() > .03 else rng.choice([301, 304, 404])
    nginx(t, ip, "GET", path, status)

# --- scenarios ------------------------------------------------------------------
for i in range(12):                                     # brute force
    sys_line(at(230) + timedelta(seconds=i * 3), "sshd",
             f"Failed password for root from 203.0.113.45 port {50000 + i} ssh2")

for i, user in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "git"]):  # spraying
    t = at(505) + timedelta(seconds=i * 35)
    sys_line(t, "sshd", f"Invalid user {user} from 203.0.113.77 port {51000 + i}")
    sys_line(t + timedelta(seconds=2), "sshd",
             f"Failed password for invalid user {user} from 203.0.113.77 port {51000 + i} ssh2")

for i in range(4):                                      # success after failures
    sys_line(at(842) + timedelta(seconds=i * 20), "sshd",
             f"Failed password for deploy from 198.51.100.23 port {52000 + i} ssh2")
sys_line(at(844), "sshd", "Accepted password for deploy from 198.51.100.23 port 52010 ssh2")
sys_line(at(845.5), "sudo", " deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")

scan = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql", "/admin", "/config.php",
        "/server-status", "/.aws/credentials", "/api/v1/users", "/old", "/test.php"]
for i in range(36):                                     # web scanner
    path = scan[i % len(scan)] if i < 12 else f"/{rng.choice(['wp', 'cms', 'admin', 'dev', 'api'])}/{rng.randint(1, 999)}"
    nginx(at(1010) + timedelta(seconds=i), "203.0.113.9", "GET", path, 404, ua="Nikto/2.5.0")

for i in range(12):                                     # 5xx burst
    nginx(at(1150) + timedelta(seconds=i * 4), f"198.51.100.{rng.randint(30, 200)}", "GET", "/api/orders", 502)

for name, rows in (("auth.log", auth), ("access.log", web)):
    rows.sort(key=lambda r: r[0])
    (HERE / name).write_text("\n".join(line for _, line in rows) + "\n", encoding="utf-8")
    print(f"wrote {name}: {len(rows)} lines")

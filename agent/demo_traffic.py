#!/usr/bin/env python3
"""Write a live stream of fake auth and nginx lines for the demo setup.

Mostly harmless traffic, with an attack every minute or so, so the dashboard
keeps moving. IPs come from the RFC 5737 documentation ranges.

    python demo_traffic.py --dir /var/log/demo
"""
from __future__ import annotations

import argparse
import random
import time
from datetime import UTC, datetime
from pathlib import Path

rng = random.Random()
PAGES = ["/", "/about", "/projects", "/api/health", "/static/app.js", "/blog/post-1"]
SCAN = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql", "/admin", "/config.php"]


def syslog(prog: str, msg: str) -> str:
    now = datetime.now(UTC)
    tag = f"sshd[{rng.randint(1000, 60000)}]" if prog == "sshd" else prog
    return f"{now:%b} {now.day:>2} {now:%H:%M:%S} web-01 {tag}: {msg}"


def access(ip: str, path: str, status: int, ua: str = "Mozilla/5.0") -> str:
    now = datetime.now(UTC)
    size = rng.randint(150, 9000)
    return f'{ip} - - [{now:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def attack(auth, web) -> None:
    kind = rng.choice(["brute", "spray", "scan", "sudo"])
    ip = f"203.0.113.{rng.randint(2, 250)}"
    if kind == "brute":
        for i in range(rng.randint(6, 12)):
            auth.write(syslog("sshd", f"Failed password for root from {ip} port {50000 + i} ssh2") + "\n")
    elif kind == "spray":
        for user in rng.sample(["admin", "test", "oracle", "ubuntu", "postgres", "git", "ftp"], 5):
            auth.write(syslog("sshd", f"Invalid user {user} from {ip} port 51000") + "\n")
    elif kind == "scan":
        for i in range(25):
            path = SCAN[i % len(SCAN)] if i < 7 else f"/x/{rng.randint(1, 999)}"
            web.write(access(ip, path, 404, "Nikto/2.5.0") + "\n")
    else:
        auth.write(syslog("sudo", " deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash") + "\n")
    print(f"demo attack: {kind} from {ip}", flush=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dir", default="demo-logs")
    p.add_argument("--attack-every", type=float, default=60.0)
    args = p.parse_args()
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    next_attack = time.monotonic() + 15
    with open(out / "auth.log", "a", buffering=1) as auth, open(out / "access.log", "a", buffering=1) as web:
        while True:
            for _ in range(rng.randint(2, 8)):
                web.write(access(f"198.51.100.{rng.randint(30, 200)}", rng.choice(PAGES), 200) + "\n")
            if rng.random() < .05:
                auth.write(syslog("sshd", "Accepted publickey for davyd from 192.0.2.10 port 45000 ssh2") + "\n")
            if time.monotonic() >= next_attack:
                attack(auth, web)
                next_attack = time.monotonic() + args.attack_every * rng.uniform(.6, 1.4)
            time.sleep(1)


if __name__ == "__main__":
    main()

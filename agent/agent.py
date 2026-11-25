#!/usr/bin/env python3
"""Sentinel log shipper: follows log files and sends new lines to the API.

Standard library only, so it can be copied to any server with Python 3.9+.

    python agent.py --url http://localhost:8000 --token $SENTINEL_INGEST_TOKEN \\
        --file auth:/var/log/auth.log --file nginx:/var/log/nginx/access.log

It survives log rotation (reopens the file when its inode changes or it
shrinks), batches lines, and retries with backoff when the API is down.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

BATCH_LINES = 500
FLUSH_SECONDS = 2.0


@dataclass
class Follower:
    source: str
    path: str
    from_start: bool = False
    fh: object | None = None
    inode: int | None = None
    pending: list[str] = field(default_factory=list)
    partial: str = ""

    def open(self) -> None:
        try:
            self.fh = open(self.path, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            self.fh = None
            return
        st = os.fstat(self.fh.fileno())
        if not self.from_start and self.inode is None:
            self.fh.seek(0, os.SEEK_END)  # first start: only new lines
        self.inode = st.st_ino
        self.from_start = True  # after a rotation, read the new file from the top

    def rotated(self) -> bool:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return False
        return self.fh is None or st.st_ino != self.inode or st.st_size < self.fh.tell()

    def read(self) -> None:
        if self.rotated():
            if self.fh:
                self.pending.extend(self._drain())  # keep what was written before rotation
                self.fh.close()
            self.open()
        if self.fh:
            self.pending.extend(self._drain())

    def _drain(self) -> list[str]:
        chunk = self.fh.read()
        if not chunk:
            return []
        data = self.partial + chunk
        lines = data.split("\n")
        self.partial = lines.pop()  # last piece may be an unfinished line
        return [ln for ln in lines if ln.strip()]


def send(url: str, token: str, source: str, host: str, lines: list[str]) -> None:
    body = json.dumps({"source": source, "host": host, "lines": lines}).encode()
    req = urllib.request.Request(f"{url.rstrip('/')}/api/ingest", data=body, method="POST",  # noqa: S310
                                 headers={"Content-Type": "application/json", "X-Ingest-Token": token})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - scheme checked in main()
        if resp.status not in (200, 202):
            raise urllib.error.HTTPError(req.full_url, resp.status, "unexpected status", resp.headers, None)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Ship log lines to Sentinel.")
    p.add_argument("--url", default=os.getenv("SENTINEL_URL", "http://localhost:8000"))
    p.add_argument("--token", default=os.getenv("SENTINEL_INGEST_TOKEN"))
    p.add_argument("--host", default=os.getenv("SENTINEL_HOST", socket.gethostname()))
    p.add_argument("--file", action="append", required=True, metavar="SOURCE:PATH",
                   help="auth:/var/log/auth.log or nginx:/var/log/nginx/access.log (repeatable)")
    p.add_argument("--from-start", action="store_true", help="also send lines already in the files")
    args = p.parse_args(argv)
    if not args.token:
        p.error("--token or SENTINEL_INGEST_TOKEN is required")
    if not args.url.startswith(("http://", "https://")):
        p.error("--url must start with http:// or https://")

    followers = []
    for spec in args.file:
        source, _, path = spec.partition(":")
        if source not in ("auth", "nginx") or not path:
            p.error(f"bad --file value: {spec}")
        f = Follower(source, path, from_start=args.from_start)
        f.open()
        followers.append(f)
    print(f"shipping {len(followers)} file(s) to {args.url} as host={args.host}", flush=True)

    backoff, last_flush = 1.0, time.monotonic()
    while True:
        for f in followers:
            f.read()
        due = time.monotonic() - last_flush >= FLUSH_SECONDS
        for f in followers:
            while f.pending and (due or len(f.pending) >= BATCH_LINES):
                batch = f.pending[:BATCH_LINES]
                try:
                    send(args.url, args.token, f.source, args.host, batch)
                except (urllib.error.URLError, OSError) as exc:
                    print(f"send failed ({exc}); retrying in {backoff:.0f}s", file=sys.stderr, flush=True)
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
                    break
                del f.pending[:len(batch)]
                backoff = 1.0
        if due:
            last_flush = time.monotonic()
        time.sleep(0.5)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)

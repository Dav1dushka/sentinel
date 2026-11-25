"""Turn raw log lines into normalised events.

Two sources are supported:

* ``auth``  – OpenSSH / sudo lines from ``/var/log/auth.log`` (classic syslog
  timestamps such as ``Nov 25 10:12:01``) or journald ``short-iso`` output
  (``2026-11-25T10:12:01+00:00``).
* ``nginx`` – the default nginx/Apache ``combined`` access-log format.

Every parser returns an :class:`Event` or ``None`` when the line is not
interesting (or not recognised). Parsers never raise on bad input: a log
pipeline must keep going when it meets a line it does not understand.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass(slots=True)
class Event:
    ts: datetime
    source: str            # "auth" | "nginx"
    kind: str              # ssh_failed, ssh_invalid_user, ssh_success, sudo, http
    host: str = ""
    ip: str | None = None
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    command: str | None = None
    raw: str = field(default="", repr=False)

    def fields(self) -> dict[str, Any]:
        """Flat dict used by the rule matcher."""
        return asdict(self)


# --- auth.log ---------------------------------------------------------------

_SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<prog>[\w\-./]+)(?:\[\d+\])?:\s(?P<msg>.*)$")
_ISO_PREFIX = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s"
    r"(?P<host>\S+)\s(?P<prog>[\w\-./]+)(?:\[\d+\])?:\s(?P<msg>.*)$")

_SSH_FAILED = re.compile(
    r"^Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+)\s:\s.*?COMMAND=(?P<cmd>.+)$")


def _syslog_time(mon: str, day: str, hms: str, now: datetime) -> datetime | None:
    """Syslog lines carry no year: assume the most recent matching date."""
    month = MONTHS.get(mon)
    if not month:
        return None
    h, m, s = (int(x) for x in hms.split(":"))
    try:
        ts = datetime(now.year, month, int(day), h, m, s, tzinfo=UTC)
    except ValueError:
        return None
    if ts > now.replace(microsecond=0) and (ts - now).days > 1:
        ts = ts.replace(year=now.year - 1)  # a December line read in January
    return ts


def parse_auth(line: str, now: datetime | None = None) -> Event | None:
    line = line.rstrip("\n")
    now = now or datetime.now(UTC)
    if m := _SYSLOG_PREFIX.match(line):
        ts = _syslog_time(m["mon"], m["day"], m["time"], now)
    elif m := _ISO_PREFIX.match(line):
        try:
            ts = datetime.fromisoformat(m["iso"].replace("Z", "+00:00"))
        except ValueError:
            return None
        ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
        ts = ts.astimezone(UTC)
    else:
        return None
    if ts is None:
        return None

    prog, msg, host = m["prog"], m["msg"], m["host"]
    base = dict(ts=ts, source="auth", host=host, raw=line)

    if prog == "sshd":
        if f := _SSH_FAILED.match(msg):
            return Event(kind="ssh_failed", user=f["user"], ip=f["ip"], **base)
        if f := _SSH_INVALID.match(msg):
            return Event(kind="ssh_invalid_user", user=f["user"] or None, ip=f["ip"], **base)
        if f := _SSH_ACCEPTED.match(msg):
            return Event(kind="ssh_success", user=f["user"], ip=f["ip"], **base)
        return None
    if prog == "sudo" and (f := _SUDO.match(msg)):
        return Event(kind="sudo", user=f["user"], command=f["cmd"].strip(), **base)
    return None


# --- nginx combined -----------------------------------------------------------

_NGINX = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) \S+')


def parse_nginx(line: str, host: str = "web") -> Event | None:
    line = line.rstrip("\n")
    m = _NGINX.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    except ValueError:
        return None
    return Event(ts=ts, source="nginx", kind="http", host=host, ip=m["ip"], method=m["method"],
                 path=m["path"], status=int(m["status"]), raw=line)


PARSERS = {"auth": parse_auth, "nginx": parse_nginx}


def parse_line(source: str, line: str, *, host: str | None = None, now: datetime | None = None) -> Event | None:
    """Dispatch to the right parser. Unknown sources return ``None``."""
    if source == "auth":
        ev = parse_auth(line, now=now)
    elif source == "nginx":
        ev = parse_nginx(line, host=host or "web")
    else:
        return None
    if ev and host:
        ev.host = host
    return ev

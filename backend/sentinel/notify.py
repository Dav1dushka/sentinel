"""Optional Telegram notifications for new alerts.

Uses only the standard library. Failures are logged and swallowed: a broken
notification channel must never stop detection.
"""
from __future__ import annotations

import json
import logging
import urllib.request
from typing import Protocol

from .config import get_settings
from .core.rules import SEVERITIES

log = logging.getLogger("sentinel.notify")
ICON = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


class AlertLike(Protocol):
    id: int
    title: str
    severity: str
    key: str
    count: int
    group_by: str | None
    evidence: list


def format_alert(a: AlertLike) -> str:
    who = f"{a.group_by}={a.key}" if a.group_by else a.key
    last = a.evidence[-1] if a.evidence else ""
    return (f"{ICON.get(a.severity, '')} <b>{a.title}</b> [{a.severity}]\n"
            f"{who} · {a.count} events · alert #{a.id}\n"
            f"<code>{_escape(last[:300])}</code>")


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def should_notify(severity: str) -> bool:
    s = get_settings()
    if not (s.telegram_token and s.telegram_chat_id):
        return False
    floor = s.notify_min_severity if s.notify_min_severity in SEVERITIES else "high"
    return SEVERITIES.index(severity) >= SEVERITIES.index(floor)


def send_alert(a: AlertLike) -> bool:
    if not should_notify(a.severity):
        return False
    s = get_settings()
    body = json.dumps({"chat_id": s.telegram_chat_id, "text": format_alert(a), "parse_mode": "HTML",
                       "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{s.telegram_token}/sendMessage", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - fixed https URL
            return resp.status == 200
    except OSError as exc:  # URLError, timeouts, HTTP errors
        log.warning("telegram notification failed: %s", exc)
        return False

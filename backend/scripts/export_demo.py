"""Export the sample logs, run through the real detection engine, as JSON for
the dashboard's static demo mode (used for the GitHub Pages preview).

Run from backend/:  python scripts/export_demo.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.core import Engine, load_rules, parse_line  # noqa: E402

OUT = ROOT.parent / "frontend" / "src" / "demo" / "demo-data.json"
NOW = datetime(2026, 11, 26, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> None:
    events = []
    for source, name in (("auth", "auth.log"), ("nginx", "access.log")):
        for line in (ROOT / "samples" / name).read_text(encoding="utf-8").splitlines():
            if ev := parse_line(source, line, host="web-01", now=NOW):
                events.append(ev)
    events.sort(key=lambda e: e.ts)
    rules = load_rules(ROOT / "rules" / "default.yml")
    drafts = Engine(rules).process_many(events)

    ev_out = [{"id": i + 1, "ts": iso(e.ts), "source": e.source, "kind": e.kind, "host": e.host, "ip": e.ip,
               "user": e.user, "method": e.method, "path": e.path, "status": e.status, "command": e.command,
               "raw": e.raw} for i, e in enumerate(events)]
    triage = {"http-5xx-spike": ("resolved", "Upstream API restarted, errors stopped."),
              "ssh-invalid-user-probe": ("acknowledged", "Known scanner range, watching.")}
    al_out = []
    for i, d in enumerate(sorted(drafts, key=lambda d: d.last_seen), start=1):
        status, history = "open", []
        if d.rule_id in triage:
            status, note = triage[d.rule_id]
            history = [{"at": iso(d.last_seen), "by": "analyst@sentinel.local", "from": "open", "to": status, "note": note}]
        al_out.append({"id": i, "rule_id": d.rule_id, "title": d.title, "severity": d.severity,
                       "description": d.description, "group_by": d.group_by, "key": d.key, "count": d.count,
                       "first_seen": iso(d.first_seen), "last_seen": iso(d.last_seen), "status": status,
                       "assignee_id": 2 if history else None, "evidence": d.evidence, "history": history,
                       "created_at": iso(d.last_seen)})
    data = {"generated_end": iso(events[-1].ts), "events": ev_out, "alerts": al_out,
            "rules": [r.summary() for r in rules]}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT.parent)}: {len(ev_out)} events, {len(al_out)} alerts, {OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()

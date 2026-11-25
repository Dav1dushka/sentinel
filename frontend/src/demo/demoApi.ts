/**
 * In-browser stand-in for the API, used by the static demo build.
 * The data is the real output of the detection engine on the sample logs
 * (see backend/scripts/export_demo.py).
 */
import type { Api } from "../api";
import { ApiError } from "../api";
import type { Alert, Counted, Overview, SecurityEvent, Severity, Token, User } from "../types";
import raw from "./demo-data.json";
import { now, setClockOffset } from "../clock";

type Data = { generated_end: string; events: SecurityEvent[]; alerts: Alert[]; rules: unknown[] };
const data = raw as unknown as Data;

/**
 * The demo is a snapshot: move the app clock to a few minutes after the last
 * sample line, so timestamps, relative times and the raw log lines all agree.
 */
export function startDemoClock() {
  setClockOffset(Date.parse(data.generated_end) + 4 * 60_000 - Date.now());
}

const events: SecurityEvent[] = data.events;
const alerts: Alert[] = data.alerts;

const DEMO_USER: User = { id: 1, email: "analyst@sentinel.local", role: "analyst", is_active: true };
const wait = <T,>(v: T, ms = 160) => new Promise<T>((r) => setTimeout(() => r(structuredClone(v)), ms));

function top(map: Map<string, number>, n = 6): Counted[] {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, count]) => ({ key, count }));
}

export const demoApi: Api = {
  demo: true,
  login(email) {
    if (!email.includes("@")) return Promise.reject(new ApiError(401, "Wrong email or password"));
    const t: Token = { access_token: "demo", expires_in: 3600, user: { ...DEMO_USER, email } };
    return wait(t, 400);
  },
  me: () => wait(DEMO_USER),
  overview(hours) {
    const since = now() - hours * 3_600_000;
    const start = new Date(since);
    start.setUTCMinutes(0, 0, 0);
    const buckets = Array.from({ length: hours + 1 }, (_, i) => ({
      t: new Date(start.getTime() + i * 3_600_000).toISOString(), auth: 0, nginx: 0, alerts: 0,
    }));
    const idx = (iso: string) => Math.floor((Date.parse(iso) - start.getTime()) / 3_600_000);
    const bySource: Record<string, number> = {};
    const offenders = new Map<string, number>();
    for (const e of events) {
      if (Date.parse(e.ts) < since) continue;
      bySource[e.source] = (bySource[e.source] ?? 0) + 1;
      const b = buckets[idx(e.ts)];
      if (b) b[e.source] += 1;
      const bad = e.kind === "ssh_failed" || e.kind === "ssh_invalid_user" || (e.status ?? 0) >= 400;
      if (bad && e.ip) offenders.set(e.ip, (offenders.get(e.ip) ?? 0) + 1);
    }
    const openAlerts: Partial<Record<Severity, number>> = {};
    const rules = new Map<string, number>();
    let inWindow = 0;
    for (const a of alerts) {
      if (a.status === "open") openAlerts[a.severity] = (openAlerts[a.severity] ?? 0) + 1;
      if (Date.parse(a.first_seen) >= since) {
        inWindow += 1;
        rules.set(a.rule_id, (rules.get(a.rule_id) ?? 0) + 1);
        const b = buckets[idx(a.first_seen)];
        if (b) b.alerts += 1;
      }
    }
    const o: Overview = {
      since: new Date(since).toISOString(),
      events: Object.values(bySource).reduce((s, n) => s + n, 0),
      events_by_source: bySource,
      open_alerts: openAlerts,
      alerts_in_window: inWindow,
      timeline: buckets,
      top_offenders: top(offenders),
      top_rules: top(rules),
    };
    return wait(o);
  },
  alerts(q) {
    const needle = q.q?.toLowerCase();
    const items = alerts
      .filter((a) => (!q.status || a.status === q.status) && (!q.severity || a.severity === q.severity))
      .filter((a) => !needle || `${a.title} ${a.key} ${a.rule_id}`.toLowerCase().includes(needle))
      .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));
    return wait({ items, next_cursor: null });
  },
  alert(id) {
    const a = alerts.find((x) => x.id === id);
    return a ? wait(a) : Promise.reject(new ApiError(404, "Alert not found"));
  },
  updateAlert(id, patch) {
    const a = alerts.find((x) => x.id === id);
    if (!a) return Promise.reject(new ApiError(404, "Alert not found"));
    const entry: Alert["history"][number] = { at: new Date(now()).toISOString(), by: DEMO_USER.email };
    if (patch.status && patch.status !== a.status) {
      entry.from = a.status;
      entry.to = patch.status;
      a.status = patch.status;
    }
    if (patch.assign_to_me) {
      a.assignee_id = DEMO_USER.id;
      entry.assigned = DEMO_USER.email;
    }
    if (patch.note?.trim()) entry.note = patch.note.trim();
    if (Object.keys(entry).length > 2) a.history = [...a.history, entry];
    return wait(a);
  },
  events(q) {
    const needle = q.q?.toLowerCase();
    const limit = q.limit ?? 50;
    const rows = events
      .filter((e) => (!q.source || e.source === q.source) && (!q.kind || e.kind === q.kind) && (!q.ip || e.ip === q.ip))
      .filter((e) => !needle || e.raw.toLowerCase().includes(needle))
      .filter((e) => !q.before_id || e.id < q.before_id)
      .sort((a, b) => b.id - a.id);
    const items = rows.slice(0, limit);
    return wait({ items, next_cursor: rows.length > limit ? items[items.length - 1].id : null });
  },
  rules: () => wait(data.rules as never),
};

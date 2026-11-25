import { useState } from "react";
import { BarList, Empty, ErrorNote, SeverityBadge, Timeline } from "../components/ui";
import { ago, api, fmt, go, useData } from "../lib";
import { SEVERITIES } from "../types";

const RANGES = [{ h: 24, label: "24 h" }, { h: 72, label: "3 days" }, { h: 168, label: "7 days" }];

export function OverviewPage() {
  const [hours, setHours] = useState(24);
  const ov = useData(() => api.overview(hours), [hours], 10_000);
  const latest = useData(() => api.alerts({ status: "open" }), [], 10_000);
  const o = ov.data;
  const open = o ? SEVERITIES.reduce((s, k) => s + (o.open_alerts[k] ?? 0), 0) : 0;
  const crit = o ? (o.open_alerts.critical ?? 0) + (o.open_alerts.high ?? 0) : 0;

  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>{o ? (crit ? `${crit} serious alert${crit > 1 ? "s" : ""} need a look` : "All quiet") : "Overview"}</h1>
          <p className="muted">Live view of SSH, sudo and web traffic. Refreshes every 10 seconds.</p>
        </div>
        <div className="seg" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button key={r.h} className={hours === r.h ? "on" : ""} onClick={() => setHours(r.h)}>{r.label}</button>
          ))}
        </div>
      </header>

      {ov.error && <ErrorNote message={ov.error} retry={ov.reload} />}

      <div className="kpis">
        <button className="kpi kpi-hot" onClick={() => go("alerts")}>
          <span className="kpi-label">Open alerts</span>
          <span className="kpi-value">{o ? fmt(open) : "–"}</span>
          <span className="kpi-sub">
            {o && SEVERITIES.filter((s) => o.open_alerts[s]).map((s) => (
              <span key={s} className={`chip chip-${s}`}>{o.open_alerts[s]} {s}</span>
            ))}
            {o && !open && "nothing waiting"}
          </span>
        </button>
        <div className="kpi">
          <span className="kpi-label">Events</span>
          <span className="kpi-value">{o ? fmt(o.events) : "–"}</span>
          <span className="kpi-sub muted">{o ? `${fmt(o.events_by_source.auth ?? 0)} auth · ${fmt(o.events_by_source.nginx ?? 0)} web` : ""}</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Alerts raised</span>
          <span className="kpi-value">{o ? fmt(o.alerts_in_window) : "–"}</span>
          <span className="kpi-sub muted">in the selected range</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Noisiest address</span>
          <span className="kpi-value mono small">{o?.top_offenders[0]?.key ?? "–"}</span>
          <span className="kpi-sub muted">{o?.top_offenders[0] ? `${fmt(o.top_offenders[0].count)} failed or rejected requests` : ""}</span>
        </div>
      </div>

      <div className="card">
        <div className="card-head"><h2>Activity per hour</h2></div>
        {o ? <Timeline points={o.timeline} /> : <div className="skeleton" style={{ height: 240 }} />}
      </div>

      <div className="grid-3">
        <div className="card">
          <div className="card-head"><h2>Latest open alerts</h2><button className="link" onClick={() => go("alerts")}>All alerts →</button></div>
          {latest.data && !latest.data.items.length && <Empty title="No open alerts">New detections appear here within seconds.</Empty>}
          <ul className="mini-alerts">
            {latest.data?.items.slice(0, 6).map((a) => (
              <li key={a.id}>
                <button onClick={() => go(`alerts/${a.id}`)}>
                  <SeverityBadge s={a.severity} />
                  <span className="t">{a.title}</span>
                  <span className="mono k">{a.key}</span>
                  <span className="muted when">{ago(a.last_seen)}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div className="card">
          <div className="card-head"><h2>Top offending addresses</h2></div>
          <BarList items={o?.top_offenders ?? []} onPick={(ip) => go(`events?ip=${encodeURIComponent(ip)}`)}
            empty="No failed logins or rejected requests." />
        </div>
        <div className="card">
          <div className="card-head"><h2>Rules that fired</h2></div>
          <BarList items={o?.top_rules ?? []} empty="No rule has fired in this range." />
        </div>
      </div>
    </section>
  );
}

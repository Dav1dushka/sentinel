import { useState } from "react";
import { Empty, ErrorNote, SeverityBadge, StatusPill } from "../components/ui";
import { ago, api, clock, duration, fmt, go, useData } from "../lib";
import type { Alert, AlertPatch, AlertStatus, Severity } from "../types";
import { SEVERITIES } from "../types";

const KEY_LABEL: Record<string, string> = { ip: "IP address", user: "User", host: "Host" };

const TABS: { s: AlertStatus | undefined; label: string }[] = [
  { s: "open", label: "Open" }, { s: "acknowledged", label: "Acknowledged" },
  { s: "resolved", label: "Resolved" }, { s: undefined, label: "All" },
];

export function AlertsPage() {
  const [status, setStatus] = useState<AlertStatus | undefined>("open");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [q, setQ] = useState("");
  const list = useData(() => api.alerts({ status, severity: severity || undefined, q: q || undefined }),
    [status, severity, q], 10_000);

  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>Alerts</h1>
          <p className="muted">Every alert keeps the log lines that triggered it. Acknowledge what you are handling, resolve what is done.</p>
        </div>
      </header>
      <div className="toolbar">
        <div className="seg" role="tablist" aria-label="Status">
          {TABS.map((t) => (
            <button key={t.label} role="tab" aria-selected={status === t.s} className={status === t.s ? "on" : ""}
              onClick={() => setStatus(t.s)}>{t.label}</button>
          ))}
        </div>
        <label className="field">
          <span>Severity</span>
          <select id="sev-filter" value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
            <option value="">Any</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="field grow">
          <span>Search</span>
          <input id="alert-search" type="search" placeholder="Title, address, user or rule" value={q}
            onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>

      {list.error && <ErrorNote message={list.error} retry={list.reload} />}
      {list.data && !list.data.items.length && (
        <Empty title={status === "open" ? "No open alerts" : "Nothing matches these filters"}>
          {status === "open" ? "Good news. New detections show up here automatically." : "Try another status or clear the search."}
        </Empty>
      )}
      <ul className="alert-list">
        {list.data?.items.map((a) => (
          <li key={a.id} className={`sevline-${a.severity}`}>
            <button onClick={() => go(`alerts/${a.id}`)}>
              <span className="col-sev"><SeverityBadge s={a.severity} /></span>
              <span className="col-main">
                <strong>{a.title}</strong>
                <span className="muted">{KEY_LABEL[a.group_by ?? ""] ?? "Key"} <span className="mono">{a.key}</span> · {fmt(a.count)} event{a.count === 1 ? "" : "s"}{a.count > 1 ? ` in ${duration(a.first_seen, a.last_seen)}` : ""}</span>
              </span>
              <span className="col-when muted" title={clock(a.last_seen)}>{ago(a.last_seen)}</span>
              <span className="col-status"><StatusPill s={a.status} /></span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function AlertDetail({ id }: { id: number }) {
  const res = useData(() => api.alert(id), [id]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const a = res.data;

  async function act(patch: AlertPatch) {
    setBusy(true);
    setErr(null);
    try {
      res.setData(await api.updateAlert(id, { ...patch, note: note.trim() || undefined }));
      setNote("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (res.error) return <section className="page"><ErrorNote message={res.error} retry={res.reload} /></section>;
  if (!a) return <section className="page"><div className="skeleton" style={{ height: 320 }} /></section>;

  return (
    <section className="page">
      <button className="link back" onClick={() => go("alerts")}>← All alerts</button>
      <header className={`detail-head sevline-${a.severity}`}>
        <div>
          <div className="row gap"><SeverityBadge s={a.severity} /><StatusPill s={a.status} /><span className="muted mono">#{a.id} · {a.rule_id}</span></div>
          <h1>{a.title}</h1>
          <p className="muted">{a.description}</p>
        </div>
      </header>

      <div className="detail-grid">
        <div className="stack">
          <dl className="facts">
            <div><dt>{KEY_LABEL[a.group_by ?? ""] ?? "Key"}</dt><dd className="mono">{a.key}</dd></div>
            <div><dt>Events</dt><dd>{fmt(a.count)}</dd></div>
            <div><dt>First seen (UTC)</dt><dd>{clock(a.first_seen)}</dd></div>
            <div><dt>Last seen (UTC)</dt><dd>{clock(a.last_seen)} <span className="muted">({ago(a.last_seen)})</span></dd></div>
          </dl>

          <div className="card">
            <div className="card-head">
              <h2>Evidence</h2>
              {a.group_by === "ip" && <button className="link" onClick={() => go(`events?ip=${encodeURIComponent(a.key)}`)}>All events from {a.key} →</button>}
            </div>
            <pre className="evidence">{a.evidence.join("\n")}</pre>
          </div>
        </div>

        <aside className="stack">
          <div className="card">
            <div className="card-head"><h2>Triage</h2></div>
            <label className="field">
              <span>Note (optional)</span>
              <textarea id="triage-note" rows={3} maxLength={1000} placeholder="What did you find or do?" value={note}
                onChange={(e) => setNote(e.target.value)} />
            </label>
            <div className="row gap wrap">
              {a.status !== "acknowledged" && a.status !== "resolved" && (
                <button className="btn" disabled={busy} onClick={() => act({ status: "acknowledged", assign_to_me: true })}>Acknowledge</button>
              )}
              {a.status !== "resolved" && <button className="btn primary" disabled={busy} onClick={() => act({ status: "resolved" })}>Resolve</button>}
              {a.status !== "open" && <button className="btn" disabled={busy} onClick={() => act({ status: "open" })}>Reopen</button>}
              {note.trim() && <button className="btn ghost" disabled={busy} onClick={() => act({})}>Add note</button>}
            </div>
            {err && <p className="error-text">{err}</p>}
          </div>

          <div className="card">
            <div className="card-head"><h2>History</h2></div>
            {a.history.length ? (
              <ol className="history">
                {[...a.history].reverse().map((h, i) => <HistoryItem key={i} h={h} />)}
              </ol>
            ) : <p className="muted">No actions yet.</p>}
          </div>
        </aside>
      </div>
    </section>
  );
}

function HistoryItem({ h }: { h: Alert["history"][number] }) {
  return (
    <li>
      <span className="muted small">{clock(h.at)} · {h.by}</span>
      {h.to && <span>Status {h.from} → <strong>{h.to}</strong></span>}
      {h.assigned && !h.to && <span>Assigned to {h.assigned}</span>}
      {h.note && <q>{h.note}</q>}
    </li>
  );
}

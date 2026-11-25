import { useEffect, useState, type ChangeEvent } from "react";
import { Empty, ErrorNote } from "../components/ui";
import { KIND_LABEL, api, clock } from "../lib";
import type { EventQuery, SecurityEvent } from "../types";

const PAGE = 60;

export function EventsPage({ params }: { params: URLSearchParams }) {
  const [filters, setFilters] = useState<EventQuery>({
    source: params.get("source") ?? "", kind: params.get("kind") ?? "", ip: params.get("ip") ?? "", q: params.get("q") ?? "",
  });
  const [rows, setRows] = useState<SecurityEvent[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);

  useEffect(() => {
    setFilters((f) => ({ ...f, ip: params.get("ip") ?? f.ip }));
  }, [params]);

  async function load(reset: boolean) {
    setLoading(true);
    setError(null);
    try {
      const clean = Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) as EventQuery;
      const page = await api.events({ ...clean, limit: PAGE, before_id: reset ? undefined : cursor ?? undefined });
      setRows((r) => (reset ? page.items : [...r, ...page.items]));
      setCursor(page.next_cursor);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const t = setTimeout(() => void load(true), 250); // debounce typing
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  const set = (k: keyof EventQuery) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setFilters((f) => ({ ...f, [k]: e.target.value }));

  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>Events</h1>
          <p className="muted">Every parsed log line, newest first. Click a row to see the original line.</p>
        </div>
      </header>
      <div className="toolbar">
        <label className="field"><span>Source</span>
          <select id="ev-source" value={filters.source} onChange={set("source")}>
            <option value="">All</option><option value="auth">auth.log</option><option value="nginx">nginx</option>
          </select>
        </label>
        <label className="field"><span>Type</span>
          <select id="ev-kind" value={filters.kind} onChange={set("kind")}>
            <option value="">All</option>
            {Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </label>
        <label className="field"><span>IP address</span>
          <input id="ev-ip" className="mono" placeholder="203.0.113.45" value={filters.ip} onChange={set("ip")} />
        </label>
        <label className="field grow"><span>Search raw line</span>
          <input id="ev-q" type="search" placeholder="wp-login, root, 502…" value={filters.q} onChange={set("q")} />
        </label>
      </div>

      {error && <ErrorNote message={error} retry={() => void load(true)} />}
      {!loading && !rows.length && !error && <Empty title="No events match">Clear a filter or send logs with the agent.</Empty>}

      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="events">
            <thead>
              <tr><th>Time (UTC)</th><th>Type</th><th>Host</th><th>IP</th><th>Detail</th><th className="num">Status</th></tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <EventRow key={e.id} e={e} open={open === e.id} toggle={() => setOpen(open === e.id ? null : e.id)}
                  pickIp={(ip) => setFilters((f) => ({ ...f, ip }))} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="row center">
        {cursor && <button className="btn" disabled={loading} onClick={() => void load(false)}>{loading ? "Loading…" : "Load older events"}</button>}
      </div>
    </section>
  );
}

function EventRow({ e, open, toggle, pickIp }: { e: SecurityEvent; open: boolean; toggle: () => void; pickIp: (ip: string) => void }) {
  const bad = e.kind === "ssh_failed" || e.kind === "ssh_invalid_user" || (e.status ?? 0) >= 400;
  const detail = e.source === "nginx" ? `${e.method} ${e.path}` : e.command ? `${e.user}: ${e.command}` : e.user ?? "";
  return (
    <>
      <tr className={`clickable ${bad ? "bad" : ""}`} onClick={toggle} aria-expanded={open}>
        <td className="nowrap mono small">{clock(e.ts)}</td>
        <td><span className={`kind kind-${e.kind}`}>{KIND_LABEL[e.kind] ?? e.kind}</span></td>
        <td className="small">{e.host}</td>
        <td>{e.ip ? <button className="link mono small" onClick={(ev) => { ev.stopPropagation(); pickIp(e.ip!); }}>{e.ip}</button> : "–"}</td>
        <td className="mono small ellipsis">{detail}</td>
        <td className="num mono small">{e.status ?? ""}</td>
      </tr>
      {open && <tr className="raw"><td colSpan={6}><code>{e.raw}</code></td></tr>}
    </>
  );
}

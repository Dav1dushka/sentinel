import { useEffect, useRef, useState, type ReactNode } from "react";
import type { AlertStatus, Counted, Overview, Severity } from "../types";
import { fmt, hourLabel } from "../lib";

export function SeverityBadge({ s }: { s: Severity }) {
  return <span className={`sev sev-${s}`}>{s}</span>;
}

export function StatusPill({ s }: { s: AlertStatus }) {
  return <span className={`pill pill-${s}`}>{s}</span>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <p>{children}</p>}
    </div>
  );
}

export function ErrorNote({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="error-note" role="alert">
      <span>Could not load data: {message}</span>
      {retry && <button className="btn small" onClick={retry}>Retry</button>}
    </div>
  );
}

/** Horizontal bars as plain HTML rows: label, bar, value. */
export function BarList({ items, onPick, empty }: { items: Counted[]; onPick?: (k: string) => void; empty: string }) {
  if (!items.length) return <p className="muted">{empty}</p>;
  const max = Math.max(...items.map((i) => i.count));
  return (
    <ul className="barlist">
      {items.map((i) => (
        <li key={i.key}>
          {onPick ? <button className="link mono" onClick={() => onPick(i.key)}>{i.key}</button> : <span className="mono">{i.key}</span>}
          <span className="track"><span style={{ width: `${(i.count / max) * 100}%` }} /></span>
          <span className="num">{fmt(i.count)}</span>
        </li>
      ))}
    </ul>
  );
}

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [w, setW] = useState(600);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

/** Stacked hourly bars (auth + web) with alert markers on top. Drawn at real pixel size. */
export function Timeline({ points }: { points: Overview["timeline"] }) {
  const [ref, W] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const H = 220, top = 22, bottom = 26, left = 40, right = 8;
  const plotW = Math.max(10, W - left - right), plotH = H - top - bottom;
  const max = Math.max(1, ...points.map((p) => p.auth + p.nginx));
  const nice = Math.pow(10, Math.floor(Math.log10(max)));
  const yMax = Math.ceil(max / nice) * nice;
  const step = plotW / Math.max(1, points.length);
  const bw = Math.max(2, step * 0.62);
  const y = (v: number) => top + plotH - (v / yMax) * plotH;
  const every = W < 520 ? 6 : points.length > 48 ? 24 : 3;
  const h = hover !== null ? points[hover] : null;

  return (
    <div className="timeline" ref={ref}>
      <svg width={W} height={H} role="img" aria-label="Events per hour with alerts"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const x = e.clientX - e.currentTarget.getBoundingClientRect().left - left;
          const i = Math.floor(x / step);
          setHover(i >= 0 && i < points.length ? i : null);
        }}>
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1={left} x2={W - right} y1={y(yMax * f)} y2={y(yMax * f)} className="grid" />
            <text x={left - 6} y={y(yMax * f) + 4} textAnchor="end" className="tick">{fmt(Math.round(yMax * f))}</text>
          </g>
        ))}
        {points.map((p, i) => {
          const x = left + i * step + (step - bw) / 2;
          return (
            <g key={p.t} opacity={hover === null || hover === i ? 1 : 0.45}>
              <rect x={x} y={y(p.nginx)} width={bw} height={top + plotH - y(p.nginx)} className="bar-web" rx={1.5} />
              <rect x={x} y={y(p.nginx + p.auth)} width={bw} height={y(p.nginx) - y(p.nginx + p.auth)} className="bar-auth" rx={1.5} />
              {p.alerts > 0 && <circle cx={x + bw / 2} cy={Math.min(y(p.nginx + p.auth) - 8, top + plotH - 8)} r={4 + Math.min(4, p.alerts)} className="dot-alert" />}
              {i % every === 0 && (
                <text x={x + bw / 2} y={H - 8} textAnchor="middle" className="tick">
                  {hourLabel(p.t)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <div className="legend">
        <span><i className="sw sw-auth" />SSH and sudo</span>
        <span><i className="sw sw-web" />Web requests</span>
        <span><i className="sw sw-alert" />Alerts</span>
        {h && (
          <span className="hover mono">
            {hourLabel(h.t)} UTC · {fmt(h.auth)} auth · {fmt(h.nginx)} web · {h.alerts} alerts
          </span>
        )}
      </div>
    </div>
  );
}

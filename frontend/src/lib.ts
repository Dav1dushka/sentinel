import { useCallback, useEffect, useRef, useState } from "react";
import type { Api } from "./api";
import { httpApi } from "./api";
import { demoApi, startDemoClock } from "./demo/demoApi";
import { now } from "./clock";

export const api: Api = import.meta.env.VITE_DEMO ? demoApi : httpApi;
if (import.meta.env.VITE_DEMO) startDemoClock();

/** Load data, optionally re-polling every `refreshMs`. Keeps old data while refreshing. */
export function useData<T>(load: () => Promise<T>, deps: unknown[], refreshMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const loadRef = useRef(load);
  loadRef.current = load;

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await loadRef.current());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    if (!refreshMs) return;
    const id = setInterval(() => { if (!document.hidden) void reload(); }, refreshMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, setData };
}

export interface Route { parts: string[]; params: URLSearchParams }

/** Minimal hash router: "#/events?ip=1.2.3.4" -> { parts: ["events"], params: ip=1.2.3.4 }. */
export function useRoute(): Route {
  const read = (): Route => {
    const [path, query = ""] = window.location.hash.replace(/^#\/?/, "").split("?");
    return { parts: path.split("/").filter(Boolean), params: new URLSearchParams(query) };
  };
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => setRoute(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export const go = (path: string) => { window.location.hash = `#/${path}`; };

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

export function ago(iso: string): string {
  const s = (Date.parse(iso) - now()) / 1000;
  const abs = Math.abs(s);
  if (abs < 45) return "just now";
  if (abs < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}

/** Times are shown in UTC, like the raw log lines. */
export function clock(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit", day: "2-digit", month: "short" });
}

export const hourLabel = (iso: string) =>
  new Date(iso).toLocaleTimeString("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit" });

export const fmt = (n: number) => n.toLocaleString("en-US");

export function duration(fromIso: string, toIso: string): string {
  const s = Math.max(0, Math.round((Date.parse(toIso) - Date.parse(fromIso)) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export const KIND_LABEL: Record<string, string> = {
  ssh_failed: "SSH failed login",
  ssh_invalid_user: "SSH invalid user",
  ssh_success: "SSH login",
  sudo: "sudo",
  http: "HTTP request",
};

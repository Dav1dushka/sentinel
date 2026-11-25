import { useEffect, useState } from "react";
import { session } from "./api";
import { api, go, useData, useRoute } from "./lib";
import { AlertDetail, AlertsPage } from "./pages/Alerts";
import { EventsPage } from "./pages/Events";
import { LoginPage, Shield } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { RulesPage } from "./pages/Rules";
import type { User } from "./types";

const NAV = [
  { id: "overview", label: "Overview" },
  { id: "alerts", label: "Alerts" },
  { id: "events", label: "Events" },
  { id: "rules", label: "Rules" },
];

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(Boolean(session.get()));

  useEffect(() => {
    if (!session.get()) return;
    api.me().then(setUser).catch(() => session.set(null)).finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    const out = () => { session.set(null); setUser(null); };
    window.addEventListener("sentinel:logout", out);
    return () => window.removeEventListener("sentinel:logout", out);
  }, []);

  if (checking) return <div className="boot">Loading…</div>;
  if (!user) {
    return <LoginPage onLogin={(t) => { session.set(t.access_token); setUser(t.user); if (!location.hash) go("overview"); }} />;
  }
  return <Shell user={user} onLogout={() => { session.set(null); setUser(null); }} />;
}

function Shell({ user, onLogout }: { user: User; onLogout: () => void }) {
  const { parts, params } = useRoute();
  const page = parts[0] ?? "overview";
  const openCount = useData(() => api.alerts({ status: "open" }).then((p) => p.items.length), [], 15_000);

  let body;
  if (page === "alerts" && parts[1]) body = <AlertDetail id={Number(parts[1])} />;
  else if (page === "alerts") body = <AlertsPage />;
  else if (page === "events") body = <EventsPage params={params} />;
  else if (page === "rules") body = <RulesPage />;
  else body = <OverviewPage />;

  return (
    <div className="shell">
      <aside className="side">
        <a className="brand" href="#/overview"><Shield /> Sentinel</a>
        <nav aria-label="Main">
          {NAV.map((n) => (
            <a key={n.id} href={`#/${n.id}`} className={page === n.id ? "active" : ""} aria-current={page === n.id ? "page" : undefined}>
              {n.label}
              {n.id === "alerts" && !!openCount.data && <span className="count">{openCount.data}</span>}
            </a>
          ))}
        </nav>
        <div className="side-foot">
          <span className="muted small">{user.email}</span>
          <span className="muted small">{user.role}</span>
          <button className="link small" onClick={onLogout}>Sign out</button>
        </div>
      </aside>
      <main className="main">
        {api.demo && <div className="demo-banner">Demo mode · sample data from the real detection engine · changes are not saved</div>}
        {body}
      </main>
    </div>
  );
}

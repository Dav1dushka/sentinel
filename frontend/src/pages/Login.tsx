import { useState, type FormEvent } from "react";
import { api } from "../lib";
import type { Token } from "../types";

export function LoginPage({ onLogin }: { onLogin: (t: Token) => void }) {
  const [email, setEmail] = useState(api.demo ? "analyst@sentinel.local" : "");
  const [password, setPassword] = useState(api.demo ? "demo-password" : "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await api.login(email.trim(), password));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="login-card" onSubmit={submit}>
        <div className="brand big"><Shield /> Sentinel</div>
        <p className="muted">Security monitoring for SSH, sudo and web logs.</p>
        <label className="field">
          <span>Email</span>
          <input id="login-email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="field">
          <span>Password</span>
          <input id="login-password" type="password" autoComplete="current-password" required value={password}
            onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <p className="error-text" role="alert">{error}</p>}
        <button className="btn primary wide" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        {api.demo && <p className="demo-note">Demo build with sample data from the real detection engine. Any email works; changes stay in your browser tab.</p>}
      </form>
    </main>
  );
}

export function Shield() {
  return (
    <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 3l11 4v8c0 7-5 12-11 14C10 27 5 22 5 15V7z" fill="var(--accent)" />
      <path d="M11 16l3.5 3.5L21 13" fill="none" stroke="#0b0a14" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

import type {
  Alert, AlertPatch, AlertQuery, EventQuery, Overview, Page, Rule, SecurityEvent, Token, User,
} from "./types";

/** Everything the UI needs from the server. The demo build swaps in a local implementation. */
export interface Api {
  demo: boolean;
  login(email: string, password: string): Promise<Token>;
  me(): Promise<User>;
  overview(hours: number): Promise<Overview>;
  alerts(q: AlertQuery): Promise<Page<Alert>>;
  alert(id: number): Promise<Alert>;
  updateAlert(id: number, patch: AlertPatch): Promise<Alert>;
  events(q: EventQuery): Promise<Page<SecurityEvent>>;
  rules(): Promise<Rule[]>;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const TOKEN_KEY = "sentinel.token";

export const session = {
  get(): string | null {
    try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
  },
  set(token: string | null) {
    try {
      if (token) localStorage.setItem(TOKEN_KEY, token);
      else localStorage.removeItem(TOKEN_KEY);
    } catch { /* storage unavailable: the session lasts until reload */ }
  },
};

function qs(params: object): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "" && v !== null) p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = session.get();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* not JSON */ }
    if (res.status === 401) window.dispatchEvent(new Event("sentinel:logout"));
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const httpApi: Api = {
  demo: false,
  login(email, password) {
    const body = new URLSearchParams({ username: email, password });
    return request<Token>("/api/auth/login", { method: "POST", body });
  },
  me: () => request<User>("/api/auth/me"),
  overview: (hours) => request<Overview>(`/api/stats/overview${qs({ hours })}`),
  alerts: (q) => request<Page<Alert>>(`/api/alerts${qs(q)}`),
  alert: (id) => request<Alert>(`/api/alerts/${id}`),
  updateAlert: (id, patch) =>
    request<Alert>(`/api/alerts/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    }),
  events: (q) => request<Page<SecurityEvent>>(`/api/events${qs(q)}`),
  rules: () => request<Rule[]>("/api/rules"),
};

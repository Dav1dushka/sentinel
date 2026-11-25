export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface User {
  id: number;
  email: string;
  role: "admin" | "analyst";
  is_active: boolean;
}

export interface Token {
  access_token: string;
  expires_in: number;
  user: User;
}

export interface SecurityEvent {
  id: number;
  ts: string;
  source: "auth" | "nginx";
  kind: string;
  host: string;
  ip: string | null;
  user: string | null;
  method: string | null;
  path: string | null;
  status: number | null;
  command: string | null;
  raw: string;
}

export interface HistoryEntry {
  at: string;
  by: string;
  from?: AlertStatus;
  to?: AlertStatus;
  note?: string;
  assigned?: string;
}

export interface Alert {
  id: number;
  rule_id: string;
  title: string;
  severity: Severity;
  description: string;
  group_by: string | null;
  key: string;
  count: number;
  first_seen: string;
  last_seen: string;
  status: AlertStatus;
  assignee_id: number | null;
  evidence: string[];
  history: HistoryEntry[];
  created_at: string;
}

export interface Page<T> {
  items: T[];
  next_cursor: number | null;
}

export interface Counted {
  key: string;
  count: number;
}

export interface Overview {
  since: string;
  events: number;
  events_by_source: Record<string, number>;
  open_alerts: Partial<Record<Severity, number>>;
  alerts_in_window: number;
  timeline: { t: string; auth: number; nginx: number; alerts: number }[];
  top_offenders: Counted[];
  top_rules: Counted[];
}

export interface RuleCondition {
  field: string;
  op: string;
  value: unknown;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  type: "threshold" | "sequence";
  match: RuleCondition[];
  then: RuleCondition[];
  group_by: string | null;
  threshold: number;
  window: number;
  distinct: string | null;
  enabled: boolean;
  tags: string[];
}

export interface EventQuery {
  source?: string;
  kind?: string;
  ip?: string;
  q?: string;
  before_id?: number;
  limit?: number;
}

export interface AlertQuery {
  status?: AlertStatus;
  severity?: Severity;
  q?: string;
}

export interface AlertPatch {
  status?: AlertStatus;
  note?: string;
  assign_to_me?: boolean;
}

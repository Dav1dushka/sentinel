import { ErrorNote, SeverityBadge } from "../components/ui";
import { api, useData } from "../lib";
import type { Rule, RuleCondition } from "../types";

const OP: Record<string, string> = { eq: "=", not: "≠", in: "in", regex: "matches", gt: ">", gte: "≥", lt: "<", lte: "≤" };

function cond(c: RuleCondition) {
  const v = Array.isArray(c.value) ? c.value.join(", ") : String(c.value);
  return <code key={`${c.field}${c.op}`}>{c.field} {OP[c.op] ?? c.op} {c.op === "regex" ? `/${v}/` : v}</code>;
}

function sentence(r: Rule) {
  const per = r.group_by ? ` from the same ${r.group_by}` : "";
  const win = r.window >= 120 ? `${Math.round(r.window / 60)} minutes` : `${r.window} seconds`;
  if (r.type === "sequence") return `Fires when the second condition follows at least ${r.threshold} matches of the first${per} within ${win}.`;
  if (r.threshold === 1) return "Fires on every matching event (repeats are grouped into one alert).";
  if (r.distinct) return `Fires when ${r.threshold} different ${r.distinct} values appear${per} within ${win}.`;
  return `Fires at ${r.threshold} matching events${per} within ${win}.`;
}

export function RulesPage() {
  const rules = useData(() => api.rules(), []);
  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>Detection rules</h1>
          <p className="muted">Rules live in <code>backend/rules/default.yml</code>. They are plain YAML, so they can be reviewed in pull requests like code.</p>
        </div>
      </header>
      {rules.error && <ErrorNote message={rules.error} retry={rules.reload} />}
      <div className="rules">
        {rules.data?.map((r) => (
          <article key={r.id} className={`card rule sevline-${r.severity}`}>
            <div className="row gap"><SeverityBadge s={r.severity} /><span className="muted mono small">{r.id}</span>
              {r.type === "sequence" && <span className="tag">sequence</span>}</div>
            <h2>{r.title}</h2>
            <p className="muted">{r.description}</p>
            <div className="conds">
              <span className="muted small">when</span>{r.match.map(cond)}
              {r.then.length > 0 && <><span className="muted small">then</span>{r.then.map(cond)}</>}
            </div>
            <p className="small">{sentence(r)}</p>
            <div className="row gap wrap">{r.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
          </article>
        ))}
      </div>
    </section>
  );
}

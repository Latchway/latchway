import type { ReactNode } from "react";

import type { EffectiveConfiguration } from "../api/admin";
import type { AdminProblem } from "../api/auth";
import { Badge, EmptyState, Notice } from "../ui";

export function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? (
    <Notice title={problem.title} tone="danger">
      {problem.detail}
      <span className="lw-problem-meta">
        Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}{problem.operationId ? ` · Operation: ${problem.operationId}` : ""}
        {problem.documentationURL ? <> · <a className="lw-link" href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a></> : null}
      </span>
    </Notice>
  ) : null;
}

export function AccessRequired() {
  return (
    <div className="lw-page-notice">
      <EmptyState icon="lock" title="Sign in before opening this view.">The console never substitutes client-facing credentials for administrator access.</EmptyState>
    </div>
  );
}

function Table({ headers, rows }: { headers: string[]; rows: ReactNode[][] }) {
  return (
    <div className="lw-table-wrap">
      <table className="lw-mini-table">
        <thead><tr>{headers.map((header) => <th key={header} scope="col">{header}</th>)}</tr></thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={headers.length}>No matching records.</td></tr>
          ) : rows.map((row, index) => (
            <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function effectiveLimitValue(limit: EffectiveConfiguration["limits"][number]): string {
  if (limit.algorithm === "calendar") return `${limit.maximum?.toLocaleString()} / ${limit.window} (${limit.timezone})`;
  if (limit.algorithm === "token_bucket") return `${limit.capacity?.toLocaleString()} capacity · ${limit.refill_per_second}/s`;
  if (limit.algorithm === "per_request") return `${limit.per_request_maximum?.toLocaleString()} / request`;
  return `${limit.maximum?.toLocaleString()} concurrent`;
}

export function EffectiveConfigurationPanel({ configuration }: { configuration: EffectiveConfiguration }) {
  const selectedRoute = configuration.selected_route;
  return <section className="lw-effective" aria-labelledby={`effective-${configuration.subject.id}`}>
    <div className="lw-row lw-row--spread"><div><p className="lw-effective__kicker">Effective configuration</p><h3 className="lw-section-title" id={`effective-${configuration.subject.id}`}>{configuration.evaluation_mode === "recorded_request" ? "Recorded decision inputs" : "Current-state projection"}</h3></div><Badge color={configuration.policy_outcome === "allowed" ? "success" : "danger"} dot>{configuration.policy_outcome}</Badge></div>
    <p className="lw-note lw-secondary">{configuration.evaluation_mode === "recorded_request" ? "This view uses the immutable revision and durable decision provenance recorded for the request. Missing historical inputs remain unavailable." : "This read-only projection runs the active compiled revision through the production policy resolver. It neither reserves quota nor sends an upstream request."}</p>
    <dl className="lw-effective__facts"><div><dt>Revision</dt><dd>{configuration.revision_id}</dd></div><div><dt>Environment</dt><dd>{configuration.environment_kind} · {configuration.environment_id}</dd></div><div><dt>Feature / protocol</dt><dd>{configuration.feature}{configuration.protocol ? ` · ${configuration.protocol}` : ""}</dd></div><div><dt>Selected plan</dt><dd>{configuration.limit_plan ?? "Unavailable"}{configuration.limit_plan_source ? ` · ${configuration.limit_plan_source}` : ""}</dd></div><div><dt>Selected route</dt><dd>{selectedRoute ? `${selectedRoute.route} → ${selectedRoute.upstream} / ${selectedRoute.model} (${selectedRoute.physical_model})` : "Unavailable"}</dd></div><div><dt>Component policy</dt><dd>{configuration.component_definition_id ?? "Legacy surface"}{configuration.component_allowed === undefined ? "" : configuration.component_allowed ? " · allowed" : " · denied"}</dd></div></dl>
    {configuration.denial_reason ? <p className="lw-note"><strong>Denial reason:</strong> {configuration.denial_reason}</p> : null}
    <h4>Redaction-safe inputs and provenance</h4>
    <Table headers={["Fact", "Availability", "Source", "Visible values", "Explanation"]} rows={configuration.inputs.map((input) => [input.fact, input.availability, input.source, input.keys?.length ? `keys: ${input.keys.join(", ")}` : input.values ? Object.entries(input.values).map(([key, value]) => `${key}=${value}`).join(" · ") : "—", input.detail])} />
    <h4>Effective limits</h4>
    <Table headers={["#", "Metric", "Algorithm", "Scope", "Effective value", "Source"]} rows={configuration.limits.map((limit) => [limit.index + 1, limit.metric, limit.algorithm, limit.scope.join(" + "), effectiveLimitValue(limit), limit.source])} />
    {configuration.output ? <><h4>Output-token clamps</h4><Table headers={["Configured default", "Configured absolute", "Effective default", "Effective maximum", "Requested", "Source"]} rows={[[configuration.output.configured_default_maximum_tokens ?? "—", configuration.output.configured_absolute_maximum_tokens ?? "—", configuration.output.effective_default_maximum_tokens ?? "—", configuration.output.effective_maximum_tokens ?? "—", configuration.output.requested_maximum_tokens ?? "—", configuration.output.source]]} /></> : null}
    <h4>{configuration.evaluation_mode === "recorded_request" ? "Observed routes" : "Ordered eligible routes"}</h4>
    <Table headers={["#", "Route", "Upstream / model", "Priority / weight", "Sticky", "Fallback on", "Retry", "Source"]} rows={configuration.routes.map((route) => [route.order, route.route, `${route.upstream} / ${route.model} → ${route.physical_model}`, `${route.configured_priority} / ${route.configured_weight}`, route.sticky_by ?? "—", route.fallback_on.join(", ") || "—", `${route.retry_maximum_attempts} on ${route.retry_on.join(", ") || "none"}`, route.source])} />
    {configuration.decision_stages.length ? <><h4>Durable decision stages</h4><Table headers={["#", "Stage", "Outcome", "Plan / rule", "Route", "Duration", "Failure"]} rows={configuration.decision_stages.map((stage) => [stage.number, stage.stage, stage.outcome, stage.limit_plan_key ? `${stage.limit_plan_key}${stage.limit_metric ? ` · ${stage.limit_metric}` : ""}` : stage.policy_rule_key ?? "—", stage.route ? `${stage.route} → ${stage.upstream} / ${stage.model}` : "—", `${stage.duration_ms.toLocaleString()} ms`, stage.failure_code ?? "—"])} /></> : null}
    {configuration.matched_access_expression || configuration.matched_limit_plan_expression ? <details className="lw-details"><summary>Matched policy expressions</summary><dl className="lw-effective__facts"><div><dt>Access</dt><dd><code className="lw-code-inline">{configuration.matched_access_expression ?? "Unavailable"}</code></dd></div><div><dt>Limit plan</dt><dd><code className="lw-code-inline">{configuration.matched_limit_plan_expression ?? "Unavailable"}</code></dd></div></dl></details> : null}
    {configuration.warnings.length ? <Notice title="Important limitations" tone="warning"><ul className="lw-issue-items">{configuration.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></Notice> : null}
    <p className="lw-note lw-secondary">Claim values, provider credentials, authorization headers, proofs, and request or response bodies are excluded from this view.</p>
  </section>;
}

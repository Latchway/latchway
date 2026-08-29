import { type FormEvent, type ReactNode, useState } from "react";

import {
  adminRequest,
  AuditPageSchema,
  InstallationPageSchema,
  InstallationSchema,
  queryPath,
  RequestPageSchema,
  RequestSchema,
  RevisionSchema,
  RouteSimulationSchema,
  SelfTestSchema,
  UsageSummarySchema,
  UsageTimeseriesSchema,
  UserPageSchema,
  UserSchema,
  type ApplicationUser,
  type ApplicationUserPage,
  type AuditPage,
  type Installation,
  type InstallationPage,
  type LogicalRequest,
  type LogicalRequestPage,
  type RouteSimulation,
  type SelfTestRun,
  type UsageSummary,
  type UsageTimeseries
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";

const environmentPattern = /^env_[A-Za-z0-9_-]{16,128}$/;
const environmentInputPattern = environmentPattern.source;
const revisionPattern = "rev_[A-Za-z0-9_-]{16,128}";
const identifierPattern = /^[a-z][a-z0-9_-]{0,62}$/;
const identifierInputPattern = identifierPattern.source;

function PageHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return (
    <section className="page-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{children}</p>
      </div>
    </section>
  );
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? (
    <div className="control-notice control-notice--error" role="alert">
      <strong>{problem.title}</strong>
      <span>{problem.detail}</span>
      <small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}</small>
    </div>
  ) : null;
}

function AccessRequired() {
  return (
    <section className="empty-state">
      <p className="eyebrow">Administrator session</p>
      <h1>Sign in before opening this control-plane view.</h1>
      <p>The console never substitutes client-facing credentials for administrator access.</p>
    </section>
  );
}

function Table({ headers, rows }: { headers: string[]; rows: ReactNode[][] }) {
  return (
    <div className="data-table-wrap">
      <table className="data-table">
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

function time(value?: string): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function duration(startedAt: string, completedAt?: string): string {
  if (!completedAt) return "In progress";
  const milliseconds = Date.parse(completedAt) - Date.parse(startedAt);
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "—";
  if (milliseconds < 1_000) return `${milliseconds.toLocaleString()} ms`;
  return `${(milliseconds / 1_000).toLocaleString(undefined, { maximumFractionDigits: 3 })} s`;
}

function ratio(value: { numerator: number; denominator: number }, suffix = ""): string {
  if (value.denominator === 0) return "—";
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value.numerator / value.denominator)}${suffix}`;
}

function rate(value: { parts_per_million: number }): string {
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value.parts_per_million / 10_000)}%`;
}

function FormActions({ busy, children = "Load" }: { busy: boolean; children?: ReactNode }) {
  return <button className="primary-action" disabled={busy} type="submit">{busy ? "Working…" : children}</button>;
}

function BreakdownLimitNotice({ label, limit, truncated }: { label: string; limit: number; truncated: boolean }) {
  return truncated ? <p>Showing the first {limit.toLocaleString()} {label} rows.</p> : null;
}

export function UsersPage() {
  const session = useConsoleSession();
  const [environment, setEnvironment] = useState("");
  const [page, setPage] = useState<ApplicationUserPage>();
  const [selected, setSelected] = useState<ApplicationUser>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  const canMutate = session.data.session?.capabilities.includes("revoke_installations") ?? false;

  async function load(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(
        queryPath("/admin/v1/users", { environment_id: environment, page_size: "50", cursor }),
        UserPageSchema
      );
      setPage(result.data); setSelected(undefined);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function mutate(user: ApplicationUser): Promise<void> {
    setBusy(true); setProblem(undefined);
    const action = user.status === "blocked" ? "unblock" : "block";
    try {
      const result = await adminRequest(
        queryPath(`/admin/v1/users/${user.id}/${action}`, { environment_id: environment }),
        UserSchema,
        { method: "POST" }
      );
      setSelected(result.data);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === user.id ? result.data : item) } : current);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="control-page">
    <PageHeading eyebrow="Identity" title="Application users">Pseudonymous identities, normalized claims, status, and overrides. Raw provider subjects and tokens never appear here.</PageHeading>
    <form className="filter-bar" onSubmit={(event) => { event.preventDefault(); void load(); }}>
      <label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></label>
      <FormActions busy={busy}>List users</FormActions>
    </form>
    <ProblemNotice problem={problem} />
    {page ? <>
      <Table headers={["User", "Status", "Providers", "Last seen", ""]} rows={page.items.map((user) => [
        <button className="link-button" onClick={() => setSelected(user)} type="button">{user.id}</button>, user.status,
        user.identity_providers.join(", "), time(user.last_seen_at),
        <button className="small-action" disabled={!canMutate || busy} onClick={() => void mutate(user)} type="button">{user.status === "blocked" ? "Unblock" : "Block"}</button>
      ])} />
      {page.page.has_more ? <button className="secondary-action" disabled={busy} onClick={() => void load(page.page.next_cursor)} type="button">Next page</button> : null}
    </> : null}
    {selected ? <aside className="detail-card"><h2>User detail</h2><dl><div><dt>ID</dt><dd>{selected.id}</dd></div><div><dt>Status</dt><dd>{selected.status}</dd></div></dl><h3>Normalized safe claims</h3><pre>{JSON.stringify(selected.normalized_claims, null, 2)}</pre></aside> : null}
  </div>;
}

export function InstallationsPage() {
  const session = useConsoleSession();
  const [environment, setEnvironment] = useState("");
  const [page, setPage] = useState<InstallationPage>();
  const [selected, setSelected] = useState<Installation>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  const canRevoke = session.data.session?.capabilities.includes("revoke_installations") ?? false;

  async function load(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(queryPath("/admin/v1/installations", { environment_id: environment, page_size: "50", cursor }), InstallationPageSchema);
      setPage(result.data); setSelected(undefined);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  async function revoke(installation: Installation): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(`/admin/v1/installations/${installation.id}/revoke`, InstallationSchema, { method: "POST", body: { reason: "console operator revocation" } });
      setSelected(result.data);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === installation.id ? result.data : item) } : current);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  return <div className="control-page">
    <PageHeading eyebrow="Identity" title="Installations">Installation-bound public keys and normalized trust status without raw attestation evidence or DPoP proofs.</PageHeading>
    <form className="filter-bar" onSubmit={(event) => { event.preventDefault(); void load(); }}>
      <label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></label><FormActions busy={busy}>List installations</FormActions>
    </form>
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Installation", "Platform", "Status", "Trust", "Last seen", ""]} rows={page.items.map((item) => [
      <button className="link-button" onClick={() => setSelected(item)} type="button">{item.id}</button>, item.platform, item.status, item.trust_level, time(item.last_seen_at),
      <button className="small-action" disabled={!canRevoke || busy || item.status === "revoked"} onClick={() => void revoke(item)} type="button">Revoke</button>
    ])} />{page.page.has_more ? <button className="secondary-action" disabled={busy} onClick={() => void load(page.page.next_cursor)} type="button">Next page</button> : null}</> : null}
    {selected ? <aside className="detail-card"><h2>Installation detail</h2><dl><div><dt>User</dt><dd>{selected.user_id}</dd></div><div><dt>Trust provider</dt><dd>{selected.attestation_provider ?? "—"}</dd></div><div><dt>Trust expires</dt><dd>{time(selected.trust_expires_at)}</dd></div><div><dt>Revoked</dt><dd>{time(selected.revoked_at)}</dd></div></dl></aside> : null}
  </div>;
}

export function RequestsPage() {
  const session = useConsoleSession();
  const [environment, setEnvironment] = useState("");
  const [page, setPage] = useState<LogicalRequestPage>();
  const [selected, setSelected] = useState<LogicalRequest>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const [detailBusy, setDetailBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  async function load(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(queryPath("/admin/v1/requests", { environment_id: environment, page_size: "50", cursor }), RequestPageSchema);
      setPage(result.data); setSelected(undefined);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  async function loadRequest(requestID: string): Promise<void> {
    setDetailBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/requests/${requestID}`, RequestSchema);
      if (response.data.id !== requestID || response.data.environment_id !== environment) throw new Error("request_context");
      setSelected(response.data);
    }
    catch (error) {
      setSelected(undefined);
      setProblem(error instanceof Error && error.message === "request_context" ? { code: "invalid_response", detail: "The request detail did not match the selected request and environment.", retryable: true, status: 0, title: "Request detail mismatch" } : problemFromError(error));
    }
    finally { setDetailBusy(false); }
  }
  return <div className="control-page">
    <PageHeading eyebrow="Observability" title="Requests">Logical request metadata, attempts, usage, and provenance. Prompt and response bodies remain excluded.</PageHeading>
    <form className="filter-bar" onSubmit={(event) => { event.preventDefault(); void load(); }}><label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></label><FormActions busy={busy}>List requests</FormActions></form>
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Request", "Feature", "Protocol", "Status", "Attempts", "Started"]} rows={page.items.map((request) => [<button className="link-button" disabled={detailBusy} onClick={() => void loadRequest(request.id)} type="button">{request.id}</button>, request.feature, request.protocol, request.status, request.attempts.length, time(request.started_at)])} />{page.page.has_more ? <button className="secondary-action" disabled={busy} onClick={() => void load(page.page.next_cursor)} type="button">Next page</button> : null}</> : null}
    {detailBusy ? <p role="status">Loading exact request detail…</p> : null}
    {selected ? <aside className="detail-card"><h2>Request detail</h2>
      <dl><div><dt>Request</dt><dd>{selected.id}</dd></div><div><dt>Environment</dt><dd>{selected.environment_id}</dd></div><div><dt>Feature</dt><dd>{selected.feature}</dd></div><div><dt>Protocol</dt><dd>{selected.protocol}</dd></div><div><dt>Status</dt><dd>{selected.status}</dd></div><div><dt>Started</dt><dd>{time(selected.started_at)}</dd></div><div><dt>Completed</dt><dd>{time(selected.completed_at)}</dd></div><div><dt>Duration</dt><dd>{duration(selected.started_at, selected.completed_at)}</dd></div></dl>
      <h3>Aggregate usage</h3><Table headers={["Logical requests", "Input tokens", "Output tokens", "Total tokens", "Cost nano-USD"]} rows={selected.usage ? [[selected.usage.logical_requests, selected.usage.input_tokens, selected.usage.output_tokens, selected.usage.total_tokens, selected.usage.cost_nano_usd]] : []} />
      <h3>Ordered upstream attempts</h3><Table headers={["#", "Attempt", "Started", "Completed", "Duration", "Upstream", "Model", "Status", "Input", "Output", "Total", "Cost nUSD", "Usage provenance", "Cost provenance", "Cost source"]} rows={selected.attempts.map((attempt, index) => [index + 1, attempt.id, time(attempt.started_at), time(attempt.completed_at), duration(attempt.started_at, attempt.completed_at), attempt.upstream, attempt.model, attempt.status, attempt.usage?.input_tokens ?? "—", attempt.usage?.output_tokens ?? "—", attempt.usage?.total_tokens ?? "—", attempt.usage?.cost_nano_usd ?? "—", attempt.usage_provenance, attempt.cost_provenance, attempt.cost_source ?? "—"])} />
      <p><small>The Admin API does not expose route IDs, upstream HTTP status, or public failure codes for request attempts. Prompt/response bodies and identity subjects remain excluded.</small></p>
    </aside> : null}
  </div>;
}

type AnalyticsFocus = "attestation" | "cost" | "errors" | "latency" | "usage";

const analyticsCopy: Record<AnalyticsFocus, { button: string; description: string; title: string }> = {
  attestation: { button: "Load attestation failures", description: "Focused aggregate of rejected platform-proof evaluations. Raw attestation evidence remains excluded.", title: "Attestation failures" },
  cost: { button: "Load cost", description: "Integer nano-USD totals, model and feature attribution, and fixed provenance without presenting estimates as observed provider cost.", title: "Cost" },
  errors: { button: "Load errors", description: "Focused request failure, quota-denial, and fallback rates with exact bounded numerators and denominators.", title: "Errors" },
  latency: { button: "Load latency", description: "Focused request and time-to-first-token distributions with sample counts and request-volume context.", title: "Latency" },
  usage: { button: "Load usage", description: "Immutable logical request and token aggregates with explicit provenance and bounded breakdowns.", title: "Usage" }
};

function FocusedAnalytics({ focus, series, summary }: { focus: AnalyticsFocus; series?: UsageTimeseries; summary: UsageSummary }) {
  if (focus === "cost") return <>
    <section className="metric-grid"><article><span>Total cost</span><strong>{summary.values.cost_nano_usd.toLocaleString()} nUSD</strong></article><article><span>Cost / active user</span><strong>{ratio(summary.analytics.cost_per_active_user_nano_usd, " nUSD")}</strong></article><article><span>Requests</span><strong>{summary.analytics.request_count.toLocaleString()}</strong></article></section>
    <section className="detail-card"><h2>Cost by feature</h2><Table headers={["Feature", "Requests", "Active users", "Cost nano-USD"]} rows={summary.analytics.by_feature.items.map((item) => [item.key, item.request_count, item.active_users, item.values.cost_nano_usd])} /><BreakdownLimitNotice label="feature" limit={summary.analytics.by_feature.limit} truncated={summary.analytics.by_feature.truncated} /></section>
    <section className="detail-card"><h2>Cost by model</h2><Table headers={["Model", "Requests", "Active users", "Cost nano-USD"]} rows={summary.analytics.by_model.items.map((item) => [item.key, item.request_count, item.active_users, item.values.cost_nano_usd])} /><BreakdownLimitNotice label="model" limit={summary.analytics.by_model.limit} truncated={summary.analytics.by_model.truncated} /></section>
    <section className="detail-card"><h2>Cost by selected plan</h2><Table headers={["Selected plan", "Requests", "Active users", "Cost nano-USD"]} rows={summary.analytics.by_selected_plan.items.map((item) => [item.key, item.request_count, item.active_users, item.values.cost_nano_usd])} /><BreakdownLimitNotice label="selected-plan" limit={summary.analytics.by_selected_plan.limit} truncated={summary.analytics.by_selected_plan.truncated} /></section>
    <section className="detail-card"><h2>Cost provenance</h2><Table headers={["Provenance", "Fixed source", "Cost nano-USD"]} rows={summary.analytics.usage_by_provenance.map((item) => [item.provenance, item.cost_source ?? "—", item.values.cost_nano_usd])} /></section>
    {series ? <Table headers={["Bucket", "Cost nano-USD"]} rows={series.points.map((point) => [time(point.timestamp), point.values.cost_nano_usd])} /> : null}
  </>;
  if (focus === "latency") return <>
    <section className="metric-grid"><article><span>Request p95</span><strong>{summary.analytics.request_latency.p95_ms.toLocaleString()} ms</strong></article><article><span>TTFT p95</span><strong>{summary.analytics.time_to_first_token.p95_ms.toLocaleString()} ms</strong></article><article><span>Request samples</span><strong>{summary.analytics.request_latency.samples.toLocaleString()}</strong></article><article><span>TTFT samples</span><strong>{summary.analytics.time_to_first_token.samples.toLocaleString()}</strong></article></section>
    <section className="detail-card"><h2>Latency distributions</h2><Table headers={["Measure", "Samples", "p50 ms", "p95 ms", "p99 ms"]} rows={[["Request latency", summary.analytics.request_latency.samples, summary.analytics.request_latency.p50_ms, summary.analytics.request_latency.p95_ms, summary.analytics.request_latency.p99_ms], ["Time to first token", summary.analytics.time_to_first_token.samples, summary.analytics.time_to_first_token.p50_ms, summary.analytics.time_to_first_token.p95_ms, summary.analytics.time_to_first_token.p99_ms]]} /></section>
    {series ? <section className="detail-card"><h2>Request-volume context</h2><Table headers={["Bucket", "Requests"]} rows={series.points.map((point) => [time(point.timestamp), point.values.logical_requests])} /></section> : null}
  </>;
  if (focus === "errors") return <>
    <section className="metric-grid"><article><span>Failure rate</span><strong>{rate(summary.analytics.failure_rate)}</strong></article><article><span>Quota-denial rate</span><strong>{rate(summary.analytics.quota_denial_rate)}</strong></article><article><span>Fallback rate</span><strong>{rate(summary.analytics.fallback_rate)}</strong></article><article><span>Requests</span><strong>{summary.analytics.request_count.toLocaleString()}</strong></article></section>
    <section className="detail-card"><h2>Error and recovery rates</h2><Table headers={["Measure", "Rate", "Events", "Denominator"]} rows={[["Failures", rate(summary.analytics.failure_rate), summary.analytics.failure_rate.numerator, summary.analytics.failure_rate.denominator], ["Quota denials", rate(summary.analytics.quota_denial_rate), summary.analytics.quota_denial_rate.numerator, summary.analytics.quota_denial_rate.denominator], ["Fallbacks", rate(summary.analytics.fallback_rate), summary.analytics.fallback_rate.numerator, summary.analytics.fallback_rate.denominator]]} /></section>
    {series ? <section className="detail-card"><h2>Request-volume context</h2><Table headers={["Bucket", "Requests"]} rows={series.points.map((point) => [time(point.timestamp), point.values.logical_requests])} /></section> : null}
  </>;
  if (focus === "attestation") return <>
    <section className="metric-grid"><article><span>Attestation-failure rate</span><strong>{rate(summary.analytics.attestation_failure_rate)}</strong></article><article><span>Rejected proofs</span><strong>{summary.analytics.attestation_failure_rate.numerator.toLocaleString()}</strong></article><article><span>Proof evaluations</span><strong>{summary.analytics.attestation_failure_rate.denominator.toLocaleString()}</strong></article></section>
    <section className="detail-card"><h2>Attestation rejection aggregate</h2><p>This aggregate contains no raw App Attest assertion, Play Integrity token, App Check token, Turnstile token, DPoP proof, or external subject.</p><Table headers={["Measure", "Value"]} rows={[["Rate", rate(summary.analytics.attestation_failure_rate)], ["Rejected", summary.analytics.attestation_failure_rate.numerator], ["Evaluated", summary.analytics.attestation_failure_rate.denominator], ["Parts per million", summary.analytics.attestation_failure_rate.parts_per_million]]} /></section>
  </>;
  return <>
    <section className="metric-grid"><article><span>Active AI users</span><strong>{summary.analytics.active_users.toLocaleString()}</strong></article><article><span>Requests / active user</span><strong>{ratio(summary.analytics.requests_per_active_user)}</strong></article><article><span>Logical requests</span><strong>{summary.values.logical_requests.toLocaleString()}</strong></article><article><span>Input tokens</span><strong>{summary.values.input_tokens.toLocaleString()}</strong></article><article><span>Output tokens</span><strong>{summary.values.output_tokens.toLocaleString()}</strong></article><article><span>Total tokens</span><strong>{summary.values.total_tokens.toLocaleString()}</strong></article></section>
    <section className="detail-card"><h2>Feature usage</h2><Table headers={["Feature", "Active users", "Requests", "Input", "Output", "Total"]} rows={summary.analytics.by_feature.items.map((item) => [item.key, item.active_users, item.request_count, item.values.input_tokens, item.values.output_tokens, item.values.total_tokens])} /><BreakdownLimitNotice label="feature" limit={summary.analytics.by_feature.limit} truncated={summary.analytics.by_feature.truncated} /></section>
    <section className="detail-card"><h2>Model usage</h2><Table headers={["Model", "Active users", "Requests", "Input", "Output", "Total"]} rows={summary.analytics.by_model.items.map((item) => [item.key, item.active_users, item.request_count, item.values.input_tokens, item.values.output_tokens, item.values.total_tokens])} /><BreakdownLimitNotice label="model" limit={summary.analytics.by_model.limit} truncated={summary.analytics.by_model.truncated} /></section>
    <section className="detail-card"><h2>Selected-plan usage</h2><Table headers={["Selected plan", "Active users", "Requests", "Input", "Output", "Total"]} rows={summary.analytics.by_selected_plan.items.map((item) => [item.key, item.active_users, item.request_count, item.values.input_tokens, item.values.output_tokens, item.values.total_tokens])} /><BreakdownLimitNotice label="selected-plan" limit={summary.analytics.by_selected_plan.limit} truncated={summary.analytics.by_selected_plan.truncated} /></section>
    <section className="detail-card"><h2>Usage provenance</h2><Table headers={["Provenance", "Requests", "Input", "Output", "Total"]} rows={summary.analytics.usage_by_provenance.map((item) => [item.provenance, item.values.logical_requests, item.values.input_tokens, item.values.output_tokens, item.values.total_tokens])} /></section>
    {series ? <Table headers={["Bucket", "Requests", "Input", "Output", "Total"]} rows={series.points.map((point) => [time(point.timestamp), point.values.logical_requests, point.values.input_tokens, point.values.output_tokens, point.values.total_tokens])} /> : null}
  </>;
}

function AnalyticsPage({ focus }: { focus: AnalyticsFocus }) {
  const session = useConsoleSession();
  const now = new Date(); const yesterday = new Date(now.getTime() - 86_400_000);
  const [environment, setEnvironment] = useState("");
  const [start, setStart] = useState(yesterday.toISOString().slice(0, 16));
  const [end, setEnd] = useState(now.toISOString().slice(0, 16));
  const [interval, setInterval] = useState<"hour" | "day">("hour");
  const [summary, setSummary] = useState<UsageSummary>(); const [series, setSeries] = useState<UsageTimeseries>();
  const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  async function load(): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const query = { environment_id: environment, start: new Date(start).toISOString(), end: new Date(end).toISOString() };
      const [summaryResult, seriesResult] = await Promise.all([
        adminRequest(queryPath("/admin/v1/usage/summary", { ...query, breakdown_limit: "50" }), UsageSummarySchema),
        adminRequest(queryPath("/admin/v1/usage/timeseries", { ...query, interval }), UsageTimeseriesSchema)
      ]);
      setSummary(summaryResult.data); setSeries(seriesResult.data);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  const copy = analyticsCopy[focus];
  return <div className="control-page">
    <PageHeading eyebrow="Observability" title={copy.title}>{copy.description}</PageHeading>
    <form className="filter-bar filter-bar--wide" onSubmit={(event) => { event.preventDefault(); void load(); }}>
      <label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></label>
      <label>Start<input required type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} /></label>
      <label>End<input required type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} /></label>
      <label>Interval<select value={interval} onChange={(event) => setInterval(event.target.value as "hour" | "day")}><option value="hour">Hourly</option><option value="day">Daily</option></select></label>
      <FormActions busy={busy}>{copy.button}</FormActions>
    </form><ProblemNotice problem={problem} />
    {summary ? <FocusedAnalytics focus={focus} series={series} summary={summary} /> : null}
  </div>;
}

export function UsagePage() { return <AnalyticsPage focus="usage" />; }
export function CostPage() { return <AnalyticsPage focus="cost" />; }
export function LatencyPage() { return <AnalyticsPage focus="latency" />; }
export function ErrorsPage() { return <AnalyticsPage focus="errors" />; }
export function AttestationFailuresPage() { return <AnalyticsPage focus="attestation" />; }

export function AuditPageView() {
  const session = useConsoleSession(); const organization = session.data?.session?.organization_id ?? "";
  const [page, setPage] = useState<AuditPage>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  async function load(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try { setPage((await adminRequest(queryPath("/admin/v1/audit-events", { organization_id: organization, page_size: "50", cursor }), AuditPageSchema)).data); }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  return <div className="control-page"><PageHeading eyebrow="Operations" title="Audit log">Append-only, tenant-scoped administrative outcomes with sensitive changes represented only by redacted summaries.</PageHeading>
    <button className="primary-action" disabled={busy} onClick={() => void load()} type="button">{busy ? "Loading…" : "Load audit events"}</button><ProblemNotice problem={problem} />
    {page ? <><Table headers={["Time", "Actor", "Action", "Target", "Result", "Request"]} rows={page.items.map((event) => [time(event.timestamp), event.actor, event.action, event.target, event.result, event.request_id])} />{page.page.has_more ? <button className="secondary-action" disabled={busy} onClick={() => void load(page.page.next_cursor)} type="button">Next page</button> : null}</> : null}
  </div>;
}

export function RouteSimulatorPage() {
  const session = useConsoleSession(); const [result, setResult] = useState<RouteSimulation>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  const [environment, setEnvironment] = useState(""); const [revision, setRevision] = useState(""); const [feature, setFeature] = useState("");
  const [contextRevision, setContextRevision] = useState<string>(); const [contextFeatures, setContextFeatures] = useState<string[]>([]);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  async function loadContext(): Promise<void> {
    if (!environmentPattern.test(environment)) { setProblem({ code: "request_invalid", detail: "Enter a canonical environment ID before loading route context.", retryable: false, status: 0, title: "Invalid route context" }); return; }
    setBusy(true); setProblem(undefined); setResult(undefined);
    try {
      const active = await adminRequest(`/admin/v1/environments/${environment}/config`, RevisionSchema);
      const spec = active.data.document.spec;
      if (!spec || typeof spec !== "object" || Array.isArray(spec)) throw new Error("context");
      const configuredFeatures = (spec as Record<string, unknown>).features;
      if (!Array.isArray(configuredFeatures) || configuredFeatures.length > 256) throw new Error("context");
      const ids = configuredFeatures.map((item) => item && typeof item === "object" && !Array.isArray(item) ? String((item as Record<string, unknown>).id ?? "") : "");
      if (ids.some((id) => !identifierPattern.test(id)) || new Set(ids).size !== ids.length) throw new Error("context");
      setContextRevision(active.data.id); setContextFeatures(ids); setRevision(active.data.id); setFeature(ids[0] ?? "");
    } catch (error) { setProblem(error instanceof Error && error.message === "context" ? { code: "invalid_response", detail: "The active revision did not contain a bounded canonical feature list.", retryable: true, status: 0, title: "Route context unavailable" } : problemFromError(error)); }
    finally { setBusy(false); }
  }
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const claims = JSON.parse(String(form.get("claims") ?? "{}")) as unknown;
      if (!claims || Array.isArray(claims) || typeof claims !== "object" || Object.keys(claims).length > 64) throw new Error("claims");
      if (contextRevision && revision !== contextRevision) throw new Error("context_selection");
      const response = await adminRequest(`/admin/v1/config-revisions/${revision}/simulate`, RouteSimulationSchema, { method: "POST", body: {
        feature, platform: String(form.get("platform")), trust_level: String(form.get("trust")),
        principal: { authenticated: form.get("authenticated") === "on", claims },
        request: { streaming: form.get("streaming") === "on", app_version: String(form.get("app_version") ?? ""), requested_input_tokens: Number(form.get("requested_input") ?? 0), requested_output_max: Number(form.get("requested_output") ?? 0), rewritten_request_bytes: Number(form.get("rewritten_request_bytes") ?? 0), framing_unit_count: Number(form.get("framing_unit_count") ?? 0) }
      }});
      if (response.data.revision_id !== revision || response.data.feature !== feature || (environment && response.data.environment_id !== environment)) throw new Error("context_result");
      setResult(response.data);
    } catch (error) { setProblem(error instanceof SyntaxError || (error instanceof Error && error.message === "claims") ? { code: "invalid_claims", detail: "Normalized claims must be one JSON object with at most 64 properties.", retryable: false, status: 0, title: "Invalid simulator input" } : error instanceof Error && error.message === "context_selection" ? { code: "context_mismatch", detail: "The revision no longer matches the loaded active environment context. Reload context before simulating.", retryable: false, status: 0, title: "Route context changed" } : error instanceof Error && error.message === "context_result" ? { code: "invalid_response", detail: "The simulation result did not match the selected revision, feature, and environment context.", retryable: true, status: 0, title: "Route context mismatch" } : problemFromError(error)); }
    finally { setBusy(false); }
  }
  return <div className="control-page"><PageHeading eyebrow="Operations" title="Route simulator">The server executes the exact compiled production CEL and resolver. This performs no quota reservation and no upstream dispatch.</PageHeading>
    <section className="filter-bar"><label>Environment context ID<input pattern={environmentInputPattern} value={environment} onChange={(event) => { setEnvironment(event.target.value); setContextRevision(undefined); setContextFeatures([]); }} /></label><button className="secondary-action" disabled={busy || !environment} onClick={() => void loadContext()} type="button">Load active route context</button>{contextRevision ? <span>Selected active revision <code>{contextRevision}</code> with {contextFeatures.length} feature{contextFeatures.length === 1 ? "" : "s"}.</span> : null}</section>
    <form className="control-form" onSubmit={(event) => void submit(event)}>
      <div className="form-field-grid"><label>Revision ID<input name="revision" pattern={revisionPattern} required value={revision} onChange={(event) => setRevision(event.target.value)} /></label><label>Feature<input list="route-context-feature-options" name="feature" pattern={identifierInputPattern} required value={feature} onChange={(event) => setFeature(event.target.value)} /><datalist id="route-context-feature-options">{contextFeatures.map((id) => <option key={id} value={id} />)}</datalist></label></div>
      <div className="form-field-grid"><label>Platform<select name="platform" defaultValue="react_native_ios"><option value="react_native_ios">React Native iOS</option><option value="react_native_android">React Native Android</option><option value="ios">iOS</option><option value="android">Android</option><option value="web">Web</option><option value="node">Node</option></select></label><label>Trust level<select name="trust" defaultValue="app_verified"><option value="none">None</option><option value="identity_only">Identity only</option><option value="app_verified">App verified</option><option value="device_verified">Device verified</option><option value="strong_device_verified">Strong device verified</option><option value="debug">Debug</option></select></label></div>
      <label>Normalized claims JSON<textarea defaultValue="{}" name="claims" rows={6} spellCheck={false} /></label>
      <div className="form-field-grid"><label>App version (explanatory)<input maxLength={128} name="app_version" /></label><label>Requested input tokens (explanatory)<input min={0} name="requested_input" type="number" /></label><label>Requested output maximum<input min={0} name="requested_output" type="number" /></label></div>
      <div className="form-field-grid"><label>Rewritten request bytes<input defaultValue={1024} max={104_857_600} min={0} name="rewritten_request_bytes" type="number" /><small>Hypothetical exact post-rewrite body size for reservation projection.</small></label><label>Framing unit count<input defaultValue={1} max={4096} min={0} name="framing_unit_count" type="number" /><small>Messages, input items, or embedding inputs after adapter validation.</small></label></div>
      <label className="check-field"><input defaultChecked name="authenticated" type="checkbox" />Authenticated principal</label><label className="check-field"><input name="streaming" type="checkbox" />Streaming request</label><FormActions busy={busy}>Simulate route</FormActions>
    </form><ProblemNotice problem={problem} />
    {result ? <section className={`simulation-result ${result.allowed ? "simulation-result--allowed" : "simulation-result--denied"}`}><h2>{result.allowed ? "Allowed" : "Denied"}</h2><dl><div><dt>Application</dt><dd>{result.application_id}</dd></div><div><dt>Environment</dt><dd>{result.environment_id} ({result.environment_kind})</dd></div><div><dt>Revision</dt><dd>{result.revision_id}</dd></div><div><dt>Access expression</dt><dd>{result.matched_access_expression ?? "—"}</dd></div><div><dt>Limit plan</dt><dd>{result.limit_plan ?? "—"}</dd></div><div><dt>Route</dt><dd>{result.route ?? "—"}</dd></div><div><dt>Upstream</dt><dd>{result.upstream ?? "—"}</dd></div><div><dt>Physical model</dt><dd>{result.physical_model ?? "—"}</dd></div><div><dt>Pricing</dt><dd>{result.pricing_confidence ?? "—"}</dd></div></dl>
      {result.reservation ? <><h3>Exact conservative reservation</h3><dl><div><dt>Applied output maximum</dt><dd>{result.reservation.applied_output_maximum.toLocaleString()}</dd></div><div><dt>Total token bound</dt><dd>{result.reservation.total_token_bound.toLocaleString()}</dd></div><div><dt>Cost bound</dt><dd>{result.reservation.cost_bound_known ? `${result.reservation.cost_nano_usd_bound.toLocaleString()} nano-USD` : "not applicable / unknown"}</dd></div><div><dt>Input accounting</dt><dd>{result.reservation.input_accounting.required ? `${result.reservation.input_accounting.profile_id}: ${result.reservation.input_accounting.input_token_bound.toLocaleString()} tokens` : "not required"}</dd></div></dl><Table headers={["Metric", "Algorithm", "Units", "Applicable", "Durable"]} rows={result.reservation.allocations.map((allocation) => [allocation.metric, allocation.algorithm, allocation.units, allocation.applicable ? "yes" : "no", allocation.durable ? "yes" : "no"])} /></> : null}
      {result.limits?.length ? <><h3>Applicable limits</h3><Table headers={["Metric", "Algorithm", "Scope", "Window / timezone", "Maximum", "Per request", "Capacity", "Refill / second"]} rows={result.limits.map((limit) => [limit.metric, limit.algorithm, limit.scope.join(", "), [limit.window, limit.timezone].filter(Boolean).join(" / ") || "—", limit.maximum ?? "—", limit.per_request_maximum ?? "—", limit.capacity ?? "—", limit.refill_per_second ?? "—"])} /></> : null}
      <h3>Bounded facts</h3><Table headers={["Fact", "Value"]} rows={[["feature", result.facts.feature], ["platform", result.facts.platform], ["trust_level", result.facts.trust_level], ["authenticated", result.facts.authenticated ? "true" : "false"], ["normalized_claims", JSON.stringify(result.facts.normalized_claims)], ["streaming", result.facts.streaming ? "true" : "false"], ["app_version", result.facts.app_version || "—"], ["requested_input_tokens", result.facts.requested_input_tokens], ["requested_output_max", result.facts.requested_output_max], ["rewritten_request_bytes", result.facts.rewritten_request_bytes], ["framing_unit_count", result.facts.framing_unit_count]]} />
      <h3>Bounded fact roles</h3><Table headers={["Fact", "Role", "Affects CEL", "Meaning"]} rows={result.fact_usage.map((fact) => [fact.fact, fact.role, fact.affects_cel ? "yes" : "no", fact.explanation])} />
      <h3>Explanation</h3><ul>{result.explanation.map((line) => <li key={line}>{line}</li>)}</ul>{result.warnings?.length ? <><h3>Warnings</h3><ul>{result.warnings.map((line) => <li key={line}>{line}</li>)}</ul></> : null}{result.fallback_sequence?.length ? <><h3>Fallback sequence</h3><Table headers={["Route", "Upstream", "Model", "Physical model", "Fallback on"]} rows={result.fallback_sequence.map((candidate) => [candidate.route, candidate.upstream, candidate.model, candidate.physical_model, candidate.fallback_on.join(", ")])} /></> : null}</section> : null}
  </div>;
}

export function SelfTestsPage() {
  const session = useConsoleSession(); const [run, setRun] = useState<SelfTestRun>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false); const [kind, setKind] = useState("local");
  if (session.data?.mode !== "configured") return <AccessRequired />;
  const canRun = session.data.session?.capabilities.includes("run_self_tests") ?? false;
  async function start(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const body: Record<string, string | number> = { kind, environment_id: String(form.get("environment")) };
      if (kind !== "local") {
        body.upstream = String(form.get("upstream")); body.model = String(form.get("model"));
        body.max_cost_nano_usd = Number(form.get("max_cost_nano_usd"));
      }
      setRun((await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body })).data);
    }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  async function refresh(): Promise<void> { if (!run) return; setBusy(true); try { setRun((await adminRequest(`/admin/v1/self-tests/${run.id}`, SelfTestSchema)).data); } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); } }
  return <div className="control-page"><PageHeading eyebrow="Operations" title="Self-tests">Local verification checks durable state. Credential-aware tests use only active server-owned targets and secrets, prove a configured cost ceiling before dispatch, and persist redaction-safe results.</PageHeading>
    <form className="control-form" onSubmit={(event) => void start(event)}><div className="form-field-grid"><label>Environment ID<input name="environment" pattern={environmentInputPattern} required /></label><label>Test kind<select name="kind" onChange={(event) => setKind(event.target.value)} value={kind}><option value="local">Local</option><option value="upstream">Configured upstream</option><option value="openrouter">OpenRouter conformance</option></select></label></div>{kind !== "local" ? <><div className="form-field-grid"><label>Upstream ID<input name="upstream" pattern={identifierInputPattern} required /></label><label>Model ID<input name="model" pattern={identifierInputPattern} required /></label></div><label>Maximum total cost (nano-USD)<input defaultValue={10_000_000} max={1_000_000_000} min={1} name="max_cost_nano_usd" required type="number" /><small>10,000,000 nano-USD = US$0.01. The server refuses dispatch when the configured two-request bound is higher.</small></label></> : null}<button className="primary-action" disabled={!canRun || busy} type="submit">{busy ? "Starting…" : "Run self-test"}</button></form><ProblemNotice problem={problem} />
    {run ? <section className="detail-card"><div className="detail-card__heading"><div><h2>{run.kind} self-test</h2><p>{run.id} · {run.state}</p></div><button className="secondary-action" disabled={busy} onClick={() => void refresh()} type="button">Refresh</button></div><Table headers={["Check", "State", "Safe detail"]} rows={run.checks.map((check) => [check.name, check.state, check.safe_detail ?? "—"])} /></section> : null}
  </div>;
}

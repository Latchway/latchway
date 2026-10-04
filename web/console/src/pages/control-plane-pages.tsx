import { type FormEvent, type ReactNode, useEffect, useState } from "react";

import {
  adminRequest,
  AuditEventSchema,
  AuditPageSchema,
  queryPath,
  SelfTestSchema,
  SelfTestSchedulePageSchema,
  SelfTestScheduleSchema,
  type AuditPage,
  type AuditEvent,
  type EffectiveConfiguration,
  type SelfTestRun,
  type SelfTestSchedule
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { useConsoleCompatibility } from "../app/console-compatibility-context";
import {
  AuditRouteSearchSchema,
  type AuditRouteSearch,
  SelfTestRouteSearchSchema,
  type SelfTestRouteSearch
} from "../app/route-search";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { useAdminRefreshTopic } from "../app/use-admin-refresh";

const environmentPattern = /^env_[A-Za-z0-9_-]{16,128}$/;
const environmentInputPattern = environmentPattern.source;
const revisionPattern = "rev_[A-Za-z0-9_-]{16,128}";
const revisionInputPattern = revisionPattern;
const identifierPattern = /^[a-z][a-z0-9_-]{0,62}$/;
const identifierInputPattern = identifierPattern.source;

type AuditFilterDraft = Record<
  "action" | "actor_id" | "actor_kind" | "end" | "environment_id" | "reason" |
  "resource_id" | "resource_type" | "result" | "source" | "start",
  string
>;

function localDateTime(value?: string): string {
  if (!value) return "";
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return "";
  const local = new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 19);
}

function canonicalInstant(value: string): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : undefined;
}

function auditFilterDraft(search: AuditRouteSearch = {}): AuditFilterDraft {
  return {
    action: search.action ?? "",
    actor_id: search.actor_id ?? "",
    actor_kind: search.actor_kind ?? "",
    end: localDateTime(search.end),
    environment_id: search.environment_id ?? "",
    reason: search.reason ?? "",
    resource_id: search.resource_id ?? "",
    resource_type: search.resource_type ?? "",
    result: search.result ?? "",
    source: search.source ?? "",
    start: localDateTime(search.start)
  };
}

function invalidFilterProblem(detail: string): AdminProblem {
  return { code: "request_invalid", detail, retryable: false, status: 0, title: "Invalid filters" };
}

function present(value: string): string | undefined {
  return value || undefined;
}

function auditSearchCandidate(base: AuditRouteSearch, draft: AuditFilterDraft) {
  return AuditRouteSearchSchema.safeParse({
    ...base,
    action: present(draft.action),
    actor_id: present(draft.actor_id),
    actor_kind: present(draft.actor_kind),
    cursor: undefined,
    end: canonicalInstant(draft.end),
    environment_id: present(draft.environment_id),
    event: undefined,
    reason: present(draft.reason),
    resource_id: present(draft.resource_id),
    resource_type: present(draft.resource_type),
    result: present(draft.result),
    source: present(draft.source),
    start: canonicalInstant(draft.start)
  });
}

function auditSearchPatch(search: AuditRouteSearch): Partial<AuditRouteSearch> {
  return {
    action: search.action,
    actor_id: search.actor_id,
    actor_kind: search.actor_kind,
    cursor: search.cursor,
    end: search.end,
    environment_id: search.environment_id,
    reason: search.reason,
    resource_id: search.resource_id,
    resource_type: search.resource_type,
    result: search.result,
    source: search.source,
    start: search.start
  };
}

function auditListKey(search: AuditRouteSearch): string {
  return JSON.stringify(auditSearchPatch(search));
}

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

export function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? (
    <div className="control-notice control-notice--error" role="alert">
      <strong>{problem.title}</strong>
      <span>{problem.detail}</span>
      <small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}{problem.operationId ? ` · Operation: ${problem.operationId}` : ""}</small>
      {problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}
    </div>
  ) : null;
}

export function AccessRequired() {
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



function FormActions({ busy, children = "Load" }: { busy: boolean; children?: ReactNode }) {
  return <button className="primary-action" disabled={busy} type="submit">{busy ? "Working…" : children}</button>;
}


function effectiveLimitValue(limit: EffectiveConfiguration["limits"][number]): string {
  if (limit.algorithm === "calendar") return `${limit.maximum?.toLocaleString()} / ${limit.window} (${limit.timezone})`;
  if (limit.algorithm === "token_bucket") return `${limit.capacity?.toLocaleString()} capacity · ${limit.refill_per_second}/s`;
  if (limit.algorithm === "per_request") return `${limit.per_request_maximum?.toLocaleString()} / request`;
  return `${limit.maximum?.toLocaleString()} concurrent`;
}

export function EffectiveConfigurationPanel({ configuration }: { configuration: EffectiveConfiguration }) {
  const selectedRoute = configuration.selected_route;
  return <section className="request-explanation" aria-labelledby={`effective-${configuration.subject.id}`}>
    <div className="detail-card__heading"><div><p className="eyebrow">Effective configuration</p><h3 id={`effective-${configuration.subject.id}`}>{configuration.evaluation_mode === "recorded_request" ? "Recorded decision inputs" : "Current-state projection"}</h3></div><span className={`state-badge ${configuration.policy_outcome === "allowed" ? "state-badge--available" : "state-badge--unavailable"}`}><span className="state-badge__dot" aria-hidden="true" />{configuration.policy_outcome}</span></div>
    <p>{configuration.evaluation_mode === "recorded_request" ? "This view uses the immutable revision and durable decision provenance recorded for the request. Missing historical inputs remain unavailable." : "This read-only projection runs the active compiled revision through the production policy resolver. It neither reserves quota nor sends an upstream request."}</p>
    <dl><div><dt>Revision</dt><dd>{configuration.revision_id}</dd></div><div><dt>Environment</dt><dd>{configuration.environment_kind} · {configuration.environment_id}</dd></div><div><dt>Feature / protocol</dt><dd>{configuration.feature}{configuration.protocol ? ` · ${configuration.protocol}` : ""}</dd></div><div><dt>Selected plan</dt><dd>{configuration.limit_plan ?? "Unavailable"}{configuration.limit_plan_source ? ` · ${configuration.limit_plan_source}` : ""}</dd></div><div><dt>Selected route</dt><dd>{selectedRoute ? `${selectedRoute.route} → ${selectedRoute.upstream} / ${selectedRoute.model} (${selectedRoute.physical_model})` : "Unavailable"}</dd></div><div><dt>Component policy</dt><dd>{configuration.component_definition_id ?? "Legacy surface"}{configuration.component_allowed === undefined ? "" : configuration.component_allowed ? " · allowed" : " · denied"}</dd></div></dl>
    {configuration.denial_reason ? <p><strong>Denial reason:</strong> {configuration.denial_reason}</p> : null}
    <h4>Redaction-safe inputs and provenance</h4>
    <Table headers={["Fact", "Availability", "Source", "Visible values", "Explanation"]} rows={configuration.inputs.map((input) => [input.fact, input.availability, input.source, input.keys?.length ? `keys: ${input.keys.join(", ")}` : input.values ? Object.entries(input.values).map(([key, value]) => `${key}=${value}`).join(" · ") : "—", input.detail])} />
    <h4>Effective limits</h4>
    <Table headers={["#", "Metric", "Algorithm", "Scope", "Effective value", "Source"]} rows={configuration.limits.map((limit) => [limit.index + 1, limit.metric, limit.algorithm, limit.scope.join(" + "), effectiveLimitValue(limit), limit.source])} />
    {configuration.output ? <><h4>Output-token clamps</h4><Table headers={["Configured default", "Configured absolute", "Effective default", "Effective maximum", "Requested", "Source"]} rows={[[configuration.output.configured_default_maximum_tokens ?? "—", configuration.output.configured_absolute_maximum_tokens ?? "—", configuration.output.effective_default_maximum_tokens ?? "—", configuration.output.effective_maximum_tokens ?? "—", configuration.output.requested_maximum_tokens ?? "—", configuration.output.source]]} /></> : null}
    <h4>{configuration.evaluation_mode === "recorded_request" ? "Observed routes" : "Ordered eligible routes"}</h4>
    <Table headers={["#", "Route", "Upstream / model", "Priority / weight", "Sticky", "Fallback on", "Retry", "Source"]} rows={configuration.routes.map((route) => [route.order, route.route, `${route.upstream} / ${route.model} → ${route.physical_model}`, `${route.configured_priority} / ${route.configured_weight}`, route.sticky_by ?? "—", route.fallback_on.join(", ") || "—", `${route.retry_maximum_attempts} on ${route.retry_on.join(", ") || "none"}`, route.source])} />
    {configuration.decision_stages.length ? <><h4>Durable decision stages</h4><Table headers={["#", "Stage", "Outcome", "Plan / rule", "Route", "Duration", "Failure"]} rows={configuration.decision_stages.map((stage) => [stage.number, stage.stage, stage.outcome, stage.limit_plan_key ? `${stage.limit_plan_key}${stage.limit_metric ? ` · ${stage.limit_metric}` : ""}` : stage.policy_rule_key ?? "—", stage.route ? `${stage.route} → ${stage.upstream} / ${stage.model}` : "—", `${stage.duration_ms.toLocaleString()} ms`, stage.failure_code ?? "—"])} /></> : null}
    {configuration.matched_access_expression || configuration.matched_limit_plan_expression ? <details><summary>Matched policy expressions</summary><dl><div><dt>Access</dt><dd><code>{configuration.matched_access_expression ?? "Unavailable"}</code></dd></div><div><dt>Limit plan</dt><dd><code>{configuration.matched_limit_plan_expression ?? "Unavailable"}</code></dd></div></dl></details> : null}
    {configuration.warnings.length ? <div className="control-notice"><strong>Important limitations</strong><ul>{configuration.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></div> : null}
    <p><small>Claim values, provider credentials, authorization headers, proofs, and request or response bodies are excluded from this view.</small></p>
  </section>;
}

export function AuditPageView() {
  const session = useConsoleSession(); const workspace = useOptionalWorkspace(); const organization = session.data?.session?.organization_id ?? "";
  const routeSearch = AuditRouteSearchSchema.parse(workspace?.search ?? {});
  const [standaloneSearch, setStandaloneSearch] = useState<AuditRouteSearch>({});
  const activeSearch = workspace ? routeSearch : standaloneSearch;
  const [filters, setFilters] = useState<AuditFilterDraft>(() => auditFilterDraft(routeSearch));
  const [page, setPage] = useState<AuditPage>(); const [selected, setSelected] = useState<AuditEvent>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  const canonicalListKey = auditListKey(routeSearch);
  const canonicalFilterKey = JSON.stringify(auditFilterDraft(routeSearch));

  async function load(search: AuditRouteSearch): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      setPage((await adminRequest(queryPath("/admin/v1/audit-events", {
        action: search.action,
        actor_id: search.actor_id,
        actor_kind: search.actor_kind,
        cursor: search.cursor,
        end: search.end,
        environment_id: search.environment_id,
        organization_id: organization,
        page_size: "50",
        reason: search.reason,
        resource_id: search.resource_id,
        resource_type: search.resource_type,
        result: search.result,
        source: search.source,
        start: search.start
      }), AuditPageSchema)).data);
    }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  async function inspect(eventID: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const event = (await adminRequest(`/admin/v1/audit-events/${eventID}`, AuditEventSchema)).data;
      if (event.id !== eventID) throw new Error("audit_context");
      setSelected(event);
    }
    catch (error) { setProblem(error instanceof Error && error.message === "audit_context" ? { code: "invalid_response", detail: "The audit detail did not match the selected immutable event.", retryable: true, status: 0, title: "Audit detail mismatch" } : problemFromError(error)); } finally { setBusy(false); }
  }

  function selectEvent(eventID: string): void {
    if (workspace) {
      workspace.updateSearch({ event: eventID });
      return;
    }
    void inspect(eventID);
  }

  function updateFilter(name: keyof AuditFilterDraft, value: string): void {
    setFilters((current) => ({ ...current, [name]: value }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const candidate = auditSearchCandidate(activeSearch, filters);
    if (!candidate.success) {
      setProblem(invalidFilterProblem("Review the audit filter formats and ensure the end time is later than the start time."));
      return;
    }
    setProblem(undefined);
    if (workspace) {
      const changed = auditListKey(candidate.data) !== canonicalListKey;
      workspace.updateSearch({ ...auditSearchPatch(candidate.data), event: undefined });
      if (!changed) void load(candidate.data);
      return;
    }
    setStandaloneSearch(candidate.data);
    void load(candidate.data);
  }

  function resetFilters(): void {
    const cleared = AuditRouteSearchSchema.parse({
      application: routeSearch.application,
      environment: routeSearch.environment,
      organization: routeSearch.organization
    });
    setFilters(auditFilterDraft());
    setProblem(undefined);
    if (workspace) {
      workspace.updateSearch({ ...auditSearchPatch(cleared), event: undefined });
      return;
    }
    setStandaloneSearch(cleared);
    void load(cleared);
  }

  function nextPage(cursor: string): void {
    const next = AuditRouteSearchSchema.parse({ ...activeSearch, cursor });
    if (workspace) workspace.updateSearch({ cursor: next.cursor, event: undefined });
    else { setStandaloneSearch(next); void load(next); }
  }

  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    // URL navigation is the external signal that starts the server-side query.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load(routeSearch);
    // The validated URL is the canonical audit query and cursor trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalListKey, organization, session.data?.mode]);

  useEffect(() => {
    if (!workspace) return;
    // Browser back/forward is an external state source for this editable draft.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setFilters(auditFilterDraft(routeSearch));
    // Restore the editable form on navigation, reload, and browser history changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalFilterKey]);

  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    if (routeSearch.event) {
      // URL navigation is the external signal that starts the detail query.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      void inspect(routeSearch.event);
      return;
    }
    // Browser history can independently close the shareable audit detail.
    setSelected(undefined);
    // Inspection is intentionally keyed only by validated URL state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routeSearch.event, session.data?.mode]);

  useAdminRefreshTopic("audit", () => {
    if (session.data?.mode === "configured") void load(activeSearch);
  }, session.data?.mode === "configured");

  if (session.data?.mode !== "configured") return <AccessRequired />;

  return <div className="control-page"><PageHeading eyebrow="Operations" title="Audit log">Append-only, tenant-scoped administrative outcomes with explicit source, environment, reason code, and value-free field changes.</PageHeading>
    <form className="filter-bar filter-bar--wide" onSubmit={applyFilters}>
      <label>Environment<input pattern={environmentInputPattern} placeholder="All environments" value={filters.environment_id} onChange={(event) => updateFilter("environment_id", event.target.value)} /></label>
      <label>Actor kind<select value={filters.actor_kind} onChange={(event) => updateFilter("actor_kind", event.target.value)}><option value="">All</option><option value="admin_user">Administrator</option><option value="admin_api_token">API token</option><option value="system">System</option></select></label>
      <label>Administrator / token<input pattern="(adm|tok)_[A-Za-z0-9_-]{16,128}" placeholder="adm_… or tok_…" value={filters.actor_id} onChange={(event) => updateFilter("actor_id", event.target.value)} /></label>
      <label>Action<input maxLength={100} pattern="[a-z][a-z0-9_.]{0,99}" placeholder="admin.secret_rotate" value={filters.action} onChange={(event) => updateFilter("action", event.target.value)} /></label>
      <label>Resource type<input maxLength={64} pattern="[a-z][a-z0-9_.]{0,63}" placeholder="secret_record" value={filters.resource_type} onChange={(event) => updateFilter("resource_type", event.target.value)} /></label>
      <label>Resource ID<input pattern="[a-z][a-z0-9]{1,15}_[A-Za-z0-9_-]{16,128}" placeholder="sec_…" value={filters.resource_id} onChange={(event) => updateFilter("resource_id", event.target.value)} /></label>
      <label>Descriptive source<select value={filters.source} onChange={(event) => updateFilter("source", event.target.value)}><option value="">All</option><option value="console">Console session</option><option value="cli">CLI claim</option><option value="api">API token</option><option value="system">System</option></select></label>
      <label>Reason code<input maxLength={100} pattern="[a-z][a-z0-9._-]{0,99}" placeholder="operator_reason_provided" value={filters.reason} onChange={(event) => updateFilter("reason", event.target.value)} /></label>
      <label>Result<select value={filters.result} onChange={(event) => updateFilter("result", event.target.value)}><option value="">All</option><option value="succeeded">Succeeded</option><option value="denied">Denied</option><option value="failed">Failed</option><option value="indeterminate">Indeterminate</option></select></label>
      <label>Start<input step="1" type="datetime-local" value={filters.start} onChange={(event) => updateFilter("start", event.target.value)} /></label><label>End<input step="1" type="datetime-local" value={filters.end} onChange={(event) => updateFilter("end", event.target.value)} /></label>
      <FormActions busy={busy}>Apply filters</FormActions><button className="secondary-action" disabled={busy} onClick={resetFilters} type="button">Reset filters</button>
    </form><ProblemNotice problem={problem} />
    {page ? <><Table headers={["Time", "Actor", "Descriptive source", "Environment", "Action", "Target", "Reason", "Result", "Request"]} rows={page.items.map((event) => [time(event.timestamp), event.actor, event.source, event.environment_id ?? "Instance", event.action, <button className="link-button" disabled={busy} onClick={() => selectEvent(event.id)} type="button">{event.target}</button>, event.reason ?? "—", event.result, event.request_id || "—"])} />{page.page.has_more && page.page.next_cursor ? <button className="secondary-action" disabled={busy} onClick={() => nextPage(page.page.next_cursor ?? "")} type="button">Next page</button> : null}</> : null}
    {selected ? <aside className="detail-card"><div className="detail-card__heading"><div><p className="eyebrow">Immutable event</p><h2>Audit detail</h2></div><button className="small-action" onClick={() => { if (workspace) workspace.updateSearch({ event: undefined }); else setSelected(undefined); }} type="button">Close</button></div>
      <dl><div><dt>Event</dt><dd>{selected.id}</dd></div><div><dt>Occurred</dt><dd>{time(selected.timestamp)}</dd></div><div><dt>Actor</dt><dd>{selected.actor}</dd></div><div><dt>Descriptive source</dt><dd>{selected.source}</dd></div><div><dt>Environment</dt><dd>{selected.environment_id ?? "Instance"}</dd></div><div><dt>Reason</dt><dd>{selected.reason ?? "Not supplied"}</dd></div><div><dt>Result</dt><dd>{selected.result}</dd></div><div><dt>Request</dt><dd>{selected.request_id || "—"}</dd></div></dl>
      <h3>Field-level diff</h3><Table headers={["Field", "Operation", "Classification", "Value"]} rows={selected.changes.map((change) => [change.field, change.operation, change.classification, change.redacted ? "Redacted by contract" : "Value not retained"])} />
      <details><summary>Redaction-safe raw JSON</summary><pre>{JSON.stringify(selected, null, 2)}</pre></details>
    </aside> : null}
  </div>;
}

export function SelfTestsPage() {
  const session = useConsoleSession(); const consoleCompatibility = useConsoleCompatibility(); const workspace = useOptionalWorkspace(); const routeSearch = SelfTestRouteSearchSchema.parse(workspace?.search ?? {}); const [run, setRun] = useState<SelfTestRun>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false); const [kind, setKind] = useState("local"); const [runEnvironment, setRunEnvironment] = useState(routeSearch.environment_id ?? "");
  const [scheduleKind, setScheduleKind] = useState<"upstream" | "openrouter">("upstream"); const [scheduleEnvironment, setScheduleEnvironment] = useState(routeSearch.environment_id ?? ""); const [schedules, setSchedules] = useState<SelfTestSchedule[]>(); const [selectedSchedule, setSelectedSchedule] = useState<SelfTestSchedule>();
  const canonicalSearchKey = JSON.stringify({ environment_id: routeSearch.environment_id, schedule_id: routeSearch.schedule_id, self_test_id: routeSearch.self_test_id });
  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    // Browser navigation restores only stable run, schedule, and environment identifiers.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setRunEnvironment(routeSearch.environment_id ?? ""); setScheduleEnvironment(routeSearch.environment_id ?? "");
    if (routeSearch.environment_id) void restoreSelfTests(routeSearch);
    else { setRun(undefined); setSchedules(undefined); setSelectedSchedule(undefined); }
    // The validated URL key is the canonical restore trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalSearchKey, session.data?.mode]);
  useAdminRefreshTopic("self_tests", () => {
    if (session.data?.mode === "configured" && routeSearch.environment_id) void restoreSelfTests(routeSearch);
  }, session.data?.mode === "configured" && Boolean(routeSearch.environment_id));
  if (session.data?.mode !== "configured") return <AccessRequired />;
  const canInspectSelfTests = session.data.session?.capabilities.includes("run_self_tests") ?? false;
  const canRun = consoleCompatibility.mutationAllowed && canInspectSelfTests;
  async function restoreSelfTests(search: SelfTestRouteSearch): Promise<void> {
    if (!search.environment_id) return;
    setBusy(true); setProblem(undefined);
    try {
      let restoredRun: SelfTestRun | undefined;
      if (search.self_test_id) {
        const response = await adminRequest(queryPath(`/admin/v1/self-tests/${search.self_test_id}`, { environment_id: search.environment_id }), SelfTestSchema);
        if (response.data.id !== search.self_test_id || response.data.environment_id !== search.environment_id) throw new Error("self_test_context");
        restoredRun = response.data;
      }
      const page = await adminRequest(queryPath("/admin/v1/self-test-schedules", { environment_id: search.environment_id }), SelfTestSchedulePageSchema);
      if (page.data.items.some((schedule) => schedule.environment_id !== search.environment_id)) throw new Error("self_test_context");
      let restoredSchedule: SelfTestSchedule | undefined;
      if (search.schedule_id) {
        const response = await adminRequest(`/admin/v1/self-test-schedules/${search.schedule_id}`, SelfTestScheduleSchema);
        if (response.data.id !== search.schedule_id || response.data.environment_id !== search.environment_id) throw new Error("self_test_context");
        restoredSchedule = response.data;
      }
      setRun(restoredRun); setSchedules(page.data.items); setSelectedSchedule(restoredSchedule);
    } catch (error) {
      setRun(undefined); setSelectedSchedule(undefined);
      setProblem(error instanceof Error && error.message === "self_test_context" ? { code: "invalid_response", detail: "The self-test run or schedule did not match the selected identifiers and environment.", retryable: true, status: 0, title: "Self-test context mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }
  async function start(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!canRun) return; setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const body: Record<string, string | number> = { kind, environment_id: runEnvironment };
      if (kind !== "local") {
        body.config_revision_id = String(form.get("config_revision_id"));
        body.upstream = String(form.get("upstream")); body.model = String(form.get("model"));
        body.max_cost_nano_usd = Number(form.get("max_cost_nano_usd"));
      }
      const created = (await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body })).data;
      if (created.environment_id !== runEnvironment || (kind !== "local" && created.config_revision_id !== body.config_revision_id)) throw new Error("self_test_context");
      setRun(created);
      if (workspace) workspace.updateSearch({ environment_id: runEnvironment, self_test_id: created.id }, { replace: false });
    }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  async function refresh(): Promise<void> { if (!run) return; setBusy(true); try { const refreshed = (await adminRequest(queryPath(`/admin/v1/self-tests/${run.id}`, { environment_id: run.environment_id }), SelfTestSchema)).data; if (refreshed.id !== run.id || refreshed.environment_id !== run.environment_id) throw new Error("self_test_context"); setRun(refreshed); } catch (error) { setProblem(error instanceof Error && error.message === "self_test_context" ? { code: "invalid_response", detail: "The refreshed self-test did not match the selected run and environment.", retryable: true, status: 0, title: "Self-test context mismatch" } : problemFromError(error)); } finally { setBusy(false); } }
  async function loadSchedules(): Promise<void> {
    if (!environmentPattern.test(scheduleEnvironment)) return;
    const search = SelfTestRouteSearchSchema.parse({ ...routeSearch, environment_id: scheduleEnvironment, schedule_id: undefined });
    if (workspace) {
      const changed = JSON.stringify({ environment_id: search.environment_id, schedule_id: search.schedule_id, self_test_id: search.self_test_id }) !== canonicalSearchKey;
      workspace.updateSearch({ environment_id: search.environment_id, schedule_id: undefined });
      if (!changed) void restoreSelfTests(search);
      return;
    }
    setBusy(true); setProblem(undefined);
    try {
      const page = await adminRequest(queryPath("/admin/v1/self-test-schedules", { environment_id: scheduleEnvironment }), SelfTestSchedulePageSchema);
      if (page.data.items.some((schedule) => schedule.environment_id !== scheduleEnvironment)) throw new Error("self_test_context");
      setSchedules(page.data.items); setSelectedSchedule(page.data.items[0]);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  async function createSchedule(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!canRun) return; setBusy(true); setProblem(undefined); const element = event.currentTarget; const form = new FormData(element); const bearerToken = String(form.get("authorization_token")); const tokenInput = element.elements.namedItem("authorization_token"); if (tokenInput instanceof HTMLInputElement) tokenInput.value = "";
    try {
      const created = (await adminRequest("/admin/v1/self-test-schedules", SelfTestScheduleSchema, { method: "POST", body: {
        daily_cost_limit_nano_usd: Number(form.get("daily_cost_limit_nano_usd")), environment_id: scheduleEnvironment,
        interval_seconds: Number(form.get("interval_seconds")), kind: scheduleKind, max_cost_nano_usd: Number(form.get("max_cost_nano_usd")), model: String(form.get("model")), upstream: String(form.get("upstream"))
      }, bearerToken })).data;
      if (created.environment_id !== scheduleEnvironment) throw new Error("self_test_context");
      setSchedules((current) => [created, ...(current ?? []).filter((item) => item.id !== created.id)]); setSelectedSchedule(created);
      if (workspace) workspace.updateSearch({ environment_id: scheduleEnvironment, schedule_id: created.id }, { replace: false });
    } catch (error) { setProblem(error instanceof Error && error.message === "self_test_context" ? { code: "invalid_response", detail: "The created schedule did not match the selected environment.", retryable: true, status: 0, title: "Self-test context mismatch" } : problemFromError(error)); } finally { if (tokenInput instanceof HTMLInputElement) tokenInput.value = ""; setBusy(false); }
  }
  async function selectSchedule(schedule: SelfTestSchedule): Promise<void> {
    if (workspace) { workspace.updateSearch({ environment_id: schedule.environment_id, schedule_id: schedule.id }, { replace: false }); return; }
    setBusy(true); setProblem(undefined);
    try { const selected = (await adminRequest(`/admin/v1/self-test-schedules/${schedule.id}`, SelfTestScheduleSchema)).data; if (selected.id !== schedule.id || selected.environment_id !== schedule.environment_id) throw new Error("self_test_context"); setSelectedSchedule(selected); }
    catch (error) { setProblem(error instanceof Error && error.message === "self_test_context" ? { code: "invalid_response", detail: "The selected schedule did not match the requested schedule and environment.", retryable: true, status: 0, title: "Self-test context mismatch" } : problemFromError(error)); } finally { setBusy(false); }
  }
  async function disableSchedule(): Promise<void> {
    if (!canRun || !selectedSchedule) return; setBusy(true); setProblem(undefined);
    try {
      const disabled = (await adminRequest(`/admin/v1/self-test-schedules/${selectedSchedule.id}`, SelfTestScheduleSchema, { method: "DELETE" })).data;
      if (disabled.id !== selectedSchedule.id || disabled.environment_id !== selectedSchedule.environment_id) throw new Error("self_test_context");
      setSelectedSchedule(disabled); setSchedules((current) => current?.map((item) => item.id === disabled.id ? disabled : item));
    } catch (error) { setProblem(error instanceof Error && error.message === "self_test_context" ? { code: "invalid_response", detail: "The disabled schedule did not match the selected schedule and environment.", retryable: true, status: 0, title: "Self-test context mismatch" } : problemFromError(error)); } finally { setBusy(false); }
  }
  return <div className="control-page"><PageHeading eyebrow="Operations" title="Self-tests">Local verification checks durable state. Credential-aware tests use only active server-owned targets and secrets, prove a configured cost ceiling before dispatch, and persist redaction-safe results.</PageHeading>
    <form className="control-form" onSubmit={(event) => void start(event)}><div className="form-field-grid"><label>Environment ID<input name="environment" pattern={environmentInputPattern} required value={runEnvironment} onChange={(event) => setRunEnvironment(event.target.value)} /></label><label>Test kind<select name="kind" onChange={(event) => setKind(event.target.value)} value={kind}><option value="local">Local</option><option value="upstream">Configured upstream</option><option value="openrouter">OpenRouter conformance</option></select></label></div>{kind !== "local" ? <><div className="form-field-grid"><label>Configuration revision ID<input name="config_revision_id" pattern={revisionInputPattern} required /></label><label>Upstream ID<input name="upstream" pattern={identifierInputPattern} required /></label><label>Model ID<input name="model" pattern={identifierInputPattern} required /></label></div><label>Maximum total cost (nano-USD)<input defaultValue={10_000_000} max={1_000_000_000} min={1} name="max_cost_nano_usd" required type="number" /><small>10,000,000 nano-USD = US$0.01. The server rejects a revision that is not the exact active revision before any provider dispatch.</small></label></> : null}<button className="primary-action" disabled={!canRun || busy} type="submit">{busy ? "Starting…" : "Run self-test"}</button></form><ProblemNotice problem={problem} />
    {run ? <section className="detail-card"><div className="detail-card__heading"><div><h2>{run.kind} self-test</h2><p>{run.id} · {run.state}</p></div><div className="button-row"><button className="secondary-action" disabled={busy} onClick={() => void refresh()} type="button">Refresh</button><button className="small-action" disabled={busy} onClick={() => { if (workspace) workspace.updateSearch({ self_test_id: undefined }); else setRun(undefined); }} type="button">Close run</button></div></div><Table headers={["Check", "State", "Safe detail"]} rows={run.checks.map((check) => [check.name, check.state, check.safe_detail ?? "—"])} /></section> : null}
    <section className="detail-card"><h2>Scheduled credential-aware self-tests</h2><p>Each schedule pins one active configuration revision and one durable API-token ID. Browser session values and provider secret values are never stored in the schedule.</p>
      <div className="filter-bar"><label>Scheduled environment ID<input pattern={environmentInputPattern} required value={scheduleEnvironment} onChange={(event) => { setScheduleEnvironment(event.target.value); setSchedules(undefined); setSelectedSchedule(undefined); }} /></label><button className="secondary-action" disabled={!canInspectSelfTests || busy || !environmentPattern.test(scheduleEnvironment)} onClick={() => void loadSchedules()} type="button">Load schedules</button></div>
      {canRun ? <form className="control-form" onSubmit={(event) => void createSchedule(event)}><div className="form-field-grid"><label>Scheduled test kind<select value={scheduleKind} onChange={(event) => setScheduleKind(event.target.value as "upstream" | "openrouter")}><option value="upstream">Configured upstream</option><option value="openrouter">OpenRouter conformance</option></select></label><label>Durable Admin API token<input autoComplete="off" maxLength={2048} minLength={32} name="authorization_token" required type="password" /><small>Enter an active token scoped to run_self_tests. It is sent once as Authorization Bearer and cleared immediately; only its stable credential ID is bound.</small></label></div>
        <div className="form-field-grid"><label>Scheduled upstream ID<input name="upstream" pattern={identifierInputPattern} required /></label><label>Scheduled model ID<input name="model" pattern={identifierInputPattern} required /></label></div>
        <div className="form-field-grid"><label>Per-run maximum cost (nano-USD)<input defaultValue={10_000_000} max={1_000_000_000} min={1} name="max_cost_nano_usd" required type="number" /></label><label>UTC-day maximum cost (nano-USD)<input defaultValue={240_000_000} max={10_000_000_000} min={1} name="daily_cost_limit_nano_usd" required type="number" /></label></div>
        <label>Cadence (seconds)<input defaultValue={3600} max={2_592_000} min={3600} name="interval_seconds" required step={1} type="number" /><small>Allowed range: one hour through 30 days. Missed intervals coalesce to one run.</small></label><button className="primary-action" disabled={!canRun || busy || !environmentPattern.test(scheduleEnvironment)} type="submit">Create schedule</button>
      </form> : <div className="control-notice"><strong>Read-only safe mode</strong><span>Scheduled self-test creation is unavailable until Console compatibility is restored.</span></div>}
      {schedules ? <Table headers={["Schedule", "Target", "Cadence", "Per run / UTC day", "State"]} rows={schedules.map((schedule) => [<button className="table-link" onClick={() => void selectSchedule(schedule)} type="button">{schedule.id}</button>, `${schedule.upstream} / ${schedule.model}`, `${schedule.interval_seconds.toLocaleString()} s`, `${schedule.max_cost_nano_usd.toLocaleString()} / ${schedule.daily_cost_limit_nano_usd.toLocaleString()}`, schedule.status])} /> : null}
      {selectedSchedule ? <section className="detail-card"><div className="detail-card__heading"><div><h3>Schedule detail</h3><p>{selectedSchedule.id} · {selectedSchedule.status}</p></div><div className="button-row"><button className="secondary-action" disabled={!canRun || busy || selectedSchedule.status !== "active"} onClick={() => void disableSchedule()} type="button">Disable schedule</button><button className="small-action" disabled={busy} onClick={() => { if (workspace) workspace.updateSearch({ schedule_id: undefined }); else setSelectedSchedule(undefined); }} type="button">Close schedule</button></div></div><dl><div><dt>Application / environment</dt><dd>{selectedSchedule.application_id} / {selectedSchedule.environment_id}</dd></div><div><dt>Pinned configuration</dt><dd>{selectedSchedule.config_revision_id}</dd></div><div><dt>Authorization credential</dt><dd>{selectedSchedule.authorization_credential_id}</dd></div><div><dt>Target</dt><dd>{selectedSchedule.kind}: {selectedSchedule.upstream} / {selectedSchedule.model}</dd></div><div><dt>Cost ceilings</dt><dd>{selectedSchedule.max_cost_nano_usd.toLocaleString()} per run / {selectedSchedule.daily_cost_limit_nano_usd.toLocaleString()} per UTC day</dd></div><div><dt>Cadence</dt><dd>{selectedSchedule.interval_seconds.toLocaleString()} seconds</dd></div><div><dt>Next run</dt><dd>{selectedSchedule.next_run_at ? new Date(selectedSchedule.next_run_at).toLocaleString() : "Disabled"}</dd></div><div><dt>Last run</dt><dd>{selectedSchedule.last_self_test_id ?? "—"}</dd></div></dl></section> : null}
    </section>
  </div>;
}

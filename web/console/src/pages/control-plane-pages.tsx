import { type FormEvent, type ReactNode, useEffect, useState } from "react";

import {
  adminRequest,
  AuditEventSchema,
  AuditPageSchema,
  InstallationPageSchema,
  InstallationSchema,
  getRequestEffectiveConfiguration,
  getUserEffectiveConfiguration,
  getUserOperationImpact,
  queryPath,
  requireApplicationUserAppReverification,
  requireApplicationUserReauthentication,
  RequestPageSchema,
  RequestSchema,
  RevisionSchema,
  RouteSimulationSchema,
  SelfTestSchema,
  SelfTestSchedulePageSchema,
  SelfTestScheduleSchema,
  UsageSummarySchema,
  UsageTimeseriesSchema,
  setApplicationUserBlocked,
  UserSchema,
  UserPageSchema,
  type ApplicationUser,
  type ApplicationUserPage,
  type AuditPage,
  type AuditEvent,
  type EffectiveConfiguration,
  type Installation,
  type InstallationPage,
  type LogicalRequest,
  type LogicalRequestPage,
  type RouteSimulation,
  type SelfTestRun,
  type SelfTestSchedule,
  type UsageSummary,
  type UsageTimeseries,
  type UserOperationAction,
  type UserOperationImpact
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import {
  AnalyticsRouteSearchSchema,
  type AnalyticsRouteSearch,
  AuditRouteSearchSchema,
  type AuditRouteSearch,
  InstallationRouteSearchSchema,
  type InstallationRouteSearch,
  RequestRouteSearchSchema,
  type RequestRouteSearch,
  RouteSimulatorRouteSearchSchema,
  type RouteSimulatorRouteSearch,
  SelfTestRouteSearchSchema,
  type SelfTestRouteSearch,
  UserRouteSearchSchema,
  type UserRouteSearch
} from "../app/route-search";
import { EnvironmentRequired } from "../app/workspace-context";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { useAdminRefreshTopic } from "../app/use-admin-refresh";
import { ImmediateOperationConfirmation } from "../components/immediate-operation-confirmation";

const environmentPattern = /^env_[A-Za-z0-9_-]{16,128}$/;
const environmentInputPattern = environmentPattern.source;
const revisionPattern = "rev_[A-Za-z0-9_-]{16,128}";
const identifierPattern = /^[a-z][a-z0-9_-]{0,62}$/;
const identifierInputPattern = identifierPattern.source;

type RequestFilterDraft = Record<
  "component_kind" | "cost_max_nano_usd" | "cost_min_nano_usd" | "end" | "error_code" |
  "feature" | "latency_max_ms" | "latency_min_ms" | "model" | "platform" | "request_id" |
  "route" | "sort" | "start" | "status" | "tokens_max" | "tokens_min" | "trust_source" |
  "upstream" | "user_id",
  string
>;

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

function requestFilterDraft(search: RequestRouteSearch = {}): RequestFilterDraft {
  return {
    component_kind: search.component_kind ?? "",
    cost_max_nano_usd: search.cost_max_nano_usd ?? "",
    cost_min_nano_usd: search.cost_min_nano_usd ?? "",
    end: localDateTime(search.end),
    error_code: search.error_code ?? "",
    feature: search.feature ?? "",
    latency_max_ms: search.latency_max_ms ?? "",
    latency_min_ms: search.latency_min_ms ?? "",
    model: search.model ?? "",
    platform: search.platform ?? "",
    request_id: search.request_id ?? "",
    route: search.route ?? "",
    sort: search.sort ?? "",
    start: localDateTime(search.start),
    status: search.status ?? "",
    tokens_max: search.tokens_max ?? "",
    tokens_min: search.tokens_min ?? "",
    trust_source: search.trust_source ?? "",
    upstream: search.upstream ?? "",
    user_id: search.user_id ?? ""
  };
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

function requestSearchCandidate(base: RequestRouteSearch, draft: RequestFilterDraft) {
  return RequestRouteSearchSchema.safeParse({
    ...base,
    component_kind: present(draft.component_kind),
    cost_max_nano_usd: present(draft.cost_max_nano_usd),
    cost_min_nano_usd: present(draft.cost_min_nano_usd),
    cursor: undefined,
    end: canonicalInstant(draft.end),
    error_code: present(draft.error_code),
    feature: present(draft.feature),
    latency_max_ms: present(draft.latency_max_ms),
    latency_min_ms: present(draft.latency_min_ms),
    model: present(draft.model),
    platform: present(draft.platform),
    request: undefined,
    request_id: present(draft.request_id),
    route: present(draft.route),
    sort: present(draft.sort),
    start: canonicalInstant(draft.start),
    status: present(draft.status),
    tokens_max: present(draft.tokens_max),
    tokens_min: present(draft.tokens_min),
    trust_source: present(draft.trust_source),
    upstream: present(draft.upstream),
    user_id: present(draft.user_id)
  });
}

function requestSearchPatch(search: RequestRouteSearch): Partial<RequestRouteSearch> {
  return {
    component_kind: search.component_kind,
    cost_max_nano_usd: search.cost_max_nano_usd,
    cost_min_nano_usd: search.cost_min_nano_usd,
    cursor: search.cursor,
    end: search.end,
    error_code: search.error_code,
    feature: search.feature,
    latency_max_ms: search.latency_max_ms,
    latency_min_ms: search.latency_min_ms,
    model: search.model,
    platform: search.platform,
    request: search.request,
    request_id: search.request_id,
    route: search.route,
    sort: search.sort,
    start: search.start,
    status: search.status,
    tokens_max: search.tokens_max,
    tokens_min: search.tokens_min,
    trust_source: search.trust_source,
    upstream: search.upstream,
    user_id: search.user_id
  };
}

function requestListKey(search: RequestRouteSearch): string {
  return JSON.stringify({ ...requestSearchPatch(search), request: undefined });
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

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? (
    <div className="control-notice control-notice--error" role="alert">
      <strong>{problem.title}</strong>
      <span>{problem.detail}</span>
      <small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}</small>
      {problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}
    </div>
  ) : null;
}

function FailureCodeLink({ code }: { code: string }) {
  const documentationURL = `https://docs.latchway.dev/errors/${code.replaceAll("_", "-")}`;
  return <a href={documentationURL} rel="noreferrer" target="_blank">{code}</a>;
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

function effectiveLimitValue(limit: EffectiveConfiguration["limits"][number]): string {
  if (limit.algorithm === "calendar") return `${limit.maximum?.toLocaleString()} / ${limit.window} (${limit.timezone})`;
  if (limit.algorithm === "token_bucket") return `${limit.capacity?.toLocaleString()} capacity · ${limit.refill_per_second}/s`;
  if (limit.algorithm === "per_request") return `${limit.per_request_maximum?.toLocaleString()} / request`;
  return `${limit.maximum?.toLocaleString()} concurrent`;
}

function EffectiveConfigurationPanel({ configuration }: { configuration: EffectiveConfiguration }) {
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

const operationLabels: Record<UserOperationAction, string> = {
  block: "Block user",
  require_app_reverification: "Require app reverification",
  require_reauthentication: "Require reauthentication",
  unblock: "Unblock user"
};

export function UsersPage() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  const routeSearch = UserRouteSearchSchema.parse(workspace?.search ?? {});
  const [environment, setEnvironment] = useState(routeSearch.environment_id ?? "");
  const [page, setPage] = useState<ApplicationUserPage>();
  const [selected, setSelected] = useState<ApplicationUser>();
  const [effective, setEffective] = useState<EffectiveConfiguration>();
  const [effectiveFeature, setEffectiveFeature] = useState("");
  const [effectiveSurface, setEffectiveSurface] = useState<"latest" | "installation" | "component">("latest");
  const [effectiveSurfaceID, setEffectiveSurfaceID] = useState("");
  const [estimatedInputTokens, setEstimatedInputTokens] = useState("");
  const [maximumOutputTokens, setMaximumOutputTokens] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [impact, setImpact] = useState<UserOperationImpact>();
  const [typedConfirmation, setTypedConfirmation] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [reason, setReason] = useState("");
  const [completion, setCompletion] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const canonicalSearchKey = JSON.stringify({ cursor: routeSearch.cursor, environment_id: routeSearch.environment_id, user_id: routeSearch.user_id });
  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    // Browser navigation restores the bounded list and selected pseudonymous user.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setEnvironment(routeSearch.environment_id ?? "");
    if (routeSearch.environment_id) void restore(routeSearch);
    else { setPage(undefined); clearSelectedUser(); }
    // The validated URL key is the canonical restore trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalSearchKey, session.data?.mode]);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  const canMutate = session.data.session?.capabilities.includes("revoke_installations") ?? false;

  function clearSelectedUser(): void {
    setSelected(undefined); setEffective(undefined); setImpact(undefined); setCompletion("");
    setTypedConfirmation(""); setAcknowledged(false); setReason("");
  }

  async function restore(search: UserRouteSearch): Promise<void> {
    if (!search.environment_id) return;
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(
        queryPath("/admin/v1/users", { environment_id: search.environment_id, page_size: "50", cursor: search.cursor }),
        UserPageSchema
      );
      if (result.data.items.some((item) => item.environment_id !== search.environment_id)) throw new Error("user_context");
      let detail: ApplicationUser | undefined;
      if (search.user_id) {
        const response = await adminRequest(queryPath(`/admin/v1/users/${search.user_id}`, { environment_id: search.environment_id }), UserSchema);
        if (response.data.id !== search.user_id || response.data.environment_id !== search.environment_id) throw new Error("user_context");
        detail = response.data;
      }
      setPage(result.data); clearSelectedUser(); setSelected(detail);
    } catch (error) {
      clearSelectedUser();
      setProblem(error instanceof Error && error.message === "user_context" ? { code: "invalid_response", detail: "The user list or detail did not match the selected environment and pseudonymous user ID.", retryable: true, status: 0, title: "User context mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  function selectUser(user: ApplicationUser): void {
    clearSelectedUser();
    if (workspace) workspace.updateSearch({ user_id: user.id }, { replace: false });
    else setSelected(user);
  }

  function applyUserFilters(): void {
    const candidate = UserRouteSearchSchema.safeParse({ ...routeSearch, cursor: undefined, environment_id: environment || undefined, user_id: undefined });
    if (!candidate.success) { setProblem(invalidFilterProblem("Enter a canonical environment ID.")); return; }
    if (workspace) workspace.updateSearch({ cursor: undefined, environment_id: candidate.data.environment_id, user_id: undefined });
    else void restore(candidate.data);
  }

  async function explain(user: ApplicationUser): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const result = await getUserEffectiveConfiguration(user.id, {
        ...(effectiveSurface === "component" ? { componentID: effectiveSurfaceID } : {}),
        environmentID: environment,
        ...(estimatedInputTokens ? { estimatedInputTokens: Number(estimatedInputTokens) } : {}),
        feature: effectiveFeature,
        ...(effectiveSurface === "installation" ? { installationID: effectiveSurfaceID } : {}),
        ...(maximumOutputTokens ? { maximumOutputTokens: Number(maximumOutputTokens) } : {}),
        streaming
      });
      if (result.data.subject.id !== user.id || result.data.environment_id !== environment) throw new Error("effective_context");
      setEffective(result.data);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function reviewOperation(user: ApplicationUser, action: UserOperationAction): Promise<void> {
    setBusy(true); setProblem(undefined); setCompletion("");
    try {
      const result = await getUserOperationImpact(user.id, environment, action);
      setImpact(result.data); setTypedConfirmation(""); setAcknowledged(false); setReason("");
    } catch (error) { setImpact(undefined); setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function performOperation(user: ApplicationUser): Promise<void> {
    if (!impact) return;
    setBusy(true); setProblem(undefined); setCompletion("");
    try {
      const confirmation = { acknowledge_immediate_effect: true as const, impact_token: impact.impact_token, reason };
      const result = impact.action === "block" || impact.action === "unblock"
        ? await setApplicationUserBlocked(user.id, environment, impact.action === "block", confirmation)
        : impact.action === "require_reauthentication"
          ? await requireApplicationUserReauthentication(user.id, environment, confirmation)
          : await requireApplicationUserAppReverification(user.id, environment, confirmation);
      const updated = "operation_id" in result.data ? result.data.user : result.data;
      const operationID = "operation_id" in result.data ? ` Operation ${result.data.operation_id}.` : "";
      setSelected(updated);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === user.id ? updated : item) } : current);
      setCompletion(`${operationLabels[impact.action]} completed.${operationID}`);
      setImpact(undefined); setTypedConfirmation(""); setAcknowledged(false); setReason("");
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="control-page">
    <PageHeading eyebrow="Identity" title="Application users">Pseudonymous identities, normalized claims, status, and overrides. Raw provider subjects and tokens never appear here.</PageHeading>
    <form className="filter-bar" onSubmit={(event) => { event.preventDefault(); applyUserFilters(); }}>
      <label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => { setEnvironment(event.target.value); setPage(undefined); clearSelectedUser(); }} /></label>
      <FormActions busy={busy}>List users</FormActions>
    </form>
    <ProblemNotice problem={problem} />
    {page ? <>
      <Table headers={["User", "Status", "Providers", "Last seen", ""]} rows={page.items.map((user) => [
        <button className="link-button" onClick={() => selectUser(user)} type="button">{user.id}</button>, user.status,
        user.identity_providers.join(", "), time(user.last_seen_at),
        <button className="small-action" onClick={() => selectUser(user)} type="button">Inspect</button>
      ])} />
      {page.page.has_more && page.page.next_cursor ? <button className="secondary-action" disabled={busy} onClick={() => { const next = UserRouteSearchSchema.parse({ ...routeSearch, cursor: page.page.next_cursor, environment_id: environment, user_id: undefined }); if (workspace) workspace.updateSearch({ cursor: next.cursor, environment_id: next.environment_id, user_id: undefined }, { replace: false }); else void restore(next); }} type="button">Next page</button> : null}
    </> : null}
    {selected ? <aside className="detail-card"><div className="detail-card__heading"><h2>User detail</h2><button className="small-action" onClick={() => { if (workspace) workspace.updateSearch({ user_id: undefined }); else clearSelectedUser(); }} type="button">Close</button></div><dl><div><dt>ID</dt><dd>{selected.id}</dd></div><div><dt>Status</dt><dd>{selected.status}</dd></div></dl><p><a className="secondary-action" href={queryPath("/installation-families", { environment_id: environment, user_id: selected.id })}>View this user's installation families</a></p><h3>Normalized safe claims</h3><pre>{JSON.stringify(selected.normalized_claims, null, 2)}</pre>
      <h3>Explain effective access and limits</h3>
      <form className="filter-bar filter-bar--wide" onSubmit={(event) => { event.preventDefault(); void explain(selected); }}>
        <label>Feature<input pattern={identifierInputPattern} required value={effectiveFeature} onChange={(event) => setEffectiveFeature(event.target.value)} /></label>
        <label>Client surface<select value={effectiveSurface} onChange={(event) => { setEffectiveSurface(event.target.value as typeof effectiveSurface); setEffectiveSurfaceID(""); }}><option value="latest">Latest active session</option><option value="installation">Installation</option><option value="component">Component</option></select></label>
        {effectiveSurface !== "latest" ? <label>{effectiveSurface === "installation" ? "Installation ID" : "Component ID"}<input required value={effectiveSurfaceID} onChange={(event) => setEffectiveSurfaceID(event.target.value)} /></label> : null}
        <label>Estimated input tokens<input min="0" max="2147483647" step="1" type="number" value={estimatedInputTokens} onChange={(event) => setEstimatedInputTokens(event.target.value)} /></label>
        <label>Requested output tokens<input min="0" max="2147483647" step="1" type="number" value={maximumOutputTokens} onChange={(event) => setMaximumOutputTokens(event.target.value)} /></label>
        <label><input checked={streaming} onChange={(event) => setStreaming(event.target.checked)} type="checkbox" /> Streaming request</label>
        <FormActions busy={busy}>Explain current state</FormActions>
      </form>
      {effective ? <EffectiveConfigurationPanel configuration={effective} /> : null}
      <h3>Sensitive user operations</h3>
      <p>Every operation starts with a fresh application-wide impact preview. State changes between review and confirmation are rejected.</p>
      <div className="button-row"><button className="secondary-action" disabled={!canMutate || busy} onClick={() => void reviewOperation(selected, selected.status === "blocked" ? "unblock" : "block")} type="button">Review {selected.status === "blocked" ? "unblock" : "block"}</button><button className="secondary-action" disabled={!canMutate || busy} onClick={() => void reviewOperation(selected, "require_reauthentication")} type="button">Review reauthentication</button><button className="secondary-action" disabled={!canMutate || busy} onClick={() => void reviewOperation(selected, "require_app_reverification")} type="button">Review app reverification</button></div>
      {impact ? <section className="request-explanation"><h4>{operationLabels[impact.action]} impact</h4><p>{impact.summary}</p><dl><div><dt>Immediate</dt><dd>{impact.immediate ? "Yes" : "No"}</dd></div><div><dt>Reversible</dt><dd>{impact.reversible ? "Yes" : "No"}</dd></div><div><dt>Current status</dt><dd>{impact.current_status}</dd></div><div><dt>Access effect</dt><dd>{impact.access_effect}</dd></div></dl><Table headers={["Active user sessions", "User refresh tokens", "Component sessions", "Component refresh tokens", "Installation families", "Client components"]} rows={[[impact.counts.active_session_grants, impact.counts.active_refresh_tokens, impact.counts.active_component_sessions, impact.counts.active_component_refresh_tokens, impact.counts.active_installation_families, impact.counts.active_client_components]]} />
        {!impact.applicable ? <p role="status">This operation does not apply to the user's current state. Review a different action.</p> : <form onSubmit={(event) => { event.preventDefault(); void performOperation(selected); }}><label>Operator reason<textarea maxLength={500} required value={reason} onChange={(event) => setReason(event.target.value)} /></label><label>Type the exact user ID to confirm<input required value={typedConfirmation} onChange={(event) => setTypedConfirmation(event.target.value)} /></label><label><input checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" /> I acknowledge the immediate application-wide effect described above.</label><button className="primary-action" disabled={busy || !acknowledged || typedConfirmation !== selected.id || !reason.trim()} type="submit">Confirm {operationLabels[impact.action]}</button></form>}
      </section> : null}
      {completion ? <p className="control-notice" role="status">{completion}</p> : null}
    </aside> : null}
  </div>;
}

export function InstallationsPage() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  const routeSearch = InstallationRouteSearchSchema.parse(workspace?.search ?? {});
  const [environment, setEnvironment] = useState(routeSearch.environment_id ?? "");
  const [page, setPage] = useState<InstallationPage>();
  const [selected, setSelected] = useState<Installation>();
  const [revocationTarget, setRevocationTarget] = useState<Installation>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const canonicalSearchKey = JSON.stringify({ cursor: routeSearch.cursor, environment_id: routeSearch.environment_id, installation_id: routeSearch.installation_id });
  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    // Browser navigation restores the bounded list and selected legacy installation.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setEnvironment(routeSearch.environment_id ?? "");
    setRevocationTarget(undefined);
    if (routeSearch.environment_id) void restore(routeSearch);
    else { setPage(undefined); setSelected(undefined); }
    // The validated URL key is the canonical restore trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalSearchKey, session.data?.mode]);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  const canRevoke = session.data.session?.capabilities.includes("revoke_installations") ?? false;

  async function restore(search: InstallationRouteSearch): Promise<void> {
    if (!search.environment_id) return;
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(queryPath("/admin/v1/installations", { environment_id: search.environment_id, page_size: "50", cursor: search.cursor }), InstallationPageSchema);
      if (result.data.items.some((item) => item.environment_id !== search.environment_id)) throw new Error("installation_context");
      let detail: Installation | undefined;
      if (search.installation_id) {
        const response = await adminRequest(`/admin/v1/installations/${search.installation_id}`, InstallationSchema);
        if (response.data.id !== search.installation_id || response.data.environment_id !== search.environment_id) throw new Error("installation_context");
        detail = response.data;
      }
      setPage(result.data); setSelected(detail); setRevocationTarget(undefined);
    } catch (error) {
      setSelected(undefined); setRevocationTarget(undefined);
      setProblem(error instanceof Error && error.message === "installation_context" ? { code: "invalid_response", detail: "The installation list or detail did not match the selected environment and installation ID.", retryable: true, status: 0, title: "Installation context mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }
  function applyInstallationFilters(): void {
    const candidate = InstallationRouteSearchSchema.safeParse({ ...routeSearch, cursor: undefined, environment_id: environment || undefined, installation_id: undefined });
    if (!candidate.success) { setProblem(invalidFilterProblem("Enter a canonical environment ID.")); return; }
    if (workspace) workspace.updateSearch({ cursor: undefined, environment_id: candidate.data.environment_id, installation_id: undefined });
    else void restore(candidate.data);
  }
  function selectInstallation(installation: Installation): void {
    setRevocationTarget(undefined);
    if (workspace) workspace.updateSearch({ installation_id: installation.id }, { replace: false });
    else setSelected(installation);
  }
  async function revoke(installation: Installation, reason: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(`/admin/v1/installations/${installation.id}/revoke`, InstallationSchema, { method: "POST", body: { reason } });
      if (result.data.id !== installation.id || result.data.environment_id !== environment) throw new Error("installation_context");
      setSelected((current) => current?.id === installation.id ? result.data : current);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === installation.id ? result.data : item) } : current);
      setRevocationTarget(undefined);
    } catch (error) { setProblem(error instanceof Error && error.message === "installation_context" ? { code: "invalid_response", detail: "The revoked installation response did not match the selected environment and installation ID.", retryable: true, status: 0, title: "Installation context mismatch" } : problemFromError(error)); } finally { setBusy(false); }
  }
  return <div className="control-page">
    <PageHeading eyebrow="Identity" title="Installations">Installation-bound public keys and normalized trust status without raw attestation evidence or DPoP proofs.</PageHeading>
    <form className="filter-bar" onSubmit={(event) => { event.preventDefault(); applyInstallationFilters(); }}>
      <label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => { setEnvironment(event.target.value); setPage(undefined); setSelected(undefined); setRevocationTarget(undefined); }} /></label><FormActions busy={busy}>List installations</FormActions>
    </form>
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Installation", "Platform", "Status", "Trust", "Last seen", ""]} rows={page.items.map((item) => [
      <button className="link-button" onClick={() => selectInstallation(item)} type="button">{item.id}</button>, item.platform, item.status, item.trust_level, time(item.last_seen_at),
      <button className="small-action" disabled={!canRevoke || busy || item.status === "revoked"} onClick={() => setRevocationTarget(item)} type="button">Review revoke</button>
    ])} />{page.page.has_more && page.page.next_cursor ? <button className="secondary-action" disabled={busy} onClick={() => { const next = InstallationRouteSearchSchema.parse({ ...routeSearch, cursor: page.page.next_cursor, environment_id: environment, installation_id: undefined }); if (workspace) workspace.updateSearch({ cursor: next.cursor, environment_id: next.environment_id, installation_id: undefined }, { replace: false }); else void restore(next); }} type="button">Next page</button> : null}</> : null}
    {revocationTarget ? <ImmediateOperationConfirmation acknowledgement="I understand this immediately and permanently revokes this installation's trust and credential boundary." affectedScope={<><code>{revocationTarget.id}</code>, its sessions, refresh tokens, and attestation keys</>} busy={busy} confirmLabel="Revoke installation credentials" credentialRestoration="Never. Revoked sessions, refresh tokens, and attestation keys stay revoked; the client must establish a new installation identity." heading="Revoke this installation?" key={revocationTarget.id} onCancel={() => setRevocationTarget(undefined)} onConfirm={(reason) => { if (reason) void revoke(revocationTarget, reason); }} requiresReason reversibility="No. Installation revocation is terminal." summary="The server revokes this installation together with its active sessions, refresh tokens, and attestation keys in one operation." timing="Immediately after the server accepts the revocation" /> : null}
    {selected ? <aside className="detail-card"><div className="detail-card__heading"><h2>Installation detail</h2><button className="small-action" onClick={() => { setRevocationTarget(undefined); if (workspace) workspace.updateSearch({ installation_id: undefined }); else setSelected(undefined); }} type="button">Close</button></div><dl><div><dt>User</dt><dd>{selected.user_id}</dd></div><div><dt>Trust provider</dt><dd>{selected.attestation_provider ?? "—"}</dd></div><div><dt>Trust expires</dt><dd>{time(selected.trust_expires_at)}</dd></div><div><dt>Revoked</dt><dd>{time(selected.revoked_at)}</dd></div></dl></aside> : null}
  </div>;
}

function RequestTimeline({ request }: { request: LogicalRequest }) {
  const fallbackUsed = request.attempts.length > 1;
  return <section className="request-explanation" aria-labelledby="execution-timeline-heading"><div className="detail-card__heading"><div><p className="eyebrow">Explain this request</p><h3 id="execution-timeline-heading">Durable execution timeline</h3></div><span className={`state-badge ${request.status === "succeeded" ? "state-badge--available" : "state-badge--unavailable"}`}><span className="state-badge__dot" aria-hidden="true" />{request.status}</span></div>
    {request.decision_stages.length === 0 ? <p className="control-notice">This legacy request has no durable decision stages. The console does not reconstruct them from current state.</p> : <ol className="execution-timeline">{request.decision_stages.map((stage) => <li className={stage.outcome === "succeeded" ? "execution-timeline__success" : "execution-timeline__warning"} key={stage.number}><span aria-hidden="true">{stage.outcome === "succeeded" ? "✓" : "!"}</span><div><strong>{stage.stage.replaceAll("_", " ")} {stage.outcome}</strong><small>{stage.duration_ms.toLocaleString()} ms · revision {stage.config_revision_id}{stage.limit_plan_key ? ` · plan ${stage.limit_plan_key}` : ""}{stage.limit_metric ? ` · ${stage.limit_metric} ${stage.limit_algorithm} ${stage.limit_maximum}` : ""}{stage.route ? ` · ${stage.route} → ${stage.upstream} / ${stage.model}` : ""}{stage.failure_code ? <> · <FailureCodeLink code={stage.failure_code} /></> : null}</small></div></li>)}</ol>}
    {request.attempts.length ? <><h4>Upstream attempts</h4><ol className="execution-timeline">{request.attempts.map((attempt) => <li className={attempt.status === "succeeded" ? "execution-timeline__success" : "execution-timeline__warning"} key={attempt.id}><span aria-hidden="true">{attempt.status === "succeeded" ? "✓" : "!"}</span><div><strong>{attempt.attempt_number === 1 ? "Primary" : "Fallback"} upstream {attempt.status}</strong><small>{attempt.route} → {attempt.upstream} / {attempt.model} · {duration(attempt.started_at, attempt.completed_at)}{attempt.failure_code ? <> · <FailureCodeLink code={attempt.failure_code} /></> : null}</small></div></li>)}</ol></> : null}
    <div className="why-grid"><article><strong>Why this outcome?</strong><p>{request.decision_stages.length ? <>The durable lifecycle ended {request.status}{request.failure_code ? <> with <FailureCodeLink code={request.failure_code} /></> : null}. Each stage above is recorded, not inferred.</> : "Exact historical policy and quota inputs are unavailable for this legacy request."}</p></article><article><strong>Why this route?</strong><p>{request.selected_route ? `Pre-dispatch selection recorded ${request.selected_route} → ${request.selected_upstream} / ${request.selected_model}.` : "No durable pre-dispatch route selection was recorded."}{fallbackUsed ? ` The observed fallback sequence ended on ${request.attempts.at(-1)?.route}.` : ""}</p></article><article><strong>Cost confidence</strong><p>{request.attempts.some((attempt) => attempt.cost_provenance === "estimated") ? "At least one attempt uses estimated cost; do not treat the total as provider-reported." : "Attempt rows preserve independent usage and cost provenance."}</p></article></div>
  </section>;
}

function RequestsWorkspacePage() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  const [environment, setEnvironment] = useState("");
  const routeSearch = RequestRouteSearchSchema.parse(workspace?.search ?? {});
  const [standaloneSearch, setStandaloneSearch] = useState<RequestRouteSearch>({});
  const activeSearch = workspace ? routeSearch : standaloneSearch;
  const [filters, setFilters] = useState<RequestFilterDraft>(() => requestFilterDraft(routeSearch));
  const [page, setPage] = useState<LogicalRequestPage>();
  const [selected, setSelected] = useState<LogicalRequest>();
  const [effective, setEffective] = useState<EffectiveConfiguration>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const [detailBusy, setDetailBusy] = useState(false);
  const effectiveEnvironment = workspace?.environment?.id ?? environment;
  const canonicalListKey = requestListKey(routeSearch);
  const canonicalFilterKey = JSON.stringify(requestFilterDraft(routeSearch));

  async function load(search: RequestRouteSearch, selectedEnvironment = effectiveEnvironment): Promise<void> {
    if (!selectedEnvironment) return;
    setBusy(true); setProblem(undefined);
    try {
      const result = await adminRequest(queryPath("/admin/v1/requests", {
        component_kind: search.component_kind,
        cost_max_nano_usd: search.cost_max_nano_usd,
        cost_min_nano_usd: search.cost_min_nano_usd,
        cursor: search.cursor,
        end: search.end,
        environment_id: selectedEnvironment,
        error_code: search.error_code,
        feature: search.feature,
        latency_max_ms: search.latency_max_ms,
        latency_min_ms: search.latency_min_ms,
        model: search.model,
        page_size: "50",
        platform: search.platform,
        request_id: search.request_id,
        route: search.route,
        sort: search.sort,
        start: search.start,
        status: search.status,
        tokens_max: search.tokens_max,
        tokens_min: search.tokens_min,
        trust_source: search.trust_source,
        upstream: search.upstream,
        user_id: search.user_id
      }), RequestPageSchema);
      setPage(result.data);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function loadRequest(requestID: string, selectedEnvironment = effectiveEnvironment): Promise<void> {
    if (!selectedEnvironment) return;
    setDetailBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/requests/${requestID}`, RequestSchema);
      if (response.data.id !== requestID || response.data.environment_id !== selectedEnvironment) throw new Error("request_context");
      setSelected(response.data); setEffective(undefined);
    }
    catch (error) {
      setSelected(undefined);
      setProblem(error instanceof Error && error.message === "request_context" ? { code: "invalid_response", detail: "The request detail did not match the selected request and environment.", retryable: true, status: 0, title: "Request detail mismatch" } : problemFromError(error));
    }
    finally { setDetailBusy(false); }
  }

  async function explainRequest(request: LogicalRequest): Promise<void> {
    setDetailBusy(true); setProblem(undefined);
    try {
      const response = await getRequestEffectiveConfiguration(request.id);
      if (response.data.subject.id !== request.id || response.data.environment_id !== request.environment_id || response.data.revision_id !== request.config_revision_id) throw new Error("request_context");
      setEffective(response.data);
    } catch (error) {
      setEffective(undefined);
      setProblem(error instanceof Error && error.message === "request_context" ? { code: "invalid_response", detail: "The recorded explanation did not match the selected request, environment, and revision.", retryable: true, status: 0, title: "Request explanation mismatch" } : problemFromError(error));
    } finally { setDetailBusy(false); }
  }

  function updateFilter(name: keyof RequestFilterDraft, value: string): void {
    setFilters((current) => ({ ...current, [name]: value }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const candidate = requestSearchCandidate(activeSearch, filters);
    if (!candidate.success) {
      setProblem(invalidFilterProblem("Review the filter formats and ensure every maximum is at least its corresponding minimum."));
      return;
    }
    setProblem(undefined);
    if (workspace) {
      const changed = requestListKey(candidate.data) !== canonicalListKey || routeSearch.request !== undefined;
      workspace.updateSearch(requestSearchPatch(candidate.data));
      if (!changed) void load(candidate.data, workspace.environment?.id);
      return;
    }
    setStandaloneSearch(candidate.data);
    void load(candidate.data);
  }

  function resetFilters(): void {
    const cleared = RequestRouteSearchSchema.parse({
      application: routeSearch.application,
      environment: routeSearch.environment,
      organization: routeSearch.organization
    });
    setFilters(requestFilterDraft());
    setProblem(undefined);
    if (workspace) {
      workspace.updateSearch(requestSearchPatch(cleared));
      return;
    }
    setStandaloneSearch(cleared);
    void load(cleared);
  }

  function nextPage(cursor: string): void {
    const next = RequestRouteSearchSchema.parse({ ...activeSearch, cursor, request: undefined });
    if (workspace) workspace.updateSearch({ cursor: next.cursor, request: undefined });
    else { setStandaloneSearch(next); void load(next); }
  }

  function selectRequest(requestID: string): void {
    if (workspace) {
      if (routeSearch.request === requestID) void loadRequest(requestID, workspace.environment?.id);
      else workspace.updateSearch({ request: requestID });
      return;
    }
    void loadRequest(requestID);
  }

  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace?.environment?.id) return;
    // URL navigation is the external signal that starts the server-side query.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load(routeSearch, workspace.environment.id);
    // The validated URL is the canonical list trigger, including cursor changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace?.environment?.id, canonicalListKey, session.data?.mode]);

  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace?.environment?.id) return;
    if (!routeSearch.request) {
      // Browser history can independently close the shareable request detail.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSelected(undefined); setEffective(undefined);
      return;
    }
    // URL navigation is the external signal that starts the detail query.
    void loadRequest(routeSearch.request, workspace.environment.id);
    // Request selection is independently shareable and must not reload the list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace?.environment?.id, routeSearch.request, session.data?.mode]);

  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    // Browser back/forward is an external state source for this editable draft.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setFilters(requestFilterDraft(routeSearch));
    // Keep the editable form synchronized with browser back/forward and reload.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalFilterKey]);

  useAdminRefreshTopic("requests", () => {
    if (session.data?.mode !== "configured" || !effectiveEnvironment) return;
    void load(activeSearch, effectiveEnvironment);
    if (routeSearch.request) void loadRequest(routeSearch.request, effectiveEnvironment);
  }, session.data?.mode === "configured" && Boolean(effectiveEnvironment));

  if (session.data?.mode !== "configured") return <AccessRequired />;

  return <div className="control-page">
    <PageHeading eyebrow="Requests" title="Understand what happened.">Inspect identity, client trust, the selected feature, upstream attempts, usage, and cost provenance. Prompt and response bodies remain excluded.</PageHeading>
    {workspace?.environment ? <section className={`production-context production-context--${workspace.environment.kind}`}><strong>{workspace.application?.display_name} / {workspace.environment.display_name}</strong><span>Server-side filters and pagination · shareable URL state</span><code>{workspace.environment.id}</code><button className="secondary-action" disabled={busy} onClick={() => void load(routeSearch, workspace.environment?.id)} type="button">Refresh requests</button></section> : null}
    <form className="filter-bar filter-bar--wide" onSubmit={applyFilters}>
      {!workspace ? <label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></label> : null}
      <label>Status<select value={filters.status} onChange={(event) => updateFilter("status", event.target.value)}><option value="">All</option><option value="succeeded">Succeeded</option><option value="failed">Failed</option><option value="denied">Denied</option><option value="canceled">Canceled</option><option value="unknown">Unknown</option></select></label>
      <label>Feature<input pattern={identifierInputPattern} value={filters.feature} onChange={(event) => updateFilter("feature", event.target.value)} /></label>
      <label>User ID<input pattern="usr_[A-Za-z0-9_-]{16,128}" value={filters.user_id} onChange={(event) => updateFilter("user_id", event.target.value)} /></label>
      <label>Platform<select value={filters.platform} onChange={(event) => updateFilter("platform", event.target.value)}><option value="">All</option><option value="ios">iOS</option><option value="android">Android</option><option value="web">Web</option><option value="react_native_ios">React Native iOS</option><option value="react_native_android">React Native Android</option><option value="node">Node.js</option></select></label>
      <label>Component kind<input pattern={identifierInputPattern} value={filters.component_kind} onChange={(event) => updateFilter("component_kind", event.target.value)} /></label>
      <label>Trust source<input pattern={identifierInputPattern} value={filters.trust_source} onChange={(event) => updateFilter("trust_source", event.target.value)} /></label>
      <label>Route<input pattern={identifierInputPattern} value={filters.route} onChange={(event) => updateFilter("route", event.target.value)} /></label>
      <label>AI connection<input pattern={identifierInputPattern} value={filters.upstream} onChange={(event) => updateFilter("upstream", event.target.value)} /></label>
      <label>Model<input maxLength={512} value={filters.model} onChange={(event) => updateFilter("model", event.target.value)} /></label>
      <label>Error code<input pattern="[a-z][a-z0-9_]{0,99}" value={filters.error_code} onChange={(event) => updateFilter("error_code", event.target.value)} /></label>
      <label>Request ID<input pattern="req_[A-Za-z0-9_-]{16,128}" value={filters.request_id} onChange={(event) => updateFilter("request_id", event.target.value)} /></label>
      <label>Start<input step="1" type="datetime-local" value={filters.start} onChange={(event) => updateFilter("start", event.target.value)} /></label>
      <label>End<input step="1" type="datetime-local" value={filters.end} onChange={(event) => updateFilter("end", event.target.value)} /></label>
      <label>Latency minimum (ms)<input inputMode="numeric" min="0" type="number" value={filters.latency_min_ms} onChange={(event) => updateFilter("latency_min_ms", event.target.value)} /></label>
      <label>Latency maximum (ms)<input inputMode="numeric" min="0" type="number" value={filters.latency_max_ms} onChange={(event) => updateFilter("latency_max_ms", event.target.value)} /></label>
      <label>Token minimum<input inputMode="numeric" min="0" type="number" value={filters.tokens_min} onChange={(event) => updateFilter("tokens_min", event.target.value)} /></label>
      <label>Token maximum<input inputMode="numeric" min="0" type="number" value={filters.tokens_max} onChange={(event) => updateFilter("tokens_max", event.target.value)} /></label>
      <label>Cost minimum (nano-USD)<input inputMode="numeric" min="0" type="number" value={filters.cost_min_nano_usd} onChange={(event) => updateFilter("cost_min_nano_usd", event.target.value)} /></label>
      <label>Cost maximum (nano-USD)<input inputMode="numeric" min="0" type="number" value={filters.cost_max_nano_usd} onChange={(event) => updateFilter("cost_max_nano_usd", event.target.value)} /></label>
      <label>Sort<select value={filters.sort} onChange={(event) => updateFilter("sort", event.target.value)}><option value="">Newest first (default)</option><option value="started_at_desc">Newest first</option><option value="started_at_asc">Oldest first</option></select></label>
      <FormActions busy={busy}>{workspace ? "Apply filters" : "List requests"}</FormActions><button className="secondary-action" disabled={busy} onClick={resetFilters} type="button">Reset filters</button>
    </form>
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Time", "Status", "Feature", "User", "Component / trust", "Selected route / model", "Latency", "Tokens", "Cost"]} rows={page.items.map((request) => { const attempt = request.attempts.at(-1); return [time(request.started_at), <button aria-label={request.id} className="link-button" disabled={detailBusy} onClick={() => selectRequest(request.id)} type="button">{request.status}<br /><small>{request.id}</small></button>, request.feature, request.user_id, `${request.component_kind ?? "legacy"} · ${request.trust_source ?? "legacy trust"}`, request.selected_route ? `${request.selected_route} → ${request.selected_model}` : attempt ? `${attempt.route} → ${attempt.model} (observed)` : "Unavailable", duration(request.started_at, request.completed_at), request.usage?.total_tokens.toLocaleString() ?? "—", request.usage ? `${request.usage.cost_nano_usd.toLocaleString()} nUSD` : "—"]; })} />{page.page.has_more && page.page.next_cursor ? <button className="secondary-action" disabled={busy} onClick={() => nextPage(page.page.next_cursor ?? "")} type="button">Next page</button> : null}</> : null}
    {detailBusy ? <p role="status">Loading exact request detail…</p> : null}
    {selected ? <aside className="detail-card request-detail"><div className="detail-card__heading"><h2>Request detail</h2><button className="small-action" onClick={() => { setSelected(undefined); setEffective(undefined); workspace?.updateSearch({ request: undefined }); }} type="button">Close detail</button></div>
      <dl><div><dt>Request</dt><dd>{selected.id}</dd></div><div><dt>Environment</dt><dd>{selected.environment_id}</dd></div><div><dt>Configuration revision</dt><dd>{selected.config_revision_id}</dd></div><div><dt>Selected limit plan</dt><dd>{selected.selected_limit_plan}</dd></div><div><dt>Pre-dispatch route</dt><dd>{selected.selected_route ? `${selected.selected_route} → ${selected.selected_upstream} / ${selected.selected_model} (${selected.selected_physical_model})` : "Unavailable"}</dd></div><div><dt>Feature</dt><dd>{selected.feature}</dd></div><div><dt>Protocol</dt><dd>{selected.protocol}</dd></div><div><dt>Status</dt><dd>{selected.status}{selected.failure_code ? <> · <FailureCodeLink code={selected.failure_code} /></> : null}</dd></div><div><dt>Started</dt><dd>{time(selected.started_at)}</dd></div><div><dt>Completed</dt><dd>{time(selected.completed_at)}</dd></div><div><dt>Duration</dt><dd>{duration(selected.started_at, selected.completed_at)}</dd></div></dl>
      <RequestTimeline request={selected} />
      <p><button className="secondary-action" disabled={detailBusy} onClick={() => void explainRequest(selected)} type="button">Explain recorded configuration</button></p>
      {effective ? <EffectiveConfigurationPanel configuration={effective} /> : null}
      <h3>Client attribution</h3><dl><div><dt>Installation</dt><dd>{selected.installation_id}</dd></div><div><dt>Installation Family</dt><dd>{selected.installation_family_id ?? "legacy request"}</dd></div><div><dt>Client component</dt><dd>{selected.client_component_id ?? "legacy request"}</dd></div><div><dt>Component definition</dt><dd>{selected.component_definition_id ?? "legacy request"}</dd></div><div><dt>Component kind</dt><dd>{selected.component_kind ?? "legacy request"}</dd></div><div><dt>Trust source</dt><dd>{selected.trust_source ?? "legacy request"}</dd></div><div><dt>Framework</dt><dd>{selected.framework ? `${selected.framework}${selected.framework_version ? ` ${selected.framework_version}` : ""}` : "raw transport"}</dd></div><div><dt>Framework version</dt><dd>{selected.framework_version ?? "—"}</dd></div></dl>
      <h3>Aggregate usage</h3><Table headers={["Logical requests", "Input tokens", "Output tokens", "Total tokens", "Cost nano-USD"]} rows={selected.usage ? [[selected.usage.logical_requests, selected.usage.input_tokens, selected.usage.output_tokens, selected.usage.total_tokens, selected.usage.cost_nano_usd]] : []} />
      <h3>Ordered upstream attempts</h3><Table headers={["#", "Attempt", "Route", "Started", "First byte", "First token", "TTFT", "Completed", "Duration", "Upstream", "Model", "Status", "HTTP", "Failure", "Input", "Output", "Total", "Cost nUSD", "Usage provenance", "Cost provenance", "Cost source"]} rows={selected.attempts.map((attempt) => [attempt.attempt_number, attempt.id, attempt.route, time(attempt.started_at), time(attempt.first_byte_at), time(attempt.first_token_at), duration(attempt.started_at, attempt.first_token_at), time(attempt.completed_at), duration(attempt.started_at, attempt.completed_at), attempt.upstream, attempt.model, attempt.status, attempt.http_status ?? "—", attempt.failure_code ? <FailureCodeLink code={attempt.failure_code} /> : "—", attempt.usage?.input_tokens ?? "—", attempt.usage?.output_tokens ?? "—", attempt.usage?.total_tokens ?? "—", attempt.usage?.cost_nano_usd ?? "—", attempt.usage_provenance, attempt.cost_provenance, attempt.cost_source ?? "—"])} />
      <p><small>Failure categories are a closed, sanitized vocabulary; unrecognized durable values appear as unknown. Prompt/response bodies, provider error text, raw internal errors, and identity subjects remain excluded.</small></p>
    </aside> : null}
  </div>;
}

export function RequestsPage() {
  return <EnvironmentRequired><RequestsWorkspacePage /></EnvironmentRequired>;
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
  const workspace = useOptionalWorkspace();
  const routeSearch = AnalyticsRouteSearchSchema.parse(workspace?.search ?? {});
  const now = new Date(); const yesterday = new Date(now.getTime() - 86_400_000);
  const [environment, setEnvironment] = useState(routeSearch.environment_id ?? "");
  const [start, setStart] = useState(localDateTime(routeSearch.start) || yesterday.toISOString().slice(0, 16));
  const [end, setEnd] = useState(localDateTime(routeSearch.end) || now.toISOString().slice(0, 16));
  const [interval, setInterval] = useState<"hour" | "day">(routeSearch.interval ?? "hour");
  const [summary, setSummary] = useState<UsageSummary>(); const [series, setSeries] = useState<UsageTimeseries>();
  const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  const canonicalSearchKey = JSON.stringify({ end: routeSearch.end, environment_id: routeSearch.environment_id, interval: routeSearch.interval, start: routeSearch.start });
  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    // Browser navigation restores the complete bounded analytics window.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setEnvironment(routeSearch.environment_id ?? "");
    if (routeSearch.start) setStart(localDateTime(routeSearch.start));
    if (routeSearch.end) setEnd(localDateTime(routeSearch.end));
    setInterval(routeSearch.interval ?? "hour");
    if (routeSearch.environment_id && routeSearch.start && routeSearch.end && routeSearch.interval) void load(routeSearch);
    else { setSummary(undefined); setSeries(undefined); }
    // The validated URL key is the canonical restore trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalSearchKey, session.data?.mode]);
  useAdminRefreshTopic("usage", () => {
    if (session.data?.mode === "configured" && routeSearch.environment_id && routeSearch.start && routeSearch.end && routeSearch.interval) void load(routeSearch);
  }, session.data?.mode === "configured" && Boolean(routeSearch.environment_id && routeSearch.start && routeSearch.end && routeSearch.interval));
  if (session.data?.mode !== "configured") return <AccessRequired />;
  async function load(search: AnalyticsRouteSearch): Promise<void> {
    if (!search.environment_id || !search.start || !search.end || !search.interval) return;
    setBusy(true); setProblem(undefined);
    try {
      const query = { environment_id: search.environment_id, start: search.start, end: search.end };
      const [summaryResult, seriesResult] = await Promise.all([
        adminRequest(queryPath("/admin/v1/usage/summary", { ...query, breakdown_limit: "50" }), UsageSummarySchema),
        adminRequest(queryPath("/admin/v1/usage/timeseries", { ...query, interval: search.interval }), UsageTimeseriesSchema)
      ]);
      if (seriesResult.data.interval !== search.interval) throw new Error("analytics_context");
      setSummary(summaryResult.data); setSeries(seriesResult.data);
    } catch (error) { setProblem(error instanceof Error && error.message === "analytics_context" ? { code: "invalid_response", detail: "The analytics time series did not match the selected interval.", retryable: true, status: 0, title: "Analytics context mismatch" } : problemFromError(error)); } finally { setBusy(false); }
  }
  function applyAnalyticsFilters(): void {
    const candidate = AnalyticsRouteSearchSchema.safeParse({
      ...routeSearch,
      end: canonicalInstant(end),
      environment_id: environment || undefined,
      interval,
      start: canonicalInstant(start)
    });
    if (!candidate.success) { setProblem(invalidFilterProblem("Enter a canonical environment and ensure the end time is later than the start time.")); return; }
    if (workspace) {
      const changed = JSON.stringify({ end: candidate.data.end, environment_id: candidate.data.environment_id, interval: candidate.data.interval, start: candidate.data.start }) !== canonicalSearchKey;
      workspace.updateSearch({ end: candidate.data.end, environment_id: candidate.data.environment_id, interval: candidate.data.interval, start: candidate.data.start });
      if (!changed) void load(candidate.data);
    } else void load(candidate.data);
  }
  const copy = analyticsCopy[focus];
  return <div className="control-page">
    <PageHeading eyebrow="Observability" title={copy.title}>{copy.description}</PageHeading>
    <form className="filter-bar filter-bar--wide" onSubmit={(event) => { event.preventDefault(); applyAnalyticsFilters(); }}>
      <label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => { setEnvironment(event.target.value); setSummary(undefined); setSeries(undefined); }} /></label>
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

export function RouteSimulatorPage() {
  const session = useConsoleSession(); const workspace = useOptionalWorkspace(); const routeSearch = RouteSimulatorRouteSearchSchema.parse(workspace?.search ?? {}); const [result, setResult] = useState<RouteSimulation>(); const [resultSearchKey, setResultSearchKey] = useState<string>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  const [environment, setEnvironment] = useState(routeSearch.environment_id ?? ""); const [revision, setRevision] = useState(routeSearch.revision_id ?? ""); const [feature, setFeature] = useState(routeSearch.feature ?? "");
  const [platform, setPlatform] = useState(routeSearch.platform ?? "react_native_ios"); const [trustLevel, setTrustLevel] = useState(routeSearch.trust_level ?? "app_verified"); const [appVersion, setAppVersion] = useState(routeSearch.app_version ?? "");
  const [requestedInputTokens, setRequestedInputTokens] = useState(routeSearch.requested_input_tokens ?? "0"); const [requestedOutputMaximum, setRequestedOutputMaximum] = useState(routeSearch.requested_output_max ?? "0"); const [rewrittenRequestBytes, setRewrittenRequestBytes] = useState(routeSearch.rewritten_request_bytes ?? "1024"); const [framingUnitCount, setFramingUnitCount] = useState(routeSearch.framing_unit_count ?? "1");
  const [authenticated, setAuthenticated] = useState(routeSearch.authenticated ?? true); const [streamingSimulation, setStreamingSimulation] = useState(routeSearch.streaming ?? false);
  const [contextRevision, setContextRevision] = useState<string>(); const [contextFeatures, setContextFeatures] = useState<string[]>([]);
  const canonicalSearchKey = JSON.stringify(routeSearch);
  useEffect(() => {
    if (session.data?.mode !== "configured" || !workspace) return;
    // Browser navigation restores only redaction-safe simulator inputs; claims and results remain local.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setEnvironment(routeSearch.environment_id ?? ""); setRevision(routeSearch.revision_id ?? ""); setFeature(routeSearch.feature ?? "");
    setPlatform(routeSearch.platform ?? "react_native_ios"); setTrustLevel(routeSearch.trust_level ?? "app_verified"); setAppVersion(routeSearch.app_version ?? "");
    setRequestedInputTokens(routeSearch.requested_input_tokens ?? "0"); setRequestedOutputMaximum(routeSearch.requested_output_max ?? "0"); setRewrittenRequestBytes(routeSearch.rewritten_request_bytes ?? "1024"); setFramingUnitCount(routeSearch.framing_unit_count ?? "1");
    setAuthenticated(routeSearch.authenticated ?? true); setStreamingSimulation(routeSearch.streaming ?? false);
    if (routeSearch.environment_id) void loadContext(routeSearch.environment_id, routeSearch, false);
    else { setContextRevision(undefined); setContextFeatures([]); }
    // The validated URL key is the canonical restore trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalSearchKey, session.data?.mode]);
  if (session.data?.mode !== "configured") return <AccessRequired />;
  async function loadContext(targetEnvironment = environment, selection: RouteSimulatorRouteSearch = routeSearch, canonicalize = true): Promise<void> {
    if (!environmentPattern.test(targetEnvironment)) { setProblem({ code: "request_invalid", detail: "Enter a canonical environment ID before loading route context.", retryable: false, status: 0, title: "Invalid route context" }); return; }
    setBusy(true); setProblem(undefined);
    if (canonicalize) { setResult(undefined); setResultSearchKey(undefined); }
    try {
      const active = await adminRequest(`/admin/v1/environments/${targetEnvironment}/config`, RevisionSchema);
      if (active.data.environment_id !== targetEnvironment) throw new Error("context");
      const spec = active.data.document.spec;
      if (!spec || typeof spec !== "object" || Array.isArray(spec)) throw new Error("context");
      const configuredFeatures = (spec as Record<string, unknown>).features;
      if (!Array.isArray(configuredFeatures) || configuredFeatures.length > 256) throw new Error("context");
      const ids = configuredFeatures.map((item) => item && typeof item === "object" && !Array.isArray(item) ? String((item as Record<string, unknown>).id ?? "") : "");
      if (ids.some((id) => !identifierPattern.test(id)) || new Set(ids).size !== ids.length) throw new Error("context");
      if (selection.revision_id && selection.revision_id !== active.data.id) throw new Error("context_selection");
      if (selection.feature && !ids.includes(selection.feature)) throw new Error("context_selection");
      const selectedFeature = selection.feature ?? ids[0] ?? "";
      setContextRevision(active.data.id); setContextFeatures(ids); setRevision(active.data.id); setFeature(selectedFeature);
      if (canonicalize && workspace) workspace.updateSearch({ environment_id: targetEnvironment, feature: selectedFeature || undefined, revision_id: active.data.id });
    } catch (error) { setProblem(error instanceof Error && error.message === "context_selection" ? { code: "context_mismatch", detail: "The selected revision or feature is not active in this environment.", retryable: false, status: 0, title: "Route context changed" } : error instanceof Error && error.message === "context" ? { code: "invalid_response", detail: "The active revision did not match the environment or contain a bounded canonical feature list.", retryable: true, status: 0, title: "Route context unavailable" } : problemFromError(error)); }
    finally { setBusy(false); }
  }
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const claims = JSON.parse(String(form.get("claims") ?? "{}")) as unknown;
      if (!claims || Array.isArray(claims) || typeof claims !== "object" || Object.keys(claims).length > 64) throw new Error("claims");
      if (contextRevision && revision !== contextRevision) throw new Error("context_selection");
      const safeSearchCandidate = {
        ...routeSearch,
        app_version: appVersion || undefined,
        authenticated,
        environment_id: environment || undefined,
        feature,
        framing_unit_count: framingUnitCount,
        platform,
        requested_input_tokens: requestedInputTokens || "0",
        requested_output_max: requestedOutputMaximum || "0",
        revision_id: revision,
        rewritten_request_bytes: rewrittenRequestBytes || "0",
        streaming: streamingSimulation,
        trust_level: trustLevel
      };
      const safeSearch = workspace ? RouteSimulatorRouteSearchSchema.parse(safeSearchCandidate) : undefined;
      const response = await adminRequest(`/admin/v1/config-revisions/${revision}/simulate`, RouteSimulationSchema, { method: "POST", body: {
        feature, platform, trust_level: trustLevel,
        principal: { authenticated, claims },
        request: { streaming: streamingSimulation, app_version: appVersion, requested_input_tokens: Number(requestedInputTokens || 0), requested_output_max: Number(requestedOutputMaximum || 0), rewritten_request_bytes: Number(rewrittenRequestBytes || 0), framing_unit_count: Number(framingUnitCount || 0) }
      }});
      if (response.data.revision_id !== revision || response.data.feature !== feature || (environment && response.data.environment_id !== environment)) throw new Error("context_result");
      setResult(response.data); setResultSearchKey(safeSearch ? JSON.stringify(safeSearch) : undefined);
      if (workspace && safeSearch) workspace.updateSearch({
        app_version: safeSearch.app_version,
        authenticated: safeSearch.authenticated,
        environment_id: safeSearch.environment_id,
        feature: safeSearch.feature,
        framing_unit_count: safeSearch.framing_unit_count,
        platform: safeSearch.platform,
        requested_input_tokens: safeSearch.requested_input_tokens,
        requested_output_max: safeSearch.requested_output_max,
        revision_id: safeSearch.revision_id,
        rewritten_request_bytes: safeSearch.rewritten_request_bytes,
        streaming: safeSearch.streaming,
        trust_level: safeSearch.trust_level
      });
    } catch (error) { setProblem(error instanceof SyntaxError || (error instanceof Error && error.message === "claims") ? { code: "invalid_claims", detail: "Normalized claims must be one JSON object with at most 64 properties.", retryable: false, status: 0, title: "Invalid simulator input" } : error instanceof Error && error.message === "context_selection" ? { code: "context_mismatch", detail: "The revision no longer matches the loaded active environment context. Reload context before simulating.", retryable: false, status: 0, title: "Route context changed" } : error instanceof Error && error.message === "context_result" ? { code: "invalid_response", detail: "The simulation result did not match the selected revision, feature, and environment context.", retryable: true, status: 0, title: "Route context mismatch" } : problemFromError(error)); }
    finally { setBusy(false); }
  }
  return <div className="control-page"><PageHeading eyebrow="Operations" title="Route simulator">The server executes the exact compiled production CEL and resolver. This performs no quota reservation and no upstream dispatch.</PageHeading>
    <section className="filter-bar"><label>Environment context ID<input pattern={environmentInputPattern} value={environment} onChange={(event) => { setEnvironment(event.target.value); setContextRevision(undefined); setContextFeatures([]); setResult(undefined); }} /></label><button className="secondary-action" disabled={busy || !environment} onClick={() => void loadContext(environment, { ...routeSearch, environment_id: environment, feature: undefined, revision_id: undefined })} type="button">Load active route context</button>{contextRevision ? <span>Selected active revision <code>{contextRevision}</code> with {contextFeatures.length} feature{contextFeatures.length === 1 ? "" : "s"}.</span> : null}</section>
    <form className="control-form" onSubmit={(event) => void submit(event)}>
      <div className="form-field-grid"><label>Revision ID<input name="revision" pattern={revisionPattern} required value={revision} onChange={(event) => setRevision(event.target.value)} /></label><label>Feature<input list="route-context-feature-options" name="feature" pattern={identifierInputPattern} required value={feature} onChange={(event) => setFeature(event.target.value)} /><datalist id="route-context-feature-options">{contextFeatures.map((id) => <option key={id} value={id} />)}</datalist></label></div>
      <div className="form-field-grid"><label>Platform<select name="platform" value={platform} onChange={(event) => setPlatform(event.target.value as typeof platform)}><option value="react_native_ios">React Native iOS</option><option value="react_native_android">React Native Android</option><option value="ios">iOS</option><option value="android">Android</option><option value="web">Web</option><option value="node">Node</option></select></label><label>Trust level<select name="trust" value={trustLevel} onChange={(event) => setTrustLevel(event.target.value as typeof trustLevel)}><option value="none">None</option><option value="identity_only">Identity only</option><option value="app_verified">App verified</option><option value="device_verified">Device verified</option><option value="strong_device_verified">Strong device verified</option><option value="debug">Debug</option></select></label></div>
      <label>Normalized claims JSON<textarea defaultValue="{}" name="claims" rows={6} spellCheck={false} /></label>
      <div className="form-field-grid"><label>App version (explanatory)<input maxLength={128} name="app_version" pattern="[A-Za-z0-9._+-]+" value={appVersion} onChange={(event) => setAppVersion(event.target.value)} /></label><label>Requested input tokens (explanatory)<input max={2_147_483_647} min={0} name="requested_input" type="number" value={requestedInputTokens} onChange={(event) => setRequestedInputTokens(event.target.value)} /></label><label>Requested output maximum<input max={2_147_483_647} min={0} name="requested_output" type="number" value={requestedOutputMaximum} onChange={(event) => setRequestedOutputMaximum(event.target.value)} /></label></div>
      <div className="form-field-grid"><label>Rewritten request bytes<input max={104_857_600} min={0} name="rewritten_request_bytes" type="number" value={rewrittenRequestBytes} onChange={(event) => setRewrittenRequestBytes(event.target.value)} /><small>Hypothetical exact post-rewrite body size for reservation projection.</small></label><label>Framing unit count<input max={4096} min={0} name="framing_unit_count" type="number" value={framingUnitCount} onChange={(event) => setFramingUnitCount(event.target.value)} /><small>Messages, input items, or embedding inputs after adapter validation.</small></label></div>
      <label className="check-field"><input checked={authenticated} name="authenticated" onChange={(event) => setAuthenticated(event.target.checked)} type="checkbox" />Authenticated principal</label><label className="check-field"><input checked={streamingSimulation} name="streaming" onChange={(event) => setStreamingSimulation(event.target.checked)} type="checkbox" />Streaming request</label><FormActions busy={busy}>Simulate route</FormActions>
    </form><ProblemNotice problem={problem} />
    {result && (!workspace || resultSearchKey === canonicalSearchKey) ? <section className={`simulation-result ${result.allowed ? "simulation-result--allowed" : "simulation-result--denied"}`}><h2>{result.allowed ? "Allowed" : "Denied"}</h2><dl><div><dt>Application</dt><dd>{result.application_id}</dd></div><div><dt>Environment</dt><dd>{result.environment_id} ({result.environment_kind})</dd></div><div><dt>Revision</dt><dd>{result.revision_id}</dd></div><div><dt>Access expression</dt><dd>{result.matched_access_expression ?? "—"}</dd></div><div><dt>Limit plan</dt><dd>{result.limit_plan ?? "—"}</dd></div><div><dt>Route</dt><dd>{result.route ?? "—"}</dd></div><div><dt>Upstream</dt><dd>{result.upstream ?? "—"}</dd></div><div><dt>Physical model</dt><dd>{result.physical_model ?? "—"}</dd></div><div><dt>Pricing</dt><dd>{result.pricing_confidence ?? "—"}</dd></div></dl>
      {result.reservation ? <><h3>Exact conservative reservation</h3><dl><div><dt>Applied output maximum</dt><dd>{result.reservation.applied_output_maximum.toLocaleString()}</dd></div><div><dt>Total token bound</dt><dd>{result.reservation.total_token_bound.toLocaleString()}</dd></div><div><dt>Cost bound</dt><dd>{result.reservation.cost_bound_known ? `${result.reservation.cost_nano_usd_bound.toLocaleString()} nano-USD` : "not applicable / unknown"}</dd></div><div><dt>Input accounting</dt><dd>{result.reservation.input_accounting.required ? `${result.reservation.input_accounting.profile_id}: ${result.reservation.input_accounting.input_token_bound.toLocaleString()} tokens` : "not required"}</dd></div></dl><Table headers={["Metric", "Algorithm", "Units", "Applicable", "Durable"]} rows={result.reservation.allocations.map((allocation) => [allocation.metric, allocation.algorithm, allocation.units, allocation.applicable ? "yes" : "no", allocation.durable ? "yes" : "no"])} /></> : null}
      {result.limits?.length ? <><h3>Applicable limits</h3><Table headers={["Metric", "Algorithm", "Scope", "Window / timezone", "Maximum", "Per request", "Capacity", "Refill / second"]} rows={result.limits.map((limit) => [limit.metric, limit.algorithm, limit.scope.join(", "), [limit.window, limit.timezone].filter(Boolean).join(" / ") || "—", limit.maximum ?? "—", limit.per_request_maximum ?? "—", limit.capacity ?? "—", limit.refill_per_second ?? "—"])} /></> : null}
      <h3>Bounded facts</h3><Table headers={["Fact", "Value"]} rows={[["feature", result.facts.feature], ["platform", result.facts.platform], ["trust_level", result.facts.trust_level], ["authenticated", result.facts.authenticated ? "true" : "false"], ["normalized_claims", JSON.stringify(result.facts.normalized_claims)], ["streaming", result.facts.streaming ? "true" : "false"], ["app_version", result.facts.app_version || "—"], ["requested_input_tokens", result.facts.requested_input_tokens], ["requested_output_max", result.facts.requested_output_max], ["rewritten_request_bytes", result.facts.rewritten_request_bytes], ["framing_unit_count", result.facts.framing_unit_count]]} />
      <h3>Bounded fact roles</h3><Table headers={["Fact", "Role", "Affects CEL", "Meaning"]} rows={result.fact_usage.map((fact) => [fact.fact, fact.role, fact.affects_cel ? "yes" : "no", fact.explanation])} />
      <h3>Explanation</h3><ul>{result.explanation.map((line) => <li key={line}>{line}</li>)}</ul>{result.warnings?.length ? <><h3>Warnings</h3><ul>{result.warnings.map((line) => <li key={line}>{line}</li>)}</ul></> : null}{result.fallback_sequence?.length ? <><h3>Fallback sequence</h3><Table headers={["Route", "Upstream", "Model", "Physical model", "Fallback on"]} rows={result.fallback_sequence.map((candidate) => [candidate.route, candidate.upstream, candidate.model, candidate.physical_model, candidate.fallback_on.join(", ")])} /></> : null}</section> : null}
  </div>;
}

export function SelfTestsPage() {
  const session = useConsoleSession(); const workspace = useOptionalWorkspace(); const routeSearch = SelfTestRouteSearchSchema.parse(workspace?.search ?? {}); const [run, setRun] = useState<SelfTestRun>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false); const [kind, setKind] = useState("local"); const [runEnvironment, setRunEnvironment] = useState(routeSearch.environment_id ?? "");
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
  const canRun = session.data.session?.capabilities.includes("run_self_tests") ?? false;
  async function restoreSelfTests(search: SelfTestRouteSearch): Promise<void> {
    if (!search.environment_id) return;
    setBusy(true); setProblem(undefined);
    try {
      let restoredRun: SelfTestRun | undefined;
      if (search.self_test_id) {
        const response = await adminRequest(`/admin/v1/self-tests/${search.self_test_id}`, SelfTestSchema);
        if (response.data.id !== search.self_test_id) throw new Error("self_test_context");
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
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const body: Record<string, string | number> = { kind, environment_id: runEnvironment };
      if (kind !== "local") {
        body.upstream = String(form.get("upstream")); body.model = String(form.get("model"));
        body.max_cost_nano_usd = Number(form.get("max_cost_nano_usd"));
      }
      const created = (await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body })).data;
      setRun(created);
      if (workspace) workspace.updateSearch({ environment_id: runEnvironment, self_test_id: created.id }, { replace: false });
    }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }
  async function refresh(): Promise<void> { if (!run) return; setBusy(true); try { const refreshed = (await adminRequest(`/admin/v1/self-tests/${run.id}`, SelfTestSchema)).data; if (refreshed.id !== run.id) throw new Error("self_test_context"); setRun(refreshed); } catch (error) { setProblem(error instanceof Error && error.message === "self_test_context" ? { code: "invalid_response", detail: "The refreshed self-test did not match the selected run ID.", retryable: true, status: 0, title: "Self-test context mismatch" } : problemFromError(error)); } finally { setBusy(false); } }
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
    event.preventDefault(); setBusy(true); setProblem(undefined); const element = event.currentTarget; const form = new FormData(element); const bearerToken = String(form.get("authorization_token")); const tokenInput = element.elements.namedItem("authorization_token"); if (tokenInput instanceof HTMLInputElement) tokenInput.value = "";
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
    if (!selectedSchedule) return; setBusy(true); setProblem(undefined);
    try {
      const disabled = (await adminRequest(`/admin/v1/self-test-schedules/${selectedSchedule.id}`, SelfTestScheduleSchema, { method: "DELETE" })).data;
      if (disabled.id !== selectedSchedule.id || disabled.environment_id !== selectedSchedule.environment_id) throw new Error("self_test_context");
      setSelectedSchedule(disabled); setSchedules((current) => current?.map((item) => item.id === disabled.id ? disabled : item));
    } catch (error) { setProblem(error instanceof Error && error.message === "self_test_context" ? { code: "invalid_response", detail: "The disabled schedule did not match the selected schedule and environment.", retryable: true, status: 0, title: "Self-test context mismatch" } : problemFromError(error)); } finally { setBusy(false); }
  }
  return <div className="control-page"><PageHeading eyebrow="Operations" title="Self-tests">Local verification checks durable state. Credential-aware tests use only active server-owned targets and secrets, prove a configured cost ceiling before dispatch, and persist redaction-safe results.</PageHeading>
    <form className="control-form" onSubmit={(event) => void start(event)}><div className="form-field-grid"><label>Environment ID<input name="environment" pattern={environmentInputPattern} required value={runEnvironment} onChange={(event) => setRunEnvironment(event.target.value)} /></label><label>Test kind<select name="kind" onChange={(event) => setKind(event.target.value)} value={kind}><option value="local">Local</option><option value="upstream">Configured upstream</option><option value="openrouter">OpenRouter conformance</option></select></label></div>{kind !== "local" ? <><div className="form-field-grid"><label>Upstream ID<input name="upstream" pattern={identifierInputPattern} required /></label><label>Model ID<input name="model" pattern={identifierInputPattern} required /></label></div><label>Maximum total cost (nano-USD)<input defaultValue={10_000_000} max={1_000_000_000} min={1} name="max_cost_nano_usd" required type="number" /><small>10,000,000 nano-USD = US$0.01. The server refuses dispatch when the complete protocol-specific request bound is higher.</small></label></> : null}<button className="primary-action" disabled={!canRun || busy} type="submit">{busy ? "Starting…" : "Run self-test"}</button></form><ProblemNotice problem={problem} />
    {run ? <section className="detail-card"><div className="detail-card__heading"><div><h2>{run.kind} self-test</h2><p>{run.id} · {run.state}</p></div><div className="button-row"><button className="secondary-action" disabled={busy} onClick={() => void refresh()} type="button">Refresh</button><button className="small-action" disabled={busy} onClick={() => { if (workspace) workspace.updateSearch({ self_test_id: undefined }); else setRun(undefined); }} type="button">Close run</button></div></div><Table headers={["Check", "State", "Safe detail"]} rows={run.checks.map((check) => [check.name, check.state, check.safe_detail ?? "—"])} /></section> : null}
    <section className="detail-card"><h2>Scheduled credential-aware self-tests</h2><p>Each schedule pins one active configuration revision and one durable API-token ID. Browser session values and provider secret values are never stored in the schedule.</p>
      <div className="filter-bar"><label>Scheduled environment ID<input pattern={environmentInputPattern} required value={scheduleEnvironment} onChange={(event) => { setScheduleEnvironment(event.target.value); setSchedules(undefined); setSelectedSchedule(undefined); }} /></label><button className="secondary-action" disabled={!canRun || busy || !environmentPattern.test(scheduleEnvironment)} onClick={() => void loadSchedules()} type="button">Load schedules</button></div>
      <form className="control-form" onSubmit={(event) => void createSchedule(event)}><div className="form-field-grid"><label>Scheduled test kind<select value={scheduleKind} onChange={(event) => setScheduleKind(event.target.value as "upstream" | "openrouter")}><option value="upstream">Configured upstream</option><option value="openrouter">OpenRouter conformance</option></select></label><label>Durable Admin API token<input autoComplete="off" maxLength={2048} minLength={32} name="authorization_token" required type="password" /><small>Enter an active token scoped to run_self_tests. It is sent once as Authorization Bearer and cleared immediately; only its stable credential ID is bound.</small></label></div>
        <div className="form-field-grid"><label>Scheduled upstream ID<input name="upstream" pattern={identifierInputPattern} required /></label><label>Scheduled model ID<input name="model" pattern={identifierInputPattern} required /></label></div>
        <div className="form-field-grid"><label>Per-run maximum cost (nano-USD)<input defaultValue={10_000_000} max={1_000_000_000} min={1} name="max_cost_nano_usd" required type="number" /></label><label>UTC-day maximum cost (nano-USD)<input defaultValue={240_000_000} max={10_000_000_000} min={1} name="daily_cost_limit_nano_usd" required type="number" /></label></div>
        <label>Cadence (seconds)<input defaultValue={3600} max={2_592_000} min={3600} name="interval_seconds" required step={1} type="number" /><small>Allowed range: one hour through 30 days. Missed intervals coalesce to one run.</small></label><button className="primary-action" disabled={!canRun || busy || !environmentPattern.test(scheduleEnvironment)} type="submit">Create schedule</button>
      </form>
      {schedules ? <Table headers={["Schedule", "Target", "Cadence", "Per run / UTC day", "State"]} rows={schedules.map((schedule) => [<button className="table-link" onClick={() => void selectSchedule(schedule)} type="button">{schedule.id}</button>, `${schedule.upstream} / ${schedule.model}`, `${schedule.interval_seconds.toLocaleString()} s`, `${schedule.max_cost_nano_usd.toLocaleString()} / ${schedule.daily_cost_limit_nano_usd.toLocaleString()}`, schedule.status])} /> : null}
      {selectedSchedule ? <section className="detail-card"><div className="detail-card__heading"><div><h3>Schedule detail</h3><p>{selectedSchedule.id} · {selectedSchedule.status}</p></div><div className="button-row"><button className="secondary-action" disabled={!canRun || busy || selectedSchedule.status !== "active"} onClick={() => void disableSchedule()} type="button">Disable schedule</button><button className="small-action" disabled={busy} onClick={() => { if (workspace) workspace.updateSearch({ schedule_id: undefined }); else setSelectedSchedule(undefined); }} type="button">Close schedule</button></div></div><dl><div><dt>Application / environment</dt><dd>{selectedSchedule.application_id} / {selectedSchedule.environment_id}</dd></div><div><dt>Pinned configuration</dt><dd>{selectedSchedule.config_revision_id}</dd></div><div><dt>Authorization credential</dt><dd>{selectedSchedule.authorization_credential_id}</dd></div><div><dt>Target</dt><dd>{selectedSchedule.kind}: {selectedSchedule.upstream} / {selectedSchedule.model}</dd></div><div><dt>Cost ceilings</dt><dd>{selectedSchedule.max_cost_nano_usd.toLocaleString()} per run / {selectedSchedule.daily_cost_limit_nano_usd.toLocaleString()} per UTC day</dd></div><div><dt>Cadence</dt><dd>{selectedSchedule.interval_seconds.toLocaleString()} seconds</dd></div><div><dt>Next run</dt><dd>{selectedSchedule.next_run_at ? new Date(selectedSchedule.next_run_at).toLocaleString() : "Disabled"}</dd></div><div><dt>Last run</dt><dd>{selectedSchedule.last_self_test_id ?? "—"}</dd></div></dl></section> : null}
    </section>
  </div>;
}

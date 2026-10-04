import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { type FormEvent, useMemo, useState } from "react";

import { adminRequest, type AuditEvent, AuditEventSchema, type AuditPage, AuditPageSchema, queryPath } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { type AuditRouteSearch, AuditRouteSearchSchema } from "../../app/route-search";
import { useAdminRefreshTopic } from "../../app/use-admin-refresh";
import { useOptionalWorkspace } from "../../app/workspace-context-value";
import { Badge, Button, type Column, DataTable, DetailPanel, EmptyState, Field, Input, Notice, PageHeader, Properties, RangePicker, type RangeValue } from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";

const PERIODS = ["24h", "7d", "30d", "90d"] as const;
const PERIOD_MS: Readonly<Record<(typeof PERIODS)[number], number>> = { "24h": 86_400_000, "30d": 30 * 86_400_000, "7d": 7 * 86_400_000, "90d": 90 * 86_400_000 };
const wallClock = (): number => Date.now();

const RESULT_COLOR = { denied: "orange", failed: "red", indeterminate: "orange", succeeded: undefined } as const;
const SOURCE_LABEL: Readonly<Record<AuditEvent["source"], string>> = { api: "API token", cli: "CLI", console: "Console", system: "System" };
const ACTOR_LABEL: Readonly<Record<AuditEvent["actor_kind"], string>> = { admin_api_token: "API token", admin_user: "Member", system: "System" };

type TextFilter = "action" | "actor_id" | "reason" | "resource_id" | "resource_type";
const TEXT_FILTERS: ReadonlyArray<[TextFilter, string, string]> = [
  ["action", "Action", "admin.secret_rotate"],
  ["resource_type", "Resource type", "secret_record"],
  ["resource_id", "Resource ID", "sec_…"],
  ["actor_id", "Member or token ID", "adm_… or tok_…"],
  ["reason", "Reason code", "operator_reason_provided"]
];

function rangeOf(search: AuditRouteSearch): RangeValue {
  if (search.period) return { id: search.period };
  if (search.start && search.end) return { end: Date.parse(search.end), id: "custom", start: Date.parse(search.start) };
  return { id: "all" };
}

/** The API query for the URL's filters. Presets are relative to when the list loads. */
function listQuery(search: AuditRouteSearch, now: number): Record<string, string | undefined> {
  return {
    action: search.action,
    actor_id: search.actor_id,
    actor_kind: search.actor_kind,
    end: search.period ? undefined : search.end,
    environment_id: search.environment_id,
    page_size: "50",
    reason: search.reason,
    resource_id: search.resource_id,
    resource_type: search.resource_type,
    result: search.result,
    source: search.source,
    start: search.period ? new Date(now - PERIOD_MS[search.period]).toISOString() : search.start
  };
}

function AuditDrawer({ environments, eventID, onClose }: { environments: ReadonlyMap<string, string>; eventID: string; onClose: () => void }) {
  const event = useQuery({
    queryFn: async () => {
      const detail = (await adminRequest(`/admin/v1/audit-events/${eventID}`, AuditEventSchema)).data;
      if (detail.id !== eventID) throw new Error("The audit event returned didn't match the one selected.");
      return detail;
    },
    queryKey: ["audit", "event", eventID],
    retry: false
  });
  const detail = event.data;
  return (
    <DetailPanel className="lw-request-drawer" mono onClose={onClose} subtitle={detail ? <><Badge color={RESULT_COLOR[detail.result]} variant="soft">{detail.result}</Badge><span className="lw-faint">{new Date(detail.timestamp).toLocaleString()}</span></> : undefined} title={eventID}>
      {event.error ? <ProblemNotice problem={event.error instanceof Error && !("problem" in event.error) ? { code: "context_mismatch", detail: event.error.message, retryable: true, status: 0, title: "Audit event mismatch" } : problemFromError(event.error)} /> : null}
      {event.isPending ? <p role="status">Loading…</p> : null}
      {detail ? (
        <div className="lw-stack">
          <Properties columns={2} items={[
            { label: "Action", value: <span className="lw-mono lw-mono--sm">{detail.action}</span> },
            { label: "Actor", value: <>{detail.actor} <Badge variant="soft">{ACTOR_LABEL[detail.actor_kind]}</Badge></> },
            { label: "Source", value: SOURCE_LABEL[detail.source] },
            { label: "Scope", value: detail.environment_id ? environments.get(detail.environment_id) ?? detail.environment_id : "Organization" },
            { label: "Target", value: <span>{detail.target} <span className="lw-faint lw-mono lw-mono--sm">{detail.resource_type} · {detail.resource_id}</span></span> },
            { label: "Reason", value: detail.reason ? <span className="lw-mono lw-mono--sm">{detail.reason}</span> : "Not supplied" },
            { label: "Request", value: detail.request_id ? <span className="lw-mono lw-mono--sm">{detail.request_id}</span> : "—" }
          ]} />
          <div>
            <strong className="lw-note">Fields changed</strong>
            {detail.changes.length ? (
              <table className="lw-mini-table">
                <thead><tr><th>Field</th><th>Change</th><th>Value</th></tr></thead>
                <tbody>{detail.changes.map((change, index) => <tr key={`${change.field}-${index}`}><td className="lw-mono lw-mono--sm">{change.field}</td><td>{change.operation}</td><td className="lw-faint">{change.redacted ? "Sensitive, never recorded" : "Not recorded"}</td></tr>)}</tbody>
              </table>
            ) : <p className="lw-secondary lw-note">No field-level changes.</p>}
            <p className="lw-secondary lw-note">The audit log records which fields changed, never their values. Passwords, token secrets and reasons&apos; text are never stored.</p>
          </div>
          <details><summary className="lw-note">Raw event</summary><pre className="lw-code-block">{JSON.stringify(detail, null, 2)}</pre></details>
        </div>
      ) : null}
    </DetailPanel>
  );
}

function AuditView() {
  const workspace = useOptionalWorkspace();
  const search = AuditRouteSearchSchema.parse(workspace?.search ?? {});
  const [loadedAt, setLoadedAt] = useState(wallClock);
  const [more, setMore] = useState<Record<TextFilter, string>>(() => ({ action: search.action ?? "", actor_id: search.actor_id ?? "", reason: search.reason ?? "", resource_id: search.resource_id ?? "", resource_type: search.resource_type ?? "" }));
  const [moreOpen, setMoreOpen] = useState(TEXT_FILTERS.some(([key]) => Boolean(search[key])));
  const [moreError, setMoreError] = useState<string>();
  const query = listQuery(search, loadedAt);
  const key = JSON.stringify({ ...query, start: search.period ?? query.start });
  const environments = useMemo(() => new Map((workspace?.environments ?? []).map((environment) => [environment.id, `${workspace?.applications.find((app) => app.id === environment.application_id)?.display_name ?? "App"} · ${environment.display_name}`])), [workspace?.applications, workspace?.environments]);
  const events = useInfiniteQuery({
    getNextPageParam: (page: AuditPage) => (page.page.has_more ? page.page.next_cursor : undefined),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }): Promise<AuditPage> => (await adminRequest(queryPath("/admin/v1/audit-events", { ...query, cursor: pageParam }), AuditPageSchema)).data,
    queryKey: ["audit", "list", key],
    retry: false
  });
  useAdminRefreshTopic("audit", () => { setLoadedAt(wallClock()); });
  const rows = events.data?.pages.flatMap((page) => page.items) ?? [];
  const update = (patch: Partial<AuditRouteSearch>) => workspace?.updateSearch({ ...patch, cursor: undefined, event: undefined });
  const activeFilters = (["actor_kind", "source", "result", "environment_id", ...TEXT_FILTERS.map(([filterKey]) => filterKey)] as const).filter((filterKey) => Boolean(search[filterKey])).length;

  function applyMore(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const candidate = AuditRouteSearchSchema.safeParse({ ...search, ...Object.fromEntries(TEXT_FILTERS.map(([filterKey]) => [filterKey, more[filterKey].trim() || undefined])) });
    if (!candidate.success) return setMoreError("Check the formats: actions and types are lowercase with dots or underscores; IDs keep their prefix; reason codes are lowercase.");
    setMoreError(undefined);
    update(Object.fromEntries(TEXT_FILTERS.map(([filterKey]) => [filterKey, candidate.data[filterKey]])) as Partial<AuditRouteSearch>);
  }

  function clearAll(): void {
    setMore({ action: "", actor_id: "", reason: "", resource_id: "", resource_type: "" });
    update({ action: undefined, actor_id: undefined, actor_kind: undefined, environment_id: undefined, reason: undefined, resource_id: undefined, resource_type: undefined, result: undefined, source: undefined });
  }

  const columns: Array<Column<AuditEvent>> = [
    { header: "Time", key: "time", render: (event) => <span className="lw-note" title={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</span> },
    { header: "Actor", key: "actor", render: (event) => <span className="lw-rq-model"><span>{event.actor}</span><span className="lw-faint">{ACTOR_LABEL[event.actor_kind]} · {SOURCE_LABEL[event.source]}</span></span> },
    { header: "Action", key: "action", render: (event) => <span className="lw-mono lw-mono--sm">{event.action}</span> },
    { header: "Target", key: "target", render: (event) => <span className="lw-rq-model"><span>{event.target}</span><span className="lw-faint lw-mono lw-mono--sm">{event.resource_id}</span></span> },
    { header: "Scope", key: "scope", render: (event) => <span className="lw-note">{event.environment_id ? environments.get(event.environment_id) ?? event.environment_id : "Organization"}</span> },
    { header: "Result", key: "result", render: (event) => <Badge color={RESULT_COLOR[event.result]} variant="soft">{event.result}</Badge> }
  ];

  return (
    <div className="lw-page lw-collection">
      <PageHeader
        actions={<RangePicker maxDays={730} onChange={(next) => update(next.id === "custom" && "start" in next ? { end: new Date(next.end).toISOString(), period: undefined, start: new Date(next.start).toISOString() } : { end: undefined, period: (PERIODS as readonly string[]).includes(next.id) ? next.id as (typeof PERIODS)[number] : undefined, start: undefined })} presets={[...PERIODS, { id: "all", label: "All" }]} value={rangeOf(search)} />}
        description="Every administrative action in this organization, newest first: who did it, from where, to what, and whether it worked. Values are never recorded."
        title="Audit Log"
      />
      <div className="lw-toolbar lw-toolbar--wrap">
        <select aria-label="Actor" className="lw-select lw-select--sm" onChange={(event) => update({ actor_kind: (event.target.value || undefined) as AuditRouteSearch["actor_kind"] })} value={search.actor_kind ?? ""}>
          <option value="">Any actor</option><option value="admin_user">Members</option><option value="admin_api_token">API tokens</option><option value="system">System</option>
        </select>
        <select aria-label="Source" className="lw-select lw-select--sm" onChange={(event) => update({ source: (event.target.value || undefined) as AuditRouteSearch["source"] })} value={search.source ?? ""}>
          <option value="">Any source</option><option value="console">Console</option><option value="cli">CLI</option><option value="api">API token</option><option value="system">System</option>
        </select>
        <select aria-label="Result" className="lw-select lw-select--sm" onChange={(event) => update({ result: (event.target.value || undefined) as AuditRouteSearch["result"] })} value={search.result ?? ""}>
          <option value="">Any result</option><option value="succeeded">Succeeded</option><option value="denied">Denied</option><option value="failed">Failed</option><option value="indeterminate">Indeterminate</option>
        </select>
        <select aria-label="Scope" className="lw-select lw-select--sm" onChange={(event) => update({ environment_id: event.target.value || undefined })} value={search.environment_id ?? ""}>
          <option value="">Any scope</option>
          {[...environments.entries()].map(([id, label]) => <option key={id} value={id}>{label}</option>)}
        </select>
        <Button onClick={() => setMoreOpen((current) => !current)} size="sm" variant="ghost">{moreOpen ? "Fewer filters" : "More filters"}</Button>
        {activeFilters ? <Button onClick={clearAll} size="sm" variant="ghost">Clear {activeFilters} filter{activeFilters === 1 ? "" : "s"}</Button> : null}
      </div>
      {moreOpen ? (
        <form className="lw-body lw-audit-more" onSubmit={applyMore}>
          <div className="lw-form-grid">
            {TEXT_FILTERS.map(([filterKey, label, placeholder]) => <Field id={`audit-${filterKey}`} key={filterKey} label={label}><Input id={`audit-${filterKey}`} mono onChange={(event) => setMore((current) => ({ ...current, [filterKey]: event.target.value }))} placeholder={placeholder} value={more[filterKey]} /></Field>)}
          </div>
          {moreError ? <Notice tone="danger">{moreError}</Notice> : null}
          <div className="lw-row"><Button size="sm" type="submit">Apply</Button></div>
        </form>
      ) : null}
      {events.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(events.error)} /></div> : null}
      {events.isPending ? <p className="lw-page-status" role="status">Loading audit events…</p> : rows.length ? (
        <DataTable caption="Audit events" columns={columns} onSelect={(event) => workspace?.updateSearch({ event: event.id }, { replace: false })} rowKey={(event) => event.id} rows={rows} selectedKey={search.event} />
      ) : <div className="lw-page-empty"><EmptyState icon="audit" orientation="horizontal" title="No audit events match">Widen the time range or clear filters.</EmptyState></div>}
      <div className="lw-page-foot lw-row">
        <span className="lw-secondary lw-note">{rows.length} loaded. How long audit events are kept is up to your deployment; System Health shows the oldest one.</span>
        {events.hasNextPage ? <Button loading={events.isFetchingNextPage} onClick={() => void events.fetchNextPage()} size="sm">Load More</Button> : null}
      </div>
      {search.event ? <div className="lw-drawer-dock lw-drawer-dock--wide"><AuditDrawer environments={environments} eventID={search.event} key={search.event} onClose={() => workspace?.updateSearch({ event: undefined })} /></div> : null}
    </div>
  );
}

/** Organization → Audit Log. */
export function AuditLogPage() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <AuditView />;
}

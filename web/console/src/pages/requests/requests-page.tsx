import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, type ReactNode, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import {
  adminRequest,
  type EffectiveConfiguration,
  getRequestEffectiveConfiguration,
  type LogicalRequest,
  type LogicalRequestPage,
  queryPath,
  RequestPageSchema,
  RequestSchema
} from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { type RequestRouteSearch, RequestRouteSearchSchema } from "../../app/route-search";
import { useAdminRefreshTopic } from "../../app/use-admin-refresh";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import {
  Button,
  type Column,
  DataTable,
  EmptyState,
  Field,
  FilterChip,
  Icon,
  Input,
  Menu,
  type MenuEntry,
  Notice,
  PageHeader,
  RangePicker,
  Segmented,
  StatusBadge,
  Toolbar
} from "../../ui";
import { AccessRequired, EffectiveConfigurationPanel, ProblemNotice } from "../control-plane-pages";
import { RequestDetail } from "./request-detail";
import {
  capitalize,
  ERROR_FILTER_SUGGESTIONS,
  formatClock,
  formatMs,
  formatUtc,
  metricCell,
  outcomeStatus,
  PLATFORM_LABEL,
  requestDuration,
  requestsCsv,
  routeSummary,
  shortId,
  timeToFirstToken,
  TRUST_LABEL,
  words
} from "./request-format";
import {
  activeQuickView,
  applyMoreFilters,
  CUSTOM_RANGE_MAX_DAYS,
  curlCommand,
  type FilterKey,
  filtersOf,
  filtersPatch,
  goToTarget,
  MORE_FILTER_KEYS,
  moreFilterDraft,
  type MoreFilterDraft,
  PAGE_SIZES,
  QUICK_VIEWS,
  RANGE_PRESETS,
  rangeOf,
  rangePatch,
  type RequestFilters,
  requestListQuery
} from "./request-query";

const OPTIONAL_COLUMNS = [["trust", "Trust"], ["route", "Route"], ["revision", "Revision"], ["plan", "Plan"]] as const;
type OptionalColumn = typeof OPTIONAL_COLUMNS[number][0];
const COLUMNS_STORAGE_KEY = "latchway.console.requests.columns";

function readColumns(): OptionalColumn[] {
  try {
    const stored: unknown = JSON.parse(window.localStorage.getItem(COLUMNS_STORAGE_KEY) ?? "[]");
    return Array.isArray(stored) ? OPTIONAL_COLUMNS.map(([id]) => id).filter((id) => stored.includes(id)) : [];
  } catch {
    return [];
  }
}

function writeColumns(columns: readonly OptionalColumn[]): void {
  try {
    window.localStorage.setItem(COLUMNS_STORAGE_KEY, JSON.stringify(columns));
  } catch {
    // The choice still applies until the page reloads.
  }
}

/** Wall-clock reads happen when a query runs or an export is made, never while rendering. */
const clock = (): number => Date.now();

const OUTCOMES = ["succeeded", "failed", "denied", "canceled", "unknown"] as const;
const PLATFORMS = ["ios", "android", "web", "react_native_ios", "react_native_android", "node"] as const;
const COMPONENT_KINDS = ["main_app", "widget", "share_extension", "app_intent_extension", "notification_service_extension", "action_extension", "sso_extension", "watch_extension", "android_app", "wear_app", "browser", "node_process"] as const;

/** Closes a popover on Escape or a press outside its anchor. */
function useDismiss(open: boolean, anchor: React.RefObject<HTMLElement | null>, close: () => void): void {
  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent): void {
      if (event.target instanceof Node && !anchor.current?.contains(event.target)) close();
    }
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape") {
        event.stopPropagation();
        close();
      }
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown, true);
    };
  }, [anchor, close, open]);
}

interface ValueFilterProps {
  emptyLabel?: string;
  label: string;
  onChange: (value: string | undefined) => void;
  /** A fixed set of values shown as a list; otherwise a validated text field. */
  options?: ReadonlyArray<{ label: string; value: string }>;
  pattern?: string;
  placeholder?: string;
  suggestions?: readonly string[];
  value?: string;
  valueLabel?: string;
}

/** A filter chip that opens a small panel to pick or type one exact value. */
function ValueFilter({ emptyLabel, label, onChange, options, pattern, placeholder, suggestions, value, valueLabel }: ValueFilterProps) {
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLSpanElement>(null);
  const id = useId();
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, anchor, close);

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const input = new FormData(event.currentTarget).get("value");
    const next = typeof input === "string" ? input.trim() : "";
    onChange(next || undefined);
    setOpen(false);
  }

  return (
    <span className="lw-anchor" ref={anchor}>
      <FilterChip emptyLabel={emptyLabel} label={label} onClear={() => onChange(undefined)} onClick={() => setOpen(!open)} value={value ? valueLabel ?? value : undefined} />
      {open ? (
        <div aria-label={`${label} filter`} className="lw-popover" role="dialog">
          {options ? (
            <Menu
              entries={[
                { heading: label, kind: "heading" },
                ...options.map((option): MenuEntry => ({ checked: option.value === value, label: option.label, onSelect: () => onChange(option.value) })),
                ...(value ? [{ kind: "separator" } as const, { label: "Any", onSelect: () => onChange(undefined) }] : [])
              ]}
              label={`${label} filter`}
              onClose={close}
            />
          ) : (
            <form className="lw-popover__form" onSubmit={submit}>
              <Field hint="Exact match." id={id} label={label}>
                <input className="lw-input lw-popover__input" data-autofocus defaultValue={value ?? ""} id={id} list={suggestions ? `${id}-list` : undefined} name="value" pattern={pattern} placeholder={placeholder} spellCheck={false} />
              </Field>
              {suggestions ? <datalist id={`${id}-list`}>{suggestions.map((suggestion) => <option key={suggestion} value={suggestion} />)}</datalist> : null}
              <div className="lw-range__foot">
                <Button onClick={close} size="sm">Cancel</Button>
                <Button size="sm" type="submit" variant="primary">Apply</Button>
              </div>
            </form>
          )}
        </div>
      ) : null}
    </span>
  );
}

function MoreFilters({ filters, onApply }: { filters: RequestFilters; onApply: (filters: RequestFilters) => void }) {
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLSpanElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, anchor, close);
  const count = MORE_FILTER_KEYS.filter((key) => filters[key] !== undefined).length;
  return (
    <span className="lw-anchor" ref={anchor}>
      <FilterChip
        label="More filters"
        onClear={count ? () => {
          const next = { ...filters };
          for (const key of MORE_FILTER_KEYS) delete next[key];
          onApply(next);
        } : undefined}
        onClick={() => setOpen(!open)}
        value={count ? String(count) : undefined}
      />
      {open ? <MoreFiltersPanel filters={filters} onApply={(next) => { setOpen(false); onApply(next); }} onCancel={close} /> : null}
    </span>
  );
}

function MoreFiltersPanel({ filters, onApply, onCancel }: { filters: RequestFilters; onApply: (filters: RequestFilters) => void; onCancel: () => void }) {
  const [draft, setDraft] = useState<MoreFilterDraft>(() => moreFilterDraft(filters));
  const [error, setError] = useState<string>();
  const set = (key: keyof MoreFilterDraft, value: string) => setDraft((current) => ({ ...current, [key]: value }));
  const range = (label: string, minimum: keyof MoreFilterDraft, maximum: keyof MoreFilterDraft, unit: string) => (
    <div className="lw-mf__row">
      <span className="lw-mf__label">{label}</span>
      <Input aria-label={`${label} at least`} inputMode="decimal" invalid={Boolean(error)} onChange={(event) => set(minimum, event.target.value)} placeholder="Min" value={draft[minimum]} />
      <span className="lw-faint">to</span>
      <Input aria-label={`${label} at most`} inputMode="decimal" invalid={Boolean(error)} onChange={(event) => set(maximum, event.target.value)} placeholder="Max" value={draft[maximum]} />
      <span className="lw-mf__unit">{unit}</span>
    </div>
  );
  return (
    <form aria-label="More filters" className="lw-mf" onSubmit={(event) => {
      event.preventDefault();
      const result = applyMoreFilters(filters, draft);
      if ("error" in result) setError(result.error);
      else onApply(result.filters);
    }} role="dialog">
      <strong className="lw-range__title">More filters</strong>
      {range("Duration", "duration_min_s", "duration_max_s", "seconds")}
      {range("Tokens", "tokens_min", "tokens_max", "tokens")}
      {range("Cost", "cost_min_usd", "cost_max_usd", "USD")}
      <div className="lw-mf__row">
        <label className="lw-mf__label" htmlFor="requests-component-kind">Component</label>
        <select className="lw-select" id="requests-component-kind" onChange={(event) => set("component_kind", event.target.value)} value={draft.component_kind}>
          <option value="">Any</option>
          {COMPONENT_KINDS.map((kind) => <option key={kind} value={kind}>{words(kind)}</option>)}
        </select>
      </div>
      <div className="lw-mf__row">
        <label className="lw-mf__label" htmlFor="requests-trust-source">Trust</label>
        <select className="lw-select" id="requests-trust-source" onChange={(event) => set("trust_source", event.target.value)} value={draft.trust_source}>
          <option value="">Any</option>
          {Object.entries(TRUST_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </div>
      {error ? <p className="lw-field__error" role="alert">{error}</p> : null}
      <div className="lw-range__foot">
        <Button onClick={onCancel} size="sm">Cancel</Button>
        <Button size="sm" type="submit" variant="primary">Apply</Button>
      </div>
    </form>
  );
}

function MenuButton({ children, entries, icon, label, size }: { children: ReactNode; entries: readonly MenuEntry[]; icon?: "upload" | "filter"; label: string; size?: "sm" }) {
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, anchor, close);
  return (
    <span className="lw-anchor" ref={anchor}>
      <button aria-expanded={open} aria-haspopup="menu" className={`lw-btn lw-btn--secondary${size ? ` lw-btn--${size}` : " lw-btn--lead"}`} onClick={() => setOpen(!open)} ref={button} type="button">
        {icon ? <Icon name={icon} /> : null}{children}
      </button>
      {open ? <div className="lw-popover lw-popover--end"><Menu entries={entries} label={label} onClose={() => { setOpen(false); button.current?.focus(); }} /></div> : null}
    </span>
  );
}

function download(filename: string, contents: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function notFoundProblem(requestID: string, scope: string): AdminProblem {
  return { code: "resource_not_found", detail: `No request ${requestID} in ${scope}. It may be older than what the server keeps, or belong to another environment.`, retryable: false, status: 404, title: "Request not found" };
}

const MISMATCH_PROBLEM: AdminProblem = { code: "invalid_response", detail: "The request detail did not match the selected request and environment.", retryable: true, status: 0, title: "Request detail mismatch" };

/** The server answered for a different request or environment than the one asked for. */
class RequestContextMismatch extends Error {}

function RequestsView() {
  const workspace = useWorkspace();
  const environment = workspace.environment;
  const environmentID = environment?.id ?? "";
  const search = RequestRouteSearchSchema.parse(workspace.search);
  const filters = filtersOf(search);
  const range = rangeOf(search);
  const pageSize = search.page_size ?? "50";
  const sort = search.sort ?? "started_at_desc";
  const scope = `${workspace.application?.display_name ?? "this application"} · ${environment?.display_name ?? "this environment"}`;
  const workspaceLinkSearch = { application: search.application, environment: search.environment, organization: search.organization };
  const [goValue, setGoValue] = useState("");
  const [goError, setGoError] = useState<string>();
  const [columns, setColumns] = useState<OptionalColumn[]>(readColumns);
  const [live, setLive] = useState(true);
  const [newArrivals, setNewArrivals] = useState(false);
  const [effective, setEffective] = useState<{ configuration: EffectiveConfiguration; requestID: string }>();
  const [explainProblem, setExplainProblem] = useState<{ problem: AdminProblem; requestID: string }>();
  const [explainBusy, setExplainBusy] = useState(false);
  const [copied, setCopied] = useState<string>();

  const listSearch = { ...search, request: undefined };
  const listKey = JSON.stringify(listSearch);
  const list = useInfiniteQuery({
    enabled: Boolean(environmentID),
    getNextPageParam: (last: LogicalRequestPage) => (last.page.has_more ? last.page.next_cursor : undefined),
    initialPageParam: search.cursor as string | undefined,
    queryFn: async ({ pageParam }): Promise<LogicalRequestPage> => (await adminRequest(queryPath("/admin/v1/requests", requestListQuery(listSearch, environmentID, clock(), pageParam)), RequestPageSchema)).data,
    queryKey: ["requests", environmentID, listKey],
    refetchOnWindowFocus: false,
    staleTime: Infinity
  });
  const rows = useMemo(() => list.data?.pages.flatMap((page) => page.items) ?? [], [list.data]);
  const hasMore = Boolean(list.hasNextPage);
  const loadedAt = list.dataUpdatedAt;

  const detail = useQuery({
    enabled: Boolean(environmentID && search.request),
    queryFn: async () => {
      const response = await adminRequest(`/admin/v1/requests/${search.request}`, RequestSchema);
      if (response.data.id !== search.request || response.data.environment_id !== environmentID) throw new RequestContextMismatch("request_context");
      return response.data;
    },
    queryKey: ["request", environmentID, search.request],
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: Infinity
  });
  const detailProblem = detail.error ? (detail.error instanceof RequestContextMismatch ? MISMATCH_PROBLEM : (() => {
    const problem = problemFromError(detail.error);
    return problem.status === 404 && search.request ? notFoundProblem(search.request, scope) : problem;
  })()) : undefined;

  useAdminRefreshTopic("requests", () => {
    // The stream carries hints, not data: new requests wait behind a pill so the list never shifts under the reader.
    if (live) setNewArrivals(true);
    if (search.request) void detail.refetch();
  }, Boolean(environmentID));

  const updateSearch = workspace.updateSearch;
  function update(patch: Partial<RequestRouteSearch>): void {
    setNewArrivals(false);
    updateSearch(patch);
  }

  const applyFilters = (next: RequestFilters) => update(filtersPatch(next));
  const setFilter = (key: FilterKey, value: string | undefined) => applyFilters({ ...filters, [key]: value });
  const select = useCallback((requestID: string | undefined) => updateSearch({ request: requestID }), [updateSearch]);

  const selectedIndex = rows.findIndex((row) => row.id === search.request);
  useEffect(() => {
    if (!search.request) return;
    function onKeyDown(event: KeyboardEvent): void {
      const target = event.target;
      if (target instanceof HTMLElement && (target.closest("input, textarea, select, [role='dialog'], [role='menu']") || target.isContentEditable)) return;
      if (event.key === "Escape") {
        select(undefined);
        return;
      }
      if (!/^(ArrowDown|ArrowUp|j|k)$/.test(event.key) || selectedIndex < 0) return;
      const next = event.key === "ArrowDown" || event.key === "j" ? Math.min(rows.length - 1, selectedIndex + 1) : Math.max(0, selectedIndex - 1);
      const nextRow = rows[next];
      if (next !== selectedIndex && nextRow) {
        event.preventDefault();
        select(nextRow.id);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [rows, search.request, select, selectedIndex]);

  function goTo(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const target = goToTarget(goValue);
    if (target.kind === "request") {
      setGoError(undefined);
      setGoValue("");
      select(target.id);
    } else if (target.kind === "user") {
      setGoError(undefined);
      setGoValue("");
      applyFilters({ ...filters, user_id: target.id });
    } else {
      setGoError("Search isn't available. Paste a req_ ID to open a request, or a usr_ ID to filter by user.");
    }
  }

  async function explain(request: LogicalRequest): Promise<void> {
    setExplainBusy(true);
    setExplainProblem(undefined);
    try {
      const response = await getRequestEffectiveConfiguration(request.id);
      if (response.data.subject.id !== request.id || response.data.environment_id !== request.environment_id || response.data.revision_id !== request.config_revision_id) {
        throw { code: "invalid_response", detail: "The recorded explanation did not match the selected request, environment, and revision.", retryable: true, status: 0, title: "Request explanation mismatch" } satisfies AdminProblem;
      }
      setEffective({ configuration: response.data, requestID: request.id });
    } catch (error) {
      setEffective(undefined);
      setExplainProblem({ problem: error && typeof error === "object" && "title" in error && "code" in error ? error as AdminProblem : problemFromError(error), requestID: request.id });
    } finally {
      setExplainBusy(false);
    }
  }

  function copyQuery(): void {
    const command = curlCommand(window.location.origin, requestListQuery(listSearch, environmentID, clock()));
    try {
      void navigator.clipboard.writeText(command).then(() => setCopied("API query copied. The CLI's requests list doesn't take filters yet."), () => setCopied(command));
    } catch {
      setCopied(command);
    }
  }

  const quickView = activeQuickView(filters);
  const filtered = Object.keys(filters).length > 0;
  const selected = detail.data && detail.data.id === search.request ? detail.data : undefined;

  const tableColumns: Array<Column<LogicalRequest>> = [
    { header: "Time", key: "time", render: (row) => <span className="lw-secondary lw-num" title={formatUtc(row.started_at)}>{formatClock(row.started_at, loadedAt)}</span> },
    {
      header: "Outcome",
      key: "outcome",
      render: (row) => (
        <span className="lw-rq-outcell">
          <StatusBadge status={outcomeStatus(row.status)}>{capitalize(row.status)}</StatusBadge>
          {row.failure_code ? <span className="lw-rq-code lw-mono">{row.failure_code}</span> : null}
        </span>
      )
    },
    { header: "Feature", key: "feature", render: (row) => row.feature },
    { header: "User", key: "user", render: (row) => <span className="lw-mono lw-mono--sm" title={row.user_id}>{shortId(row.user_id)}</span> },
    {
      header: "Model on connection",
      key: "model",
      render: (row) => {
        const route = routeSummary(row);
        if (route.kind === "not-routed") return <span className="lw-faint">Not routed</span>;
        if (route.kind === "not-sent") return <span className="lw-faint">Not sent · {route.model}</span>;
        return (
          <span className="lw-rq-model">
            <span className="lw-mono">{route.model}</span>
            <span className="lw-faint">{route.upstream}</span>
            {row.attempts.length > 1 ? <span className="lw-rq-retry" title={`${row.attempts.length} attempts: ${row.attempts.map((attempt) => `${attempt.upstream} ${attempt.status}`).join(", ")}`}>↻{row.attempts.length}</span> : null}
          </span>
        );
      }
    },
    ...columns.map((column): Column<LogicalRequest> => {
      if (column === "trust") return { header: "Trust", key: "trust", render: (row) => row.trust_source ? <span className="lw-secondary">{TRUST_LABEL[row.trust_source] ?? words(row.trust_source)}</span> : <span className="lw-faint">—</span> };
      if (column === "route") return { header: "Route", key: "route", render: (row) => row.selected_route ? <span className="lw-mono lw-mono--sm">{row.selected_route}</span> : <span className="lw-faint">—</span> };
      if (column === "revision") return { header: "Revision", key: "revision", render: (row) => <span className="lw-mono lw-mono--sm">{shortId(row.config_revision_id)}</span> };
      return { header: "Plan", key: "plan", render: (row) => row.selected_limit_plan };
    }),
    {
      align: "right",
      header: "Duration",
      key: "duration",
      render: (row) => {
        const ttft = timeToFirstToken(row);
        return <span className="lw-rq-dur"><span className="lw-num">{formatMs(requestDuration(row))}</span>{ttft !== undefined ? <span className="lw-faint lw-num">first {formatMs(ttft)}</span> : null}</span>;
      }
    },
    { align: "right", header: "Tokens", key: "tokens", render: (row) => { const cell = metricCell(row.usage, "total_tokens"); return <span className={cell.recorded ? "lw-num" : "lw-faint"} title={cell.recorded ? (cell.estimated ? "Includes estimated or unknown units" : undefined) : "No record"}>{cell.text}</span>; } },
    { align: "right", header: "Cost", key: "cost", render: (row) => { const cell = metricCell(row.usage, "cost_nano_usd"); return <span className={cell.recorded ? "lw-num" : "lw-faint"} title={cell.recorded ? (cell.estimated ? "Estimated" : "Recorded") : "No record"}>{cell.text}</span>; } }
  ];

  const empty = filtered || range.id !== "all"
    ? <EmptyState action={<Button onClick={() => update({ ...filtersPatch({}), ...rangePatch({ id: "all" }) })}>Clear Filters</Button>} icon="search" orientation="horizontal" title="No requests match">Try a longer time range or remove a filter.</EmptyState>
    : <EmptyState action={<Link className="lw-btn lw-btn--secondary" search={workspaceLinkSearch} to="/features">Open Features</Link>} icon="requests" orientation="horizontal" title="No requests yet">Requests appear here as soon as an app calls a feature through Latchway.</EmptyState>;

  return (
    <div className="lw-page lw-requests">
      <PageHeader
        actions={
          <div className="lw-an-actions">
            <RangePicker
              maxDays={CUSTOM_RANGE_MAX_DAYS}
              onChange={(next) => update(rangePatch(next))}
              presets={[...RANGE_PRESETS, { id: "all", label: "All" }]}
              value={range}
            />
            <MenuButton entries={[
              { heading: `${rows.length} loaded row${rows.length === 1 ? "" : "s"}`, kind: "heading" },
              { label: "CSV without user IDs", onSelect: () => download(`requests-${environment?.slug ?? "environment"}.csv`, requestsCsv(rows, false)) },
              { label: "CSV with user IDs", onSelect: () => download(`requests-${environment?.slug ?? "environment"}-with-users.csv`, requestsCsv(rows, true)) },
              { kind: "separator" },
              { icon: "code", label: "Copy API Query", onSelect: copyQuery }
            ]} icon="upload" label="Export">Export</MenuButton>
          </div>
        }
        badge={
          <button aria-pressed={live} className={`lw-livebtn${live ? "" : " is-paused"}`} onClick={() => { setLive(!live); if (live) setNewArrivals(false); }} title={live ? "Pause new-request notices" : "Resume new-request notices"} type="button">
            <span aria-hidden="true" className="lw-livebtn__dot" />{live ? "Live" : "Paused"}
          </button>
        }
        description="Every request your apps sent through Latchway: its outcome, route, timing and cost. Prompts and responses are never stored."
        title="Requests"
      />
      {copied ? <div className="lw-page-notice"><Notice action={<Button onClick={() => setCopied(undefined)} size="sm">Dismiss</Button>} title={copied.startsWith("curl") ? "Copy this API query" : "Copied"} tone="success">{copied.startsWith("curl") ? <pre className="lw-code-block">{copied}</pre> : copied}</Notice></div> : null}

      <div aria-label="Quick views" className="lw-rq-views" role="group">
        {QUICK_VIEWS.map((view) => (
          <button aria-pressed={quickView?.id === view.id} className="lw-pill" key={view.id} onClick={() => applyFilters(view.filters)} type="button">
            {view.label}{view.hint ? <span className="lw-faint"> {view.hint}</span> : null}
          </button>
        ))}
      </div>

      <Toolbar
        className="lw-toolbar--wrap"
        search={
          <form className="lw-rq-go" onSubmit={goTo} role="search">
            <Input aria-label="Go to a request or user ID" boxClassName="lw-search" onChange={(event) => { setGoValue(event.target.value); setGoError(undefined); }} placeholder="Go to req_… or usr_…" prefix="search" spellCheck={false} value={goValue} />
            {goError ? <span className="lw-rq-go__err" role="status">{goError}</span> : null}
          </form>
        }
      >
        <ValueFilter label="Outcome" onChange={(value) => setFilter("status", value)} options={OUTCOMES.map((value) => ({ label: capitalize(value), value }))} value={filters.status} valueLabel={filters.status && capitalize(filters.status)} />
        <ValueFilter label="Feature" onChange={(value) => setFilter("feature", value)} pattern="[a-z][a-z0-9_\-]{0,62}" placeholder="feature-key" value={filters.feature} />
        <ValueFilter label="Error" onChange={(value) => setFilter("error_code", value)} pattern="[a-z][a-z0-9_]{0,99}" placeholder="quota_exceeded" suggestions={ERROR_FILTER_SUGGESTIONS} value={filters.error_code} />
        <ValueFilter label="AI connection" onChange={(value) => setFilter("upstream", value)} pattern="[a-z][a-z0-9_\-]{0,62}" placeholder="connection-key" value={filters.upstream} />
        <ValueFilter label="Model" onChange={(value) => setFilter("model", value)} placeholder="Model key or provider model" value={filters.model} />
        <ValueFilter label="Route" onChange={(value) => setFilter("route", value)} pattern="[a-z][a-z0-9_\-]{0,62}" placeholder="route-key" value={filters.route} />
        <ValueFilter label="Platform" onChange={(value) => setFilter("platform", value)} options={PLATFORMS.map((value) => ({ label: PLATFORM_LABEL[value] ?? value, value }))} value={filters.platform} valueLabel={filters.platform && PLATFORM_LABEL[filters.platform]} />
        {filters.user_id ? <FilterChip label="User" onClear={() => setFilter("user_id", undefined)} value={shortId(filters.user_id)} /> : null}
        {filters.request_id ? <FilterChip label="Request" onClear={() => setFilter("request_id", undefined)} value={shortId(filters.request_id)} /> : null}
        <MoreFilters filters={filters} onApply={applyFilters} />
      </Toolbar>

      <div className="lw-rq-bar">
        <span>{sort === "started_at_asc" ? "Oldest first" : "Newest first"}{filtered ? " · filtered" : ""}{range.id === "between" ? " · open-ended time range" : ""}</span>
        <span className="lw-spacer" />
        {newArrivals ? (
          <button className="lw-rq-new" onClick={() => { setNewArrivals(false); void list.refetch(); }} type="button">
            <Icon name="arrowUp" size={12} />New requests may have arrived · Show
          </button>
        ) : null}
        <Button aria-label="Refresh requests" icon="refresh" loading={list.isFetching && !list.isFetchingNextPage} onClick={() => { setNewArrivals(false); void list.refetch(); }} size="sm" variant="ghost" />
        <Segmented items={[{ id: "started_at_desc", label: "Newest" }, { id: "started_at_asc", label: "Oldest" }]} label="Sort" onChange={(value) => update({ cursor: undefined, sort: value === "started_at_desc" ? undefined : value })} value={sort} />
        <MenuButton entries={[
          { heading: "Add columns", kind: "heading" },
          ...OPTIONAL_COLUMNS.map(([id, label]): MenuEntry => {
            const on = columns.includes(id);
            return { checked: on, label, onSelect: () => { const next = on ? columns.filter((column) => column !== id) : [...columns, id]; setColumns(next); writeColumns(next); } };
          })
        ]} icon="filter" label="Columns" size="sm">Columns{columns.length ? ` · ${columns.length}` : ""}</MenuButton>
      </div>

      {list.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(list.error)} /></div> : null}
      {list.isPending ? <p className="lw-page-status" role="status">Loading requests…</p> : rows.length ? (
        <DataTable caption="Requests" columns={tableColumns} onSelect={(row) => select(row.id)} rowKey={(row) => row.id} rows={rows} selectedKey={search.request} />
      ) : list.isSuccess ? <div className="lw-page-empty">{empty}</div> : null}

      <div className="lw-rq-foot">
        <span>{rows.length ? `${rows.length} shown${hasMore ? " · more available" : " · that's all"}` : ""}</span>
        {hasMore ? <Button loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()} size="sm">Load {pageSize} More</Button> : null}
        <span className="lw-spacer" />
        <span className="lw-faint">↑ ↓ move between requests · totals are in <Link className="lw-link" search={workspaceLinkSearch} to="/usage">Analytics</Link></span>
        <Segmented items={PAGE_SIZES.map((size) => ({ id: size, label: size }))} label="Page size" onChange={(value) => update({ cursor: undefined, page_size: value === "50" ? undefined : value })} value={pageSize} />
      </div>

      {search.request ? (
        <div className="lw-drawer-dock">
          {selected ? (
            <RequestDetail
              effective={effective?.requestID === selected.id ? effective.configuration : undefined}
              explainBusy={explainBusy}
              explainProblem={explainProblem?.requestID === selected.id ? explainProblem.problem : undefined}
              key={selected.id}
              onClose={() => select(undefined)}
              onExplain={() => void explain(selected)}
              onFilter={(next) => applyFilters(next)}
              renderEffective={(configuration) => <EffectiveConfigurationPanel configuration={configuration} />}
              renderProblem={(problem) => <ProblemNotice problem={problem} />}
              request={selected}
              workspaceSearch={workspaceLinkSearch}
            />
          ) : (
            <aside aria-label={search.request} className="lw-drawer lw-request-drawer">
              <div className="lw-drawer__head">
                <div className="lw-drawer__lead">
                  <button aria-label="Close" className="lw-drawer__close" onClick={() => select(undefined)} type="button"><Icon name="x" /></button>
                  <div className="lw-drawer__titles"><h2 className="lw-drawer__title lw-mono">{search.request}</h2></div>
                </div>
              </div>
              <div className="lw-drawer__body">
                {detailProblem ? <ProblemNotice problem={detailProblem} /> : <p role="status">Loading request…</p>}
              </div>
            </aside>
          )}
        </div>
      ) : null}
    </div>
  );
}

function RequestsWorkspace() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <RequestsView />;
}

/** Traffic → Requests: individual requests for the selected environment, from GET /admin/v1/requests. */
export function RequestsPage() {
  return <EnvironmentRequired><RequestsWorkspace /></EnvironmentRequired>;
}

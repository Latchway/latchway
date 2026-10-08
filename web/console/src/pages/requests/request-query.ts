import { CLIENT_REQUEST_ID_PATTERN } from "../../api/admin";
import type { RequestRouteSearch } from "../../app/route-search";
import type { RangeValue } from "../../ui";

export const RANGE_PRESETS = ["15m", "1h", "24h", "7d"] as const;
export type RangePreset = typeof RANGE_PRESETS[number];
const RANGE_MS: Record<RangePreset, number> = { "15m": 900_000, "1h": 3_600_000, "24h": 86_400_000, "7d": 604_800_000 };

/** Custom ranges are whole UTC days, up to the 90 days of requests the console offers to browse. */
export const CUSTOM_RANGE_MAX_DAYS = 90;

export const PAGE_SIZES = ["50", "100", "200"] as const;

/** The filters that map one-to-one onto GET /admin/v1/requests parameters (everything but time, sort and paging). */
export const FILTER_KEYS = [
  "status", "feature", "user_id", "platform", "component_kind", "trust_source", "route", "upstream", "model",
  "error_code", "request_id", "client_request_id", "latency_min_ms", "latency_max_ms", "tokens_min", "tokens_max",
  "cost_min_nano_usd", "cost_max_nano_usd"
] as const satisfies ReadonlyArray<keyof RequestRouteSearch>;
export type FilterKey = typeof FILTER_KEYS[number];
export type RequestFilters = Partial<Record<FilterKey, string>>;

export const MORE_FILTER_KEYS = [
  "latency_min_ms", "latency_max_ms", "tokens_min", "tokens_max", "cost_min_nano_usd", "cost_max_nano_usd", "component_kind", "trust_source"
] as const satisfies readonly FilterKey[];

export interface QuickView {
  filters: RequestFilters;
  hint?: string;
  id: string;
  label: string;
}

/** Built-in views; each is a plain set of API filters. */
export const QUICK_VIEWS: readonly QuickView[] = [
  { filters: {}, id: "all", label: "All" },
  { filters: { status: "failed" }, id: "failed", label: "Failed" },
  { filters: { status: "denied" }, id: "denied", label: "Denied" },
  { filters: { latency_min_ms: "2000" }, hint: "over 2 s", id: "slow", label: "Slow" },
  { filters: { cost_min_nano_usd: "20000000" }, hint: "over $0.02", id: "expensive", label: "Expensive" }
];

export function filtersOf(search: RequestRouteSearch): RequestFilters {
  const filters: RequestFilters = {};
  for (const key of FILTER_KEYS) {
    const value = search[key];
    if (value !== undefined && value !== "") filters[key] = value;
  }
  return filters;
}

export function activeQuickView(filters: RequestFilters): QuickView | undefined {
  const keys = Object.keys(filters) as FilterKey[];
  return QUICK_VIEWS.find((view) => {
    const viewKeys = Object.keys(view.filters) as FilterKey[];
    return viewKeys.length === keys.length && viewKeys.every((key) => view.filters[key] === filters[key]);
  });
}

/** A URL patch that replaces every filter (absent keys are cleared) and drops paging and the open record. */
export function filtersPatch(filters: RequestFilters): Partial<RequestRouteSearch> {
  const patch: Record<string, string | undefined> = { cursor: undefined, request: undefined };
  for (const key of FILTER_KEYS) patch[key] = filters[key];
  return patch as Partial<RequestRouteSearch>;
}

/** The range the URL describes: a preset, a custom start/end, or everything the server keeps. */
export function rangeOf(search: RequestRouteSearch): RangeValue {
  if (search.range) return { id: search.range };
  if (search.start && search.end) return { end: Date.parse(search.end), id: "custom", start: Date.parse(search.start) };
  if (search.start || search.end) return { id: "between" };
  return { id: "all" };
}

export function rangePatch(range: RangeValue): Partial<RequestRouteSearch> {
  if (range.id === "custom" && "start" in range) {
    return { cursor: undefined, end: new Date(range.end).toISOString(), range: undefined, start: new Date(range.start).toISOString() };
  }
  if ((RANGE_PRESETS as readonly string[]).includes(range.id)) {
    return { cursor: undefined, end: undefined, range: range.id as RangePreset, start: undefined };
  }
  return { cursor: undefined, end: undefined, range: undefined, start: undefined };
}

/** The [start, end) bounds sent to the API. Presets are relative to `now`, so a refresh moves the window forward. */
export function timeBounds(search: RequestRouteSearch, now: number): { end?: string; start?: string } {
  if (search.range) return { start: new Date(now - RANGE_MS[search.range]).toISOString() };
  return { end: search.end, start: search.start };
}

/** Query parameters for GET /admin/v1/requests, in a stable order. `includeTotal` asks for the capped match count. */
export function requestListQuery(search: RequestRouteSearch, environmentID: string, now: number, cursor?: string, includeTotal = false): Record<string, string | undefined> {
  const bounds = timeBounds(search, now);
  const query: Record<string, string | undefined> = {
    cursor,
    end: bounds.end,
    environment_id: environmentID,
    include_total: includeTotal ? "true" : undefined,
    page_size: search.page_size ?? "50",
    sort: search.sort,
    start: bounds.start
  };
  for (const key of FILTER_KEYS) query[key] = search[key];
  return query;
}

/**
 * A query counting requests that started at or after `since` (a server timestamp), with the list's filters.
 * Only meaningful for newest-first lists without a fixed end; returns undefined otherwise.
 */
export function newArrivalsQuery(search: RequestRouteSearch, environmentID: string, since: string | undefined, now: number): Record<string, string | undefined> | undefined {
  if ((search.sort ?? "started_at_desc") !== "started_at_desc" || search.end) return undefined;
  const query = requestListQuery({ ...search, page_size: "50" }, environmentID, now, undefined, true);
  query.page_size = "1";
  if (since) query.start = since;
  return query;
}

const DAY_MS = 86_400_000;

/**
 * The [start, end) range facet counts cover: the list's own range when it has one, otherwise the last 7 days.
 * The server counts at most 90 days.
 */
export function facetRange(search: RequestRouteSearch, now: number): { end: string; fallback: boolean; start: string } {
  if (search.range) return { end: new Date(now).toISOString(), fallback: false, start: new Date(now - RANGE_MS[search.range]).toISOString() };
  if (search.start && search.end && Date.parse(search.end) - Date.parse(search.start) <= CUSTOM_RANGE_MAX_DAYS * DAY_MS) {
    return { end: search.end, fallback: false, start: search.start };
  }
  return { end: new Date(now).toISOString(), fallback: true, start: new Date(now - 7 * DAY_MS).toISOString() };
}

const CLI_FLAG: Partial<Record<string, string>> = { environment_id: "environment", user_id: "user" };

/** The current query as a `latchway requests list` command; the token comes from the CLI's usual configuration. */
export function cliCommand(query: Record<string, string | undefined>): string {
  const parts = ["latchway requests list"];
  for (const [key, value] of Object.entries(query).sort(([a], [b]) => a.localeCompare(b))) {
    if (value === undefined || value === "" || key === "cursor") continue;
    if (key === "include_total") {
      parts.push("--total");
      continue;
    }
    const flag = CLI_FLAG[key] ?? key.replaceAll("_", "-");
    parts.push(`--${flag} ${/^[A-Za-z0-9._:/@+-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`}`);
  }
  return parts.join(" \\\n  ");
}

/** The current query as a curl command against the Admin API, reading the token from the environment. */
export function curlCommand(origin: string, query: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query).sort(([a], [b]) => a.localeCompare(b))) {
    if (value !== undefined && value !== "" && key !== "cursor") params.set(key, value);
  }
  return `curl -s -H "Authorization: Bearer $LATCHWAY_ADMIN_API_TOKEN" \\\n  "${origin}/admin/v1/requests?${params.toString()}"`;
}

export type GoToTarget = { kind: "client"; id: string } | { kind: "request"; id: string } | { kind: "user"; id: string } | { kind: "invalid" };

const REQUEST_ID = /^req_[A-Za-z0-9_-]{16,128}$/;
const USER_ID = /^usr_[A-Za-z0-9_-]{16,128}$/;

/** The search box: a request ID opens it, a user ID filters by user, anything else shaped like a client request ID searches by it. */
export function goToTarget(value: string): GoToTarget {
  const trimmed = value.trim();
  if (REQUEST_ID.test(trimmed)) return { id: trimmed, kind: "request" };
  if (USER_ID.test(trimmed)) return { id: trimmed, kind: "user" };
  if (CLIENT_REQUEST_ID_PATTERN.test(trimmed)) return { id: trimmed, kind: "client" };
  return { kind: "invalid" };
}

export interface MoreFilterDraft {
  component_kind: string;
  cost_max_usd: string;
  cost_min_usd: string;
  duration_max_s: string;
  duration_min_s: string;
  tokens_max: string;
  tokens_min: string;
  trust_source: string;
}

export function moreFilterDraft(filters: RequestFilters): MoreFilterDraft {
  const seconds = (ms?: string) => (ms === undefined ? "" : String(Number(ms) / 1_000));
  const dollars = (nano?: string) => (nano === undefined ? "" : String(Number(nano) / 1_000_000_000));
  return {
    component_kind: filters.component_kind ?? "",
    cost_max_usd: dollars(filters.cost_max_nano_usd),
    cost_min_usd: dollars(filters.cost_min_nano_usd),
    duration_max_s: seconds(filters.latency_max_ms),
    duration_min_s: seconds(filters.latency_min_ms),
    tokens_max: filters.tokens_max ?? "",
    tokens_min: filters.tokens_min ?? "",
    trust_source: filters.trust_source ?? ""
  };
}

const DECIMAL = /^(0|[1-9]\d*)(\.\d+)?$/;

/** Converts a decimal string to an integer number of `scale` units without floating-point error. */
function scaled(value: string, scale: number): string | undefined {
  if (!DECIMAL.test(value)) return undefined;
  const digits = String(scale).length - 1;
  const [whole = "0", fraction = ""] = value.split(".");
  const padded = (fraction + "0".repeat(digits)).slice(0, digits);
  if (fraction.length > digits && /[1-9]/.test(fraction.slice(digits))) return undefined;
  return String(BigInt(whole) * BigInt(scale) + BigInt(padded || "0"));
}

/**
 * Applies the More filters panel: durations in seconds become milliseconds and dollars become integer nano-USD.
 * Returns an error instead when a value isn't a non-negative number or a minimum exceeds its maximum.
 */
export function applyMoreFilters(filters: RequestFilters, draft: MoreFilterDraft): { error: string } | { filters: RequestFilters } {
  const error = { error: "Use numbers, with the minimum no larger than the maximum." };
  const convert = (value: string, scale: number): string | undefined | null => {
    const trimmed = value.trim();
    if (!trimmed) return undefined;
    return scaled(trimmed, scale) ?? null;
  };
  const values = {
    cost_max_nano_usd: convert(draft.cost_max_usd, 1_000_000_000),
    cost_min_nano_usd: convert(draft.cost_min_usd, 1_000_000_000),
    latency_max_ms: convert(draft.duration_max_s, 1_000),
    latency_min_ms: convert(draft.duration_min_s, 1_000),
    tokens_max: convert(draft.tokens_max, 1),
    tokens_min: convert(draft.tokens_min, 1)
  };
  if (Object.values(values).some((value) => value === null)) return error;
  const pairs: Array<[string | undefined | null, string | undefined | null]> = [
    [values.latency_min_ms, values.latency_max_ms], [values.tokens_min, values.tokens_max], [values.cost_min_nano_usd, values.cost_max_nano_usd]
  ];
  if (pairs.some(([minimum, maximum]) => minimum && maximum && BigInt(minimum) > BigInt(maximum))) return error;
  const next: RequestFilters = { ...filters };
  for (const key of MORE_FILTER_KEYS) delete next[key];
  for (const [key, value] of Object.entries(values)) if (value) next[key as FilterKey] = value;
  if (draft.component_kind) next.component_kind = draft.component_kind;
  if (draft.trust_source) next.trust_source = draft.trust_source;
  return { filters: next };
}

import type { JSONRecord } from "../configuration-slice";

/** Usage-record metrics the server can sum per user and window. */
const DISTRIBUTION_METRICS = new Set([
  "logical_requests", "upstream_attempts", "input_tokens", "output_tokens", "total_tokens",
  "reasoning_tokens", "cached_input_tokens", "cache_write_tokens", "cost_nano_usd"
]);
const DISTRIBUTION_SCOPES = new Set(["user", "feature", "installation"]);
const WINDOW = /^[1-9][0-9]*(m|h|d|w|mo)$/;

export interface ProjectableLimit {
  maximum: number;
  metric: string;
  scope: string[];
  timezone?: string;
  window: string;
}

/**
 * The limit as a usage-distribution query, or undefined when the server can't count it: only calendar limits on a
 * usage metric, scoped to users, features or installations, have a per-window total to compare with.
 */
export function projectableLimit(limit: JSONRecord): ProjectableLimit | undefined {
  const { algorithm, maximum, metric, scope, timezone, window } = limit;
  if ((algorithm ?? "calendar") !== "calendar" || typeof metric !== "string" || !DISTRIBUTION_METRICS.has(metric)) return undefined;
  if (typeof maximum !== "number" || !Number.isSafeInteger(maximum) || maximum < 0) return undefined;
  if (typeof window !== "string" || !WINDOW.test(window)) return undefined;
  if (!Array.isArray(scope) || !scope.length || !scope.every((value) => typeof value === "string" && DISTRIBUTION_SCOPES.has(value))) return undefined;
  return { maximum, metric, scope: scope as string[], timezone: typeof timezone === "string" ? timezone : undefined, window };
}

/**
 * How far back to look for a window: a month of daily or shorter windows, two months of weekly ones, and the
 * server's 90-day limit for monthly ones. Fine-grained windows look back less, to stay within 2,000 windows.
 */
export function impactRange(window: string, now: number): { days: number; end: string; start: string } {
  const unit = /(m|h|d|w|mo)$/.exec(window)?.[1];
  const amount = Number.parseInt(window, 10) || 1;
  let days = 30;
  if (unit === "w") days = 60;
  if (unit === "mo") days = 90;
  if (unit === "m") days = Math.max(1, Math.min(30, Math.floor((1_900 * amount) / (24 * 60))));
  if (unit === "h") days = Math.max(1, Math.min(30, Math.floor((1_900 * amount) / 24)));
  return { days, end: new Date(now).toISOString(), start: new Date(now - days * 86_400_000).toISOString() };
}

import type { z } from "zod";

import type { UsageSummary, UsageTimeseries, UsageValuesSchema } from "../../api/admin";
import type { AnalyticsRouteSearch } from "../../app/route-search";
import type { RangeValue } from "../../ui";
import { formatUsd } from "../requests/request-format";

export type UsageValues = z.infer<typeof UsageValuesSchema>;
export type Metric = "logical_requests" | "input_tokens" | "output_tokens" | "total_tokens" | "cost_nano_usd";

export const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;
export const PERIOD_PRESETS = ["24h", "7d", "30d", "90d"] as const;
export type PeriodPreset = typeof PERIOD_PRESETS[number];
export const DEFAULT_PERIOD: PeriodPreset = "7d";
export const CUSTOM_PERIOD_MAX_DAYS = 366;

export interface UsageWindow {
  /** Exclusive end sent to the API. Presets end now, so the last bucket is still counting. */
  end: number;
  interval: "hour" | "day";
  /** True when the window reaches the present and its last bucket is incomplete. */
  partialLast: boolean;
  /** How far back the comparison window sits: a whole number of buckets, so like compares with like. */
  shift: number;
  start: number;
}

export function periodOf(search: AnalyticsRouteSearch): RangeValue {
  if (search.start && search.end) return { end: Date.parse(search.end), id: "custom", start: Date.parse(search.start) };
  return { id: search.period ?? DEFAULT_PERIOD };
}

export function periodPatch(period: RangeValue): Partial<AnalyticsRouteSearch> {
  if (period.id === "custom" && "start" in period) {
    return { end: new Date(period.end).toISOString(), period: undefined, start: new Date(period.start).toISOString() };
  }
  return { end: undefined, period: period.id === DEFAULT_PERIOD ? undefined : period.id as PeriodPreset, start: undefined };
}

const PRESET_DAYS: Record<Exclude<PeriodPreset, "24h">, number> = { "30d": 30, "7d": 7, "90d": 90 };

/** The UTC buckets a period covers. Custom periods of two days or less use hourly buckets. */
export function usageWindow(period: RangeValue, now: number): UsageWindow {
  if (period.id === "custom" && "start" in period) {
    const length = period.end - period.start;
    return { end: period.end, interval: length <= 2 * DAY_MS ? "hour" : "day", partialLast: period.end > now, shift: length, start: period.start };
  }
  if (period.id === "24h") {
    const start = Math.floor(now / HOUR_MS) * HOUR_MS - 23 * HOUR_MS;
    return { end: now, interval: "hour", partialLast: true, shift: 24 * HOUR_MS, start };
  }
  const days = PRESET_DAYS[period.id as Exclude<PeriodPreset, "24h">] ?? 7;
  return { end: now, interval: "day", partialLast: true, shift: days * DAY_MS, start: Math.floor(now / DAY_MS) * DAY_MS - (days - 1) * DAY_MS };
}

export function previousWindow(window: UsageWindow): UsageWindow {
  return { ...window, end: window.end - window.shift, partialLast: false, start: window.start - window.shift };
}

export function bucketSize(window: UsageWindow): number {
  return window.interval === "hour" ? HOUR_MS : DAY_MS;
}

export function iso(ms: number): string {
  return new Date(ms).toISOString().replace(".000Z", "Z");
}

const MONTH_DAY: Intl.DateTimeFormatOptions = { day: "numeric", month: "short", timeZone: "UTC" };

/** "Aug 31 – Sep 29, 2026 (UTC days)" or "Sep 28, 15:00 – Sep 29, 15:40 UTC". */
export function windowLabel(window: UsageWindow): string {
  if (window.interval === "hour") {
    const time: Intl.DateTimeFormatOptions = { ...MONTH_DAY, hour: "2-digit", hourCycle: "h23", minute: "2-digit" };
    return `${new Date(window.start).toLocaleString("en-US", time)} – ${new Date(window.end).toLocaleString("en-US", time)} UTC`;
  }
  const first = new Date(window.start).toLocaleDateString("en-US", MONTH_DAY);
  const last = new Date(window.end - 1).toLocaleDateString("en-US", { ...MONTH_DAY, year: "numeric" });
  return `${first} – ${last} (UTC days)`;
}

export interface Bucket {
  label: string;
  start: number;
  title: string;
  values?: UsageValues;
}

/** Every bucket in the window, in order, with the server's values where it returned any. */
export function buckets(window: UsageWindow, series: UsageTimeseries | undefined): Bucket[] {
  const size = bucketSize(window);
  const byStart = new Map((series?.points ?? []).map((point) => [Date.parse(point.timestamp), point.values]));
  const result: Bucket[] = [];
  for (let start = Math.floor(window.start / size) * size; start < window.end; start += size) {
    const date = new Date(start);
    const label = window.interval === "hour"
      ? date.toLocaleTimeString("en-US", { hour: "2-digit", hourCycle: "h23", minute: "2-digit", timeZone: "UTC" })
      : date.toLocaleDateString("en-US", MONTH_DAY);
    const title = window.interval === "hour"
      ? `${date.toLocaleDateString("en-US", MONTH_DAY)}, ${label}–${new Date(start + size).toLocaleTimeString("en-US", { hour: "2-digit", hourCycle: "h23", minute: "2-digit", timeZone: "UTC" })} UTC`
      : `${date.toLocaleDateString("en-US", { ...MONTH_DAY, year: "numeric" })} (UTC)`;
    result.push({ label, start, title, values: byStart.get(start) });
  }
  return result;
}

/** A metric's recorded units, or null when nothing was recorded (never shown as zero). */
export function recorded(values: UsageValues | undefined, metric: Metric): number | null {
  if (!values) return null;
  if (metric === "logical_requests") return values.logical_requests;
  const details = values.details?.[metric];
  if (details) return details.recorded_units;
  return values[metric];
}

/** 912, 12.4K, 44.3M, 1.2B. */
export function formatCount(value: number | null): string {
  if (value === null) return "—";
  if (value < 1_000) return value.toLocaleString();
  const [divisor, suffix] = value >= 1e9 ? [1e9, "B"] : value >= 1e6 ? [1e6, "M"] : [1e3, "K"];
  const scaled = value / divisor;
  return `${scaled.toLocaleString("en-US", { maximumFractionDigits: scaled < 100 ? 1 : 0 })}${suffix}`;
}

export function formatMoney(nano: number | null): string {
  return nano === null ? "—" : formatUsd(Math.round(nano));
}

/** Chart axis money: $0, $0.005, $0.50, $12. */
export function formatAxisMoney(nano: number): string {
  if (!nano) return "$0";
  const dollars = nano / 1e9;
  return `$${dollars.toLocaleString("en-US", { maximumFractionDigits: dollars >= 10 ? 0 : dollars >= 0.1 ? 2 : 3 })}`;
}

export function percent(numerator: number, denominator: number, digits = 1): string {
  if (!denominator) return "—";
  const value = (numerator / denominator) * 100;
  if (value > 0 && value < 10 ** -digits) return `<${10 ** -digits}%`;
  return `${value.toLocaleString("en-US", { maximumFractionDigits: digits })}%`;
}

/** Percent change, rounded; undefined when there's no earlier value to compare with. */
export function percentChange(current: number | null, previous: number | null | undefined): number | undefined {
  if (current === null || previous === null || previous === undefined || previous === 0) return undefined;
  return Math.round(((current - previous) / previous) * 1000) / 10;
}

type Rate = UsageSummary["analytics"]["failure_rate"];

/** Change in percentage points, with enough decimals to show a real difference as non-zero. */
export function pointChange(current: Rate, previous: Rate | undefined): number | undefined {
  if (!previous || !current.denominator || !previous.denominator) return undefined;
  const difference = (current.parts_per_million - previous.parts_per_million) / 10_000;
  if (difference === 0) return 0;
  for (const digits of [1, 2, 3, 4]) {
    const rounded = Math.round(difference * 10 ** digits) / 10 ** digits;
    if (rounded !== 0) return rounded;
  }
  return difference;
}

export function ratePercent(rate: Rate, digits = 1): string {
  return percent(rate.numerator, rate.denominator, digits);
}

export function fraction(value: { denominator: number; numerator: number }): number | null {
  return value.denominator ? value.numerator / value.denominator : null;
}

export const PROVENANCE: Record<UsageSummary["analytics"]["usage_by_provenance"][number]["provenance"], { color: string; label: string; text: string }> = {
  calculated: { color: "var(--accent-primary)", label: "Calculated from your prices", text: "Reported tokens × the model prices in AI Connections. Matches your bill only if those prices do." },
  estimated: { color: "var(--orange)", label: "Estimated", text: "No usage report arrived, usually a stream that ended early. Latchway counted what it could see." },
  unknown: { color: "var(--grey)", label: "Unknown", text: "Can include conservative quota charges: units reserved for a request that never reported back." },
  upstream_reported: { color: "var(--success)", label: "Reported by the provider", text: "The provider's own usage numbers for the request." }
};

export const BREAKDOWN_LABEL: Record<"feature" | "model" | "plan", string> = { feature: "Feature", model: "Model", plan: "Plan" };

export function breakdownOf(summary: UsageSummary, by: "feature" | "model" | "plan") {
  return by === "feature" ? summary.analytics.by_feature : by === "model" ? summary.analytics.by_model : summary.analytics.by_selected_plan;
}

/** Breakdown keys the server uses for rows recorded before that dimension was tracked. */
export function breakdownKeyLabel(key: string, by: "feature" | "model" | "plan"): { label: string; note?: string } {
  if (key === "legacy_unknown") return { label: by === "plan" ? "Before plan tracking" : "Before model tracking", note: "Recorded before this was kept" };
  return { label: key };
}

function csvCell(value: string | number | null): string {
  const text = value === null ? "" : String(value);
  const neutral = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return /[",\n]/.test(neutral) ? `"${neutral.replaceAll("\"", "\"\"")}"` : neutral;
}

function csv(rows: ReadonlyArray<ReadonlyArray<string | number | null>>): string {
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

/** Feature, model and plan breakdowns. The usage API never returns user IDs, so none can appear. */
export function breakdownCsv(summary: UsageSummary): string {
  const rows: Array<Array<string | number | null>> = [["dimension", "key", "active_users", "logical_requests", "input_tokens", "output_tokens", "total_tokens", "cost_nano_usd"]];
  for (const [dimension, breakdown] of [["feature", summary.analytics.by_feature], ["model", summary.analytics.by_model], ["selected_plan", summary.analytics.by_selected_plan]] as const) {
    for (const item of breakdown.items) {
      rows.push([dimension, item.key, item.active_users, item.request_count, recorded(item.values, "input_tokens"), recorded(item.values, "output_tokens"), recorded(item.values, "total_tokens"), recorded(item.values, "cost_nano_usd")]);
    }
  }
  return csv(rows);
}

export function timeseriesCsv(points: readonly Bucket[]): string {
  const rows: Array<Array<string | number | null>> = [["bucket_start_utc", "logical_requests", "input_tokens", "output_tokens", "total_tokens", "cost_nano_usd"]];
  for (const point of points) {
    rows.push([iso(point.start), point.values?.logical_requests ?? 0, recorded(point.values, "input_tokens"), recorded(point.values, "output_tokens"), recorded(point.values, "total_tokens"), recorded(point.values, "cost_nano_usd")]);
  }
  return csv(rows);
}

/** The same queries through the CLI, which reads its token from the environment. */
export function cliCommands(environmentID: string, window: UsageWindow, breakdownLimit: string): string {
  return [
    `latchway usage summary --environment ${environmentID} \\`,
    `  --start ${iso(window.start)} --end ${iso(window.end)} \\`,
    `  --breakdown-limit ${breakdownLimit} --output json`,
    "",
    `latchway usage timeseries --environment ${environmentID} \\`,
    `  --start ${iso(window.start)} --end ${iso(window.end)} --interval ${window.interval} --output json`
  ].join("\n");
}

/** The current UTC calendar month up to now, and the month before it. Providers bill by UTC month. */
export interface MonthWindows {
  /** Exclusive end of this month. */
  monthEnd: number;
  now: number;
  previousStart: number;
  start: number;
}

export function monthWindows(now: number): MonthWindows {
  const date = new Date(now);
  const start = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1);
  return { monthEnd: Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1), now, previousStart: Date.UTC(date.getUTCFullYear(), date.getUTCMonth() - 1, 1), start };
}

/** Projections wait for a full day of the month, so one busy hour can't set the pace. */
export const PROJECTION_MINIMUM_MS = 86_400_000;

/**
 * Month-end cost if the rest of the month runs at this month's pace so far: integer nano-USD, or null before a full
 * day has passed or without a recorded cost. Exact integer arithmetic; a straight line, not a forecast.
 */
export function projectMonthEnd(costNano: number | null, months: MonthWindows): number | null {
  const elapsed = months.now - months.start;
  if (costNano === null || elapsed < PROJECTION_MINIMUM_MS) return null;
  const span = BigInt(months.monthEnd - months.start);
  const projected = (BigInt(costNano) * span + BigInt(elapsed) / 2n) / BigInt(elapsed);
  return Number(projected);
}

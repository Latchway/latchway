import { describe, expect, it } from "vitest";

import { attentionItems } from "../overview/attention-model";
import { summaryFixture, zero } from "./usage-fixture";
import {
  breakdownCsv,
  buckets,
  cliCommands,
  formatAxisMoney,
  formatCount,
  percentChange,
  periodOf,
  periodPatch,
  pointChange,
  previousWindow,
  recorded,
  usageWindow,
  windowLabel
} from "./usage-model";

const NOW = Date.UTC(2026, 8, 29, 15, 40);


describe("usage periods", () => {
  it("uses 24 hourly buckets for 24h and whole UTC days otherwise", () => {
    const day = usageWindow({ id: "24h" }, NOW);
    expect(day).toMatchObject({ end: NOW, interval: "hour", partialLast: true, start: Date.UTC(2026, 8, 28, 16) });
    expect(buckets(day, undefined)).toHaveLength(24);
    const week = usageWindow({ id: "7d" }, NOW);
    expect(week).toMatchObject({ interval: "day", start: Date.UTC(2026, 8, 23) });
    expect(buckets(week, undefined)).toHaveLength(7);
    expect(windowLabel(week)).toBe("Sep 23 – Sep 29, 2026 (UTC days)");
  });

  it("compares with the same number of whole buckets just before", () => {
    const week = usageWindow({ id: "7d" }, NOW);
    expect(previousWindow(week)).toMatchObject({ end: NOW - 7 * 86_400_000, start: Date.UTC(2026, 8, 16) });
  });

  it("uses hourly buckets for custom periods of two days or less", () => {
    expect(usageWindow({ end: Date.UTC(2026, 8, 3), id: "custom", start: Date.UTC(2026, 8, 1) }, NOW)).toMatchObject({ interval: "hour", partialLast: false });
    expect(usageWindow({ end: Date.UTC(2026, 8, 4), id: "custom", start: Date.UTC(2026, 8, 1) }, NOW).interval).toBe("day");
  });

  it("round-trips periods through the URL", () => {
    expect(periodOf({})).toEqual({ id: "7d" });
    expect(periodPatch({ id: "7d" })).toEqual({ end: undefined, period: undefined, start: undefined });
    expect(periodPatch({ id: "30d" })).toMatchObject({ period: "30d" });
    expect(periodOf({ end: "2026-09-03T00:00:00.000Z", start: "2026-09-01T00:00:00.000Z" })).toEqual({ end: Date.UTC(2026, 8, 3), id: "custom", start: Date.UTC(2026, 8, 1) });
  });

  it("places server points into their buckets and leaves missing ones empty", () => {
    const window = usageWindow({ id: "7d" }, NOW);
    const result = buckets(window, { interval: "day", points: [{ timestamp: "2026-09-25T00:00:00Z", values: { ...zero, logical_requests: 12 } }] });
    expect(result.find((bucket) => bucket.label === "Sep 25")?.values?.logical_requests).toBe(12);
    expect(result.find((bucket) => bucket.label === "Sep 24")?.values).toBeUndefined();
    expect(result.at(-1)?.title).toBe("Sep 29, 2026 (UTC)");
  });
});

describe("usage numbers", () => {
  it("keeps no record distinct from zero", () => {
    const missing = { provenance: [], recorded_units: null, reported_units: null, unknown_units: null };
    const values = { ...zero, details: { cost_nano_usd: missing, input_tokens: missing, output_tokens: { provenance: ["upstream_reported"], recorded_units: 0, reported_units: 0, unknown_units: null }, total_tokens: missing } } as const;
    expect(recorded(values as never, "cost_nano_usd")).toBeNull();
    expect(recorded(values as never, "output_tokens")).toBe(0);
    expect(formatCount(null)).toBe("—");
  });

  it("formats counts, axis money and changes", () => {
    expect(formatCount(912)).toBe("912");
    expect(formatCount(44_312_000)).toBe("44.3M");
    expect(formatAxisMoney(500_000_000)).toBe("$0.5");
    expect(percentChange(110, 100)).toBe(10);
    expect(percentChange(5, 0)).toBeUndefined();
    expect(pointChange({ denominator: 100, numerator: 2, parts_per_million: 20_000 }, { denominator: 100, numerator: 1, parts_per_million: 10_000 })).toBe(1);
    expect(pointChange({ denominator: 1e6, numerator: 1, parts_per_million: 1 }, { denominator: 1e6, numerator: 0, parts_per_million: 0 })).toBe(0.0001);
  });

  it("exports breakdowns without user IDs and gives real CLI commands", () => {
    const csv = breakdownCsv(summaryFixture());
    expect(csv.split("\n")[0]).toBe("dimension,key,active_users,logical_requests,input_tokens,output_tokens,total_tokens,cost_nano_usd");
    expect(csv).toContain("selected_plan,legacy_unknown,2,3");
    const window = usageWindow({ id: "24h" }, NOW);
    expect(cliCommands("env_0123456789abcdef", window, "50")).toContain("latchway usage summary --environment env_0123456789abcdef");
    expect(cliCommands("env_0123456789abcdef", window, "50")).toContain("--interval hour");
  });
});

describe("attention", () => {
  const environment = { active_revision_id: undefined, application_id: "app_0123456789abcdef", created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: "env_0123456789abcdef", kind: "production" as const, slug: "production", status: "active" as const };

  it("lists only what server records show, with the page that fixes each", () => {
    const unpricedSummary = summaryFixture({
      analytics: {
        ...summaryFixture().analytics,
        by_model: { items: [{ active_users: 1, key: "opaque", request_count: 4, values: { ...zero, details: { cost_nano_usd: { provenance: [], recorded_units: null, reported_units: null, unknown_units: null }, input_tokens: { provenance: [], recorded_units: null, reported_units: null, unknown_units: null }, output_tokens: { provenance: [], recorded_units: null, reported_units: null, unknown_units: null }, total_tokens: { provenance: [], recorded_units: null, reported_units: null, unknown_units: null } } } }], limit: 50, truncated: false },
        failure_rate: { denominator: 40, numerator: 4, parts_per_million: 100_000 }
      }
    });
    const items = attentionItems({
      apiTokens: [
        { created_at: "2026-08-01T00:00:00Z", expires_at: new Date(NOW + 3 * 86_400_000).toISOString(), id: "tok_0123456789abcdef", name: "ci", revoked: false, scopes: ["usage.read"] as never },
        { created_at: "2026-08-01T00:00:00Z", expires_at: new Date(NOW + 60 * 86_400_000).toISOString(), id: "tok_1123456789abcdef", name: "later", revoked: false, scopes: ["usage.read"] as never }
      ],
      environment,
      latestRevisionState: "invalid",
      now: NOW,
      readiness: { checks: [{ detail: "Pool exhausted", name: "database", state: "unavailable" }], endpoint: "/readyz", kind: "readiness", latencyMs: 4, observedAt: "2026-09-29T15:40:00Z", state: "unavailable", statusCode: 503, summary: "Not ready" },
      summary: unpricedSummary
    });
    expect(items.map((item) => [item.id, item.severity, item.to])).toEqual([
      ["no-active-configuration", "warning", "/setup"],
      ["draft-invalid", "warning", "/configuration-revisions"],
      ["models-unpriced", "warning", "/models-pricing"],
      ["failure-rate", "warning", "/requests"],
      ["token-tok_0123456789abcdef", "warning", "/api-tokens"],
      ["check-database", "critical", "/system-health"]
    ]);
  });

  it("is empty when nothing needs attention", () => {
    expect(attentionItems({ environment: { ...environment, active_revision_id: "rev_0123456789abcdef" }, now: NOW, summary: summaryFixture() })).toEqual([]);
  });
});

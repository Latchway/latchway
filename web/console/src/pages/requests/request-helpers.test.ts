import { describe, expect, it } from "vitest";

import { RequestSchema } from "../../api/admin";
import { RequestRouteSearchSchema } from "../../app/route-search";
import { formatMs, formatUsd, metricCell, outcomeSentence, requestsCsv, routeSummary, shortId } from "./request-format";
import {
  activeQuickView,
  applyMoreFilters,
  curlCommand,
  filtersOf,
  filtersPatch,
  goToTarget,
  moreFilterDraft,
  rangeOf,
  rangePatch,
  requestListQuery
} from "./request-query";

const base = {
  attempts: [],
  completed_at: "2026-08-29T00:00:01Z",
  config_revision_id: "rev_0123456789abcdef",
  decision_stages: [],
  environment_id: "env_0123456789abcdef",
  feature: "assistant",
  id: "req_0123456789abcdef",
  installation_id: "ins_0123456789abcdef",
  protocol: "openai_chat",
  selected_limit_plan: "subscriber",
  started_at: "2026-08-29T00:00:00Z",
  status: "succeeded",
  user_id: "usr_0123456789abcdef"
} as const;

const attempt = (number: number, status: "succeeded" | "failed", upstream: string) => ({
  attempt_number: number,
  completed_at: `2026-08-29T00:00:0${number}Z`,
  cost_provenance: "unknown" as const,
  ...(status === "failed" ? { failure_code: "timeout" as const } : { http_status: 200 }),
  id: `atm_0123456789abcde${number}`,
  model: "gpt_mobile",
  route: "primary",
  started_at: `2026-08-29T00:00:0${number - 1}Z`,
  status,
  upstream,
  usage_provenance: "unknown" as const
});

describe("request formatting", () => {
  it("formats integer nano-USD without float drift", () => {
    expect(formatUsd(0)).toBe("$0");
    expect(formatUsd(123_400)).toBe("$0.000123");
    expect(formatUsd(20_000_000)).toBe("$0.02");
    expect(formatUsd(12_400_000_000)).toBe("$12.40");
  });

  it("formats durations and IDs", () => {
    expect(formatMs(840)).toBe("840 ms");
    expect(formatMs(2_400)).toBe("2.4 s");
    expect(formatMs(undefined)).toBe("—");
    expect(shortId("usr_01J9ZK4Q7TFWABCDEF")).toBe("usr_01J9ZK…CDEF");
  });

  it("describes the outcome from recorded attempts only", () => {
    const answered = RequestSchema.parse({ ...base, attempts: [attempt(1, "failed", "openai"), attempt(2, "succeeded", "azure")], completed_at: "2026-08-29T00:00:03Z", selected_model: "gpt_mobile", selected_physical_model: "gpt-5-mini", selected_route: "primary", selected_upstream: "openai" });
    expect(outcomeSentence(answered)).toBe("Answered by azure after 1 failed attempt.");
    expect(routeSummary(answered)).toEqual({ kind: "routed", model: "gpt_mobile", upstream: "azure" });
    const denied = RequestSchema.parse({ ...base, failure_code: "quota_exceeded", status: "denied" });
    expect(outcomeSentence(denied)).toBe("A limit refused it: the user had reached a limit in their plan.");
    expect(routeSummary(denied)).toEqual({ kind: "not-routed" });
    const unregistered = RequestSchema.parse({ ...base, failure_code: "server_not_ready", status: "failed" });
    expect(outcomeSentence(unregistered)).toBe("It ended with server_not_ready.");
  });

  it("shows missing usage as no record rather than zero", () => {
    expect(metricCell(undefined, "cost_nano_usd")).toEqual({ estimated: false, recorded: false, text: "—" });
    const missing = { details: { cost_nano_usd: { provenance: [], recorded_units: null, reported_units: null, unknown_units: null } } };
    expect(metricCell({ cost_nano_usd: 0, input_tokens: 0, logical_requests: 1, output_tokens: 0, total_tokens: 0, ...missing } as never, "cost_nano_usd").text).toBe("—");
  });

  it("exports CSV without user IDs unless asked, and neutralizes formula prefixes", () => {
    const request = RequestSchema.parse({ ...base });
    const withoutUsers = requestsCsv([request], false);
    expect(withoutUsers.split("\n")[0]).not.toContain("user_id");
    expect(withoutUsers).not.toContain(base.user_id);
    expect(requestsCsv([request], true)).toContain(base.user_id);
  });
});

describe("request query state", () => {
  it("maps quick views to plain API filters", () => {
    expect(activeQuickView({})?.id).toBe("all");
    expect(activeQuickView({ latency_min_ms: "2000" })?.id).toBe("slow");
    expect(activeQuickView({ cost_min_nano_usd: "20000000" })?.id).toBe("expensive");
    expect(activeQuickView({ feature: "assistant", status: "failed" })).toBeUndefined();
  });

  it("replaces every filter and drops paging and the open record", () => {
    const patch = filtersPatch({ feature: "assistant" });
    expect(patch).toMatchObject({ cursor: undefined, feature: "assistant", request: undefined, status: undefined, user_id: undefined });
    expect(Object.keys(patch)).toContain("status");
  });

  it("sends a relative range as a start moving with the clock", () => {
    const search = RequestRouteSearchSchema.parse({ feature: "assistant", page_size: "100", range: "1h", sort: "started_at_asc" });
    expect(requestListQuery(search, "env_0123456789abcdef", Date.UTC(2026, 9, 2, 12), "next")).toMatchObject({
      cursor: "next", end: undefined, environment_id: "env_0123456789abcdef", feature: "assistant", page_size: "100", sort: "started_at_asc", start: "2026-10-02T11:00:00.000Z"
    });
    expect(rangeOf(search)).toEqual({ id: "1h" });
    expect(rangePatch({ id: "all" })).toMatchObject({ end: undefined, range: undefined, start: undefined });
    expect(rangePatch({ end: Date.UTC(2026, 8, 3), id: "custom", start: Date.UTC(2026, 8, 1) })).toMatchObject({ end: "2026-09-03T00:00:00.000Z", range: undefined, start: "2026-09-01T00:00:00.000Z" });
  });

  it("rejects a relative range combined with explicit bounds", () => {
    expect(RequestRouteSearchSchema.safeParse({ range: "1h", start: "2026-08-29T00:00:00Z" }).success).toBe(false);
  });

  it("builds a curl command without the cursor or a token", () => {
    const command = curlCommand("https://console.example.test", { cursor: "abc", environment_id: "env_0123456789abcdef", status: "failed" });
    expect(command).toContain("$LATCHWAY_TOKEN");
    expect(command).toContain("https://console.example.test/admin/v1/requests?environment_id=env_0123456789abcdef&status=failed");
    expect(command).not.toContain("cursor");
  });

  it("routes Go to ID by prefix", () => {
    expect(goToTarget(" req_0123456789abcdef ")).toEqual({ id: "req_0123456789abcdef", kind: "request" });
    expect(goToTarget("usr_0123456789abcdef")).toEqual({ id: "usr_0123456789abcdef", kind: "user" });
    expect(goToTarget("timeout")).toEqual({ kind: "invalid" });
  });

  it("converts More filters to integer milliseconds and nano-USD, and validates ranges", () => {
    const draft = { ...moreFilterDraft({}), cost_min_usd: "0.02", duration_max_s: "2.5", duration_min_s: "0.5", tokens_min: "10" };
    expect(applyMoreFilters({ status: "failed" }, draft)).toEqual({ filters: { cost_min_nano_usd: "20000000", latency_max_ms: "2500", latency_min_ms: "500", status: "failed", tokens_min: "10" } });
    expect(applyMoreFilters({}, { ...draft, duration_min_s: "3" })).toEqual({ error: "Use numbers, with the minimum no larger than the maximum." });
    expect(applyMoreFilters({}, { ...draft, tokens_min: "-1" })).toHaveProperty("error");
    expect(moreFilterDraft(filtersOf(RequestRouteSearchSchema.parse({ cost_max_nano_usd: "20000000", latency_min_ms: "2000" })))).toMatchObject({ cost_max_usd: "0.02", duration_min_s: "2" });
  });
});

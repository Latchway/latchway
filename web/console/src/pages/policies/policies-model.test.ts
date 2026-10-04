import { describe, expect, it } from "vitest";

import type { JSONRecord } from "../configuration-slice";
import {
  dollarsToNano,
  featuresByPlan,
  formatAmount,
  isProtection,
  limitProblems,
  limitText,
  nanoToDollars,
  planIssues,
  scopeLabel,
  withKind,
  withMetric
} from "./limit-model";
import { compileRules, parseRules, replacePlanInExpression, rulesProblems, rulesSentence } from "./plan-rules";

const daily: JSONRecord = { algorithm: "calendar", hard: true, maximum: 50_000, metric: "total_tokens", scope: ["user"], timezone: "UTC", window: "1d" };

describe("limits as sentences", () => {
  it("reads each kind of limit as one line with human units", () => {
    expect(limitText(daily)).toBe("Each user can use 50,000 tokens per day");
    expect(limitText({ algorithm: "calendar", hard: true, maximum: 12_500_000_000, metric: "cost_nano_usd", scope: ["organization"], window: "1mo" })).toBe("Everyone together can use $12.50 per month");
    expect(limitText({ algorithm: "token_bucket", capacity: 60, hard: true, metric: "logical_requests", refillPerSecond: 0.5, scope: ["trust_source"] })).toBe("Each trust source can burst to 60 requests, refilling 30 requests per minute");
    expect(limitText({ algorithm: "concurrency", hard: true, maximum: 1, metric: "concurrent_streams", scope: ["installation"] })).toBe("Each installation can have 1 open stream at once");
    expect(limitText({ algorithm: "per_request", hard: true, metric: "tool_calls", perRequestMaximum: 8, scope: ["user"] })).toBe("No single request can use more than 8 tool calls");
    expect(limitText({ ...daily, window: "7d" })).toBe("Each user can use 50,000 tokens per 7 days");
  });

  it("names custom scopes and recognises protection limits", () => {
    expect(scopeLabel(["feature", "user"])).toBe("Each user, per feature");
    expect(scopeLabel(["platform", "user", "normalized_claim:team"])).toBe("Each user, per platform and team claim value");
    expect(isProtection({ ...daily, scope: ["installation"] })).toBe(true);
    expect(isProtection({ ...daily, scope: ["installation", "user"] })).toBe(false);
  });

  it("converts dollars and nano-USD exactly, without floating-point drift", () => {
    expect(dollarsToNano("0.1")).toBe(100_000_000);
    expect(dollarsToNano("$1,234.56")).toBe(1_234_560_000_000);
    expect(dollarsToNano("0.000000001")).toBe(1);
    expect(dollarsToNano("0")).toBeUndefined();
    expect(dollarsToNano("-1")).toBeUndefined();
    expect(nanoToDollars(1_234_560_000_000)).toBe("$1,234.56");
    expect(nanoToDollars(1)).toBe("$0.000000001");
    expect(formatAmount("concurrent_requests", 3)).toBe("3 open requests");
  });
});

describe("limit checks follow the server's activation rules", () => {
  it("refuses track-only limits, unsupported kinds and bad fields", () => {
    expect(limitProblems(daily)).toEqual([]);
    expect(limitProblems({ ...daily, hard: false })).toContain("Track-only limits can't be activated by this server; every limit blocks.");
    expect(limitProblems({ ...daily, metric: "cost_nano_usd", algorithm: "token_bucket" }).join(" ")).toMatch(/Burst rate doesn't work for spend/);
    expect(limitProblems({ ...daily, window: "400d" }).join(" ")).toMatch(/at most one year/);
    expect(limitProblems({ ...daily, timezone: "Local" }).join(" ")).toMatch(/IANA/);
    expect(limitProblems({ ...daily, scope: ["normalized_claim:a", "normalized_claim:b"] }).join(" ")).toMatch(/at most one claim/);
    expect(limitProblems({ algorithm: "token_bucket", capacity: 10, hard: true, metric: "logical_requests", refillPerSecond: 0.0000001, scope: ["user"] }).join(" ")).toMatch(/six decimal places/);
    expect(limitProblems({ ...daily, metric: "cost_nano_usd", costRetryTreatment: "initial_attempt_only", scope: ["organization"] }).join(" ")).toMatch(/includes the user/);
  });

  it("enforces the first-attempt spend pairing rule and duplicate identities per plan", () => {
    const firstAttempt = { ...daily, costRetryTreatment: "initial_attempt_only", maximum: 5_000_000_000, metric: "cost_nano_usd", window: "1mo" };
    expect(planIssues([firstAttempt]).errors.map((issue) => issue.fix)).toContain("organization_spend");
    const organization = { algorithm: "calendar", hard: true, maximum: 100_000_000_000, metric: "cost_nano_usd", scope: ["organization"], timezone: "UTC", window: "1mo" };
    expect(planIssues([firstAttempt, organization]).errors).toEqual([]);
    expect(planIssues([daily, { ...daily, maximum: 10 }]).errors.map((issue) => issue.index)).toEqual([1]);
    expect(planIssues([daily]).warnings.map((issue) => issue.fix)).toEqual(["spend"]);
    expect(planIssues([]).errors.map((issue) => issue.message)).toContain("A plan needs at least one limit.");
  });

  it("keeps only the fields each kind takes when the kind or metric changes", () => {
    expect(withKind(daily, "token_bucket")).toEqual({ algorithm: "token_bucket", capacity: 50_000, hard: true, metric: "total_tokens", refillPerSecond: 1, scope: ["user"] });
    expect(withKind(daily, "per_request")).toEqual({ algorithm: "per_request", hard: true, metric: "total_tokens", perRequestMaximum: 50_000, scope: ["user"] });
    expect(withMetric(daily, "concurrent_requests")).toMatchObject({ algorithm: "concurrency", metric: "concurrent_requests" });
    expect(withMetric({ ...daily, metric: "cost_nano_usd", costRetryTreatment: "actual_attempts" }, "total_tokens")).not.toHaveProperty("costRetryTreatment");
  });

  it("finds which features select each plan", () => {
    const document = { spec: { features: [{ id: "chat", limitPlan: { expression: "principal.claims.plan == 'premium' ? 'premium' : 'free'" } }, { id: "embed", limitPlan: { expression: "'free'" } }] } };
    expect(Object.fromEntries(featuresByPlan(document))).toEqual({ free: ["chat", "embed"], premium: ["chat"] });
  });
});

describe("plan selection rules", () => {
  it("compiles ordered rules to a nested ternary and reads it back exactly", () => {
    const rules = { fallback: "free", rules: [{ attribute: "claim" as const, claim: "plan", plan: "premium", value: "premium" }, { attribute: "platform" as const, plan: "web", value: "web" }, { attribute: "streaming" as const, plan: "stream", value: "false" }] };
    const expression = compileRules(rules);
    expect(expression).toBe("principal.claims.plan == 'premium' ? 'premium' : installation.platform == 'web' ? 'web' : !request.streaming ? 'stream' : 'free'");
    expect(parseRules(expression)).toEqual(rules);
    expect(parseRules("'free'")).toEqual({ fallback: "free", rules: [] });
    expect(rulesSentence(rules)).toBe("If plan is premium → premium · Else if platform is web → web · Else if not streaming → stream · Everyone else → free");
  });

  it("keeps an expression it can't read back as custom CEL", () => {
    expect(parseRules("principal.claims.plan in ['a', 'b'] ? 'premium' : 'free'")).toBeUndefined();
    expect(parseRules("size(principal.claims) > 2 ? 'a' : 'b'")).toBeUndefined();
  });

  it("refuses plans that aren't in the draft and unreachable rules", () => {
    const rules = { fallback: "gone", rules: [{ attribute: "claim" as const, claim: "plan", plan: "premium", value: "premium" }, { attribute: "claim" as const, claim: "plan", plan: "free", value: "premium" }] };
    const problems = rulesProblems(rules, ["free", "premium"]);
    expect(problems).toContain("gone isn't a plan in the draft.");
    expect(problems.join(" ")).toMatch(/Rule 2 can never be reached/);
  });

  it("repoints a plan inside rules and inside custom expressions", () => {
    expect(replacePlanInExpression("principal.claims.plan == 'trial' ? 'trial' : 'free'", "trial", "premium")).toBe("principal.claims.plan == 'trial' ? 'premium' : 'free'");
    expect(replacePlanInExpression("principal.claims.plan in ['x'] ? \"trial\" : 'free'", "trial", "premium")).toBe("principal.claims.plan in ['x'] ? 'premium' : 'free'");
  });
});

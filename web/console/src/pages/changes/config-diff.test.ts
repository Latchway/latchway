import { describe, expect, it } from "vitest";

import type { JSONRecord } from "../configuration-slice";
import { affectedFeatures, changeSetSummary, configurationDiff, discardEntry, fieldChanges, fixTarget } from "./config-diff";

function documentWith(spec: JSONRecord): JSONRecord {
  return { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: { application: "mobile" }, spec };
}

const live = documentWith({
  features: [{ access: { expression: "principal.authenticated" }, id: "chat", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "fast", priority: 10, when: "true" }] }],
  limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user"], window: "1d" }] }],
  upstreams: [{ baseUrl: "https://a.example.test/v1", id: "a", type: "openai_compatible" }, { baseUrl: "https://b.example.test/v1", id: "b", type: "openai_compatible" }]
});

const draft = documentWith({
  features: [{ access: { expression: "principal.authenticated" }, id: "chat", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "fast", priority: 10, when: "true" }, { id: "backup", model: "slow", priority: 20, when: "true" }] }],
  limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 200, metric: "logical_requests", scope: ["user"], window: "1d" }] }],
  session: { accessTokenTtl: "15m" },
  upstreams: [{ baseUrl: "https://a2.example.test/v1", id: "a", type: "openai_compatible" }, { baseUrl: "https://c.example.test/v1", id: "c", type: "openai_compatible" }]
});

describe("configuration diff", () => {
  it("lists only resources that differ, with routing separate from feature settings", () => {
    const entries = configurationDiff(live, draft);
    expect(entries.map((entry) => [entry.key, entry.state, entry.group])).toEqual([
      ["routing/chat", "edited", "routing"],
      ["limitPlans/free", "edited", "limits"],
      ["upstreams/a", "edited", "connections"],
      ["upstreams/b", "removing", "connections"],
      ["upstreams/c", "new", "connections"],
      ["session/session", "new", "trust"]
    ]);
    expect(entries.find((entry) => entry.key === "upstreams/a")?.summary).toBe("baseUrl: https://a.example.test/v1 → https://a2.example.test/v1");
    expect(configurationDiff(live, structuredClone(live))).toEqual([]);
    expect(changeSetSummary(entries)).toMatch(/^1 routing, 1 limit plan, 3 AI connections, 1 session settings · \d+ fields$/);
  });

  it("describes list changes as additions and removals", () => {
    expect(fieldChanges({ audiences: ["a", "b"] }, { audiences: ["b", "c"] })).toEqual([{ list: { added: ["c"], removed: ["a"] }, path: "audiences" }]);
    expect(fieldChanges({ routes: [{ id: "r", model: "x" }] }, { routes: [{ id: "r", model: "y" }] })).toEqual([{ after: "y", before: "x", path: "routes › r › model" }]);
    expect(fieldChanges({ limits: [{ maximum: 1 }] }, { limits: [{ maximum: 2 }, { maximum: 3 }] })).toEqual([{ after: 2, before: 1, path: "limits › 1 › maximum" }, { after: { maximum: 3 }, before: undefined, path: "limits › 2" }]);
  });

  it("discards one change back to live and nothing else", () => {
    const entries = configurationDiff(live, draft);
    const byKey = (key: string) => entries.find((entry) => entry.key === key)!;
    let next = discardEntry(draft, live, byKey("routing/chat"));
    expect(configurationDiff(live, next).map((entry) => entry.key)).not.toContain("routing/chat");
    next = discardEntry(next, live, byKey("upstreams/c"));
    next = discardEntry(next, live, byKey("upstreams/b"));
    next = discardEntry(next, live, byKey("session/session"));
    expect(configurationDiff(live, next).map((entry) => entry.key)).toEqual(["limitPlans/free", "upstreams/a"]);
    expect(draft.spec).toHaveProperty("session");
  });

  it("finds features affected by changed plans and routing, and where to fix a problem", () => {
    expect(affectedFeatures(configurationDiff(live, draft), draft)).toEqual(["chat"]);
    expect(fixTarget("/spec/features/0/limitPlan/expression", draft)).toEqual({ search: { feature: "chat", tab: "access" }, to: "/features" });
    expect(fixTarget("/spec/features/0/routes/1/model", draft)).toEqual({ search: { feature: "chat", tab: "routing" }, to: "/features" });
    expect(fixTarget("/spec/limitPlans/0/limits/0", draft)).toEqual({ search: { plan: "free" }, to: "/limit-plans" });
    expect(fixTarget("/spec/upstreams/1/baseUrl", draft)).toEqual({ to: "/upstreams" });
    expect(fixTarget("/metadata", draft)).toEqual({ to: "/configuration" });
  });
});

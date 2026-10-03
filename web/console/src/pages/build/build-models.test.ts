import { describe, expect, it } from "vitest";

import { configurationAreas, type JSONRecord } from "../configuration-slice";
import { changeCount, resourceRows, restoreResource } from "./resource-diff";
import { hasSplits, moveRoute, removeRoute, routeRows, upsertRoute } from "./routing-model";

const upstreams = configurationAreas.upstreams.collections[0]!;

function documentWith(list: JSONRecord[]): JSONRecord {
  return {
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: { application: "mobile", environment: "production", organization: "example" },
    spec: {
      features: [{ id: "assistant", protocol: "openai_responses", routes: [{ id: "primary", model: "fast", priority: 10, when: "true" }, { id: "backup", model: "reliable", priority: 20, when: "true" }] }],
      models: [{ capabilities: ["openai_responses"], id: "fast", upstream: "a", upstreamModel: "f" }, { capabilities: ["openai_responses"], id: "reliable", upstream: "b", upstreamModel: "r" }],
      upstreams: list
    }
  };
}

const a = { authentication: { type: "none" }, baseUrl: "https://a.example.test/v1", id: "a", type: "openai_compatible" };
const b = { authentication: { type: "none" }, baseUrl: "https://b.example.test/v1", id: "b", type: "openai_compatible" };
const c = { authentication: { type: "none" }, baseUrl: "https://c.example.test/v1", id: "c", type: "openai_compatible" };

describe("resource diff", () => {
  it("marks new, edited, removed and unchanged resources against the live configuration", () => {
    const active = documentWith([a, b]);
    const working = documentWith([{ ...a, baseUrl: "https://a2.example.test/v1" }, c]);
    const rows = resourceRows(active, working, upstreams);
    expect(rows.map((row) => [row.key, row.state])).toEqual([["a", "edited"], ["c", "new"], ["b", "removing"]]);
    expect(rows.find((row) => row.key === "b")?.live).toEqual(b);
    expect(changeCount(rows)).toBe(3);
    expect(resourceRows(active, undefined, upstreams).every((row) => row.state === "live")).toBe(true);
  });

  it("undoes each kind of change back to the live value", () => {
    const active = documentWith([a, b]);
    const working = documentWith([{ ...a, baseUrl: "https://a2.example.test/v1" }, c]);
    let next = working;
    for (const row of resourceRows(active, working, upstreams).filter((candidate) => candidate.state !== "live")) next = restoreResource(next, row, upstreams);
    expect(resourceRows(active, next, upstreams).map((row) => [row.key, row.state]).sort()).toEqual([["a", "live"], ["b", "live"]]);
    expect(working).toEqual(documentWith([{ ...a, baseUrl: "https://a2.example.test/v1" }, c]));
  });
});

describe("routing model", () => {
  const feature = (routes: JSONRecord[]): JSONRecord => ({ id: "assistant", protocol: "openai_responses", routes });

  it("moves a route by swapping priorities with its neighbour only", () => {
    const moved = moveRoute(feature([{ id: "one", priority: 10 }, { id: "two", priority: 20 }, { id: "three", priority: 35 }]), "three", -1);
    expect(moved.routes).toEqual(expect.arrayContaining([{ id: "one", priority: 10 }, { id: "two", priority: 35 }, { id: "three", priority: 20 }]));
    expect(moveRoute(feature([{ id: "one", priority: 10 }]), "one", -1).routes).toEqual([{ id: "one", priority: 10 }]);
  });

  it("refuses to reorder routes that split traffic at one priority", () => {
    const split = feature([{ id: "one", priority: 10, weight: 1 }, { id: "two", priority: 10, weight: 3 }]);
    expect(hasSplits(split)).toBe(true);
    expect(() => moveRoute(split, "two", -1)).toThrow(/share a priority/);
  });

  it("adds a route after the last one, keeps IDs stable and keeps at least one route", () => {
    const added = upsertRoute(feature([{ id: "one", priority: 10 }, { id: "two", priority: 25 }]), undefined, { id: "three", model: "fast", when: "true" });
    expect((added.routes as JSONRecord[]).at(-1)).toMatchObject({ id: "three", priority: 35 });
    expect(() => upsertRoute(added, undefined, { id: "two" })).toThrow(/already has a route/);
    expect(() => upsertRoute(added, "two", { id: "renamed" })).toThrow(/can't be changed/);
    expect(() => upsertRoute(added, undefined, { id: "Bad ID" })).toThrow(/starts with a letter/);
    expect(removeRoute(added, "two").routes).toHaveLength(2);
    expect(() => removeRoute(feature([{ id: "one", priority: 10 }]), "one")).toThrow(/at least one route/);
  });

  it("lists every route in evaluation order with its connection", () => {
    expect(routeRows(documentWith([a, b])).map((row) => [row.feature, row.order, row.model, row.connection])).toEqual([["assistant", 0, "fast", "a"], ["assistant", 1, "reliable", "b"]]);
  });
});

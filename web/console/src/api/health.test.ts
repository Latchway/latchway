import { describe, expect, it, vi } from "vitest";

import { fetchHealth, healthEndpoints, overallHealthState } from "./health";

describe("fetchHealth", () => {
  it("calls the canonical readiness endpoint and normalizes structured checks", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            checks: {
              active_configuration: { status: "ready" },
              database: { message: "connection refused", status: "failed" }
            },
            message: "dependencies unavailable",
            status: "degraded",
            version: "0.1.0"
          }),
          {
            headers: { "Content-Type": "application/json" },
            status: 503,
            statusText: "Service Unavailable"
          }
        )
      )
    ) as unknown as typeof fetch;

    const result = await fetchHealth("readiness", undefined, fetcher);

    expect(fetcher).toHaveBeenCalledWith(
      healthEndpoints.readiness,
      expect.objectContaining({ method: "GET" })
    );
    expect(result).toMatchObject({
      endpoint: "/readyz",
      state: "degraded",
      statusCode: 503,
      summary: "dependencies unavailable",
      version: "0.1.0"
    });
    expect(result.checks).toEqual([
      { name: "active_configuration", state: "available" },
      {
        detail: "connection refused",
        name: "database",
        state: "unavailable"
      }
    ]);
  });

  it("accepts the plain-text liveness response used by minimal servers", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(new Response("ok\n", { status: 200 }))
    ) as unknown as typeof fetch;

    const result = await fetchHealth("liveness", undefined, fetcher);

    expect(result).toMatchObject({
      checks: [],
      endpoint: "/healthz",
      state: "available",
      statusCode: 200,
      summary: "ok"
    });
  });
});

describe("overallHealthState", () => {
  const result = (state: "available" | "degraded" | "unavailable") => ({
    checks: [],
    endpoint: "/healthz",
    kind: "liveness" as const,
    latencyMs: 1,
    observedAt: "2026-08-27T00:00:00.000Z",
    state,
    statusCode: 200,
    summary: "ok"
  });

  it("does not report ready until both endpoints are available", () => {
    expect(overallHealthState(undefined, undefined)).toBe("loading");
    expect(overallHealthState(result("available"), result("degraded"))).toBe(
      "degraded"
    );
    expect(overallHealthState(result("unavailable"), result("available"))).toBe(
      "unavailable"
    );
    expect(overallHealthState(result("available"), result("available"))).toBe(
      "available"
    );
  });
});

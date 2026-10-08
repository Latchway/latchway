import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));
vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));

import { connectionHealth, listSelfTests, renameEnvironment } from "../../api/operations-history";
import { ConnectionHealthTable, HealthTimeline, SelfTestRuns } from "./operations-history";
import { healthIncidents, healthyShare, successRate } from "./operations-history-model";

const environmentID = "env_0123456789abcdef";
const otherEnvironment = "env_1123456789abcdef";
const instant = "2026-10-08T00:00:00Z";
const usage = { cost_nano_usd: 1_250_000_000, input_tokens: 10, logical_requests: 4, output_tokens: 5, total_tokens: 15 };
const latency = (p50: number, p95: number, samples = 4) => ({ p50_ms: p50, p95_ms: p95, p99_ms: p95, samples });

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{children}</QueryClientProvider>);
}

function sample(minute: number, state: "healthy" | "degraded" | "unhealthy", failed: string[] = [], warning: string[] = []) {
  return { failed_checks: failed, overall_state: state, sampled_at: new Date(Date.parse(instant) + minute * 60_000).toISOString(), warning_checks: warning };
}

function run(id: string, state: string, extra: Record<string, unknown> = {}) {
  return { checks: [], config_revision_id: "rev_0123456789abcdef", created_at: instant, environment_id: environmentID, id, kind: "upstream", state, ...extra };
}

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("operations history model", () => {
  it("groups consecutive unhealthy samples into one incident with the worst state and every check", () => {
    const incidents = healthIncidents([
      sample(0, "healthy"),
      sample(5, "degraded", [], ["worker_heartbeat"]),
      sample(10, "unhealthy", ["database_connectivity"]),
      sample(15, "degraded", [], ["worker_heartbeat"]),
      sample(20, "healthy")
    ], 300);
    expect(incidents).toEqual([{ checks: ["database_connectivity", "worker_heartbeat"], end: "2026-10-08T00:20:00.000Z", start: "2026-10-08T00:05:00.000Z", state: "unhealthy" }]);
  });

  it("ends an incident at a sampling gap, since nothing is known while no worker ran", () => {
    const incidents = healthIncidents([sample(0, "degraded", ["a"]), sample(5, "degraded", ["a"]), sample(60, "degraded", ["b"])], 300);
    expect(incidents.map((incident) => [incident.start, incident.end, incident.checks])).toEqual([
      ["2026-10-08T00:00:00.000Z", "2026-10-08T00:10:00.000Z", ["a"]],
      ["2026-10-08T01:00:00.000Z", "2026-10-08T01:05:00.000Z", ["b"]]
    ]);
  });

  it("measures the healthy share and success rates without inventing values", () => {
    expect(healthyShare([])).toBeUndefined();
    expect(healthyShare([sample(0, "healthy"), sample(5, "healthy"), sample(10, "degraded"), sample(15, "healthy")])).toBe(0.75);
    expect(successRate(0, 0)).toBeUndefined();
    expect(successRate(199, 1)).toBe(99.5);
    expect(successRate(2, 1)).toBe(66.7);
  });
});

describe("operations history API", () => {
  it("refuses connection health, runs or renames that belong to something else", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/usage/connections?")) return Promise.resolve({ data: { connections: [], end: instant, environment_id: otherEnvironment, start: instant, truncated: false } });
      if (path.startsWith("/admin/v1/self-tests?")) return Promise.resolve({ data: { items: [run("tst_0123456789abcdef", "passed", { environment_id: otherEnvironment })], page: { has_more: false } } });
      if (path.startsWith("/admin/v1/environments/")) return Promise.resolve({ data: { application_id: "app_0123456789abcdef", created_at: instant, display_name: "Production", id: otherEnvironment, kind: "production", slug: "production", status: "active" } });
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    await expect(connectionHealth(environmentID, instant, instant)).rejects.toThrow("another environment");
    await expect(listSelfTests(environmentID)).rejects.toThrow("another environment");
    await expect(renameEnvironment(environmentID, "Live")).rejects.toThrow("different environment");
    expect(adminRequestMock.mock.calls.find(([path]) => String(path).startsWith("/admin/v1/environments/"))?.[2]).toEqual({ body: { display_name: "Live" }, method: "PATCH" });
  });
});

describe("operations history views", () => {
  it("shows the healthy share, each sample and incidents newest first with readable check names", async () => {
    const user = userEvent.setup();
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/system/health-history?")) {
        return Promise.resolve({ data: { end: instant, interval_seconds: 300, samples: [sample(0, "healthy"), sample(5, "unhealthy", ["worker_heartbeat"]), sample(10, "healthy"), sample(15, "degraded", [], ["external_jwks_reachability"])], start: instant } });
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    wrap(<HealthTimeline checkName={(id) => ({ external_jwks_reachability: "Sign-in provider keys", worker_heartbeat: "Background workers" })[id] ?? id} />);
    expect(await screen.findByText("50%")).toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "Health samples" })).getAllByRole("listitem")).toHaveLength(4);
    const incidents = within(screen.getByRole("list", { name: "Incidents" })).getAllByRole("listitem");
    expect(incidents[0]).toHaveTextContent("Degraded");
    expect(incidents[0]).toHaveTextContent("Sign-in provider keys");
    expect(incidents[1]).toHaveTextContent("Unhealthy");
    expect(incidents[1]).toHaveTextContent("Background workers");
    const first = new URLSearchParams(String(adminRequestMock.mock.calls[0]?.[0]).split("?")[1]);
    expect(Date.parse(first.get("end") ?? "") - Date.parse(first.get("start") ?? "")).toBe(86_400_000);
    await user.click(screen.getByRole("button", { name: "7 days" }));
    await screen.findByText(/in the last 7 days/);
    const last = new URLSearchParams(String(adminRequestMock.mock.calls.at(-1)?.[0]).split("?")[1]);
    expect(Date.parse(last.get("end") ?? "") - Date.parse(last.get("start") ?? "")).toBe(7 * 86_400_000);
  });

  it("says when no worker has sampled yet", async () => {
    adminRequestMock.mockResolvedValue({ data: { end: instant, interval_seconds: 300, samples: [], start: instant } });
    wrap(<HealthTimeline checkName={(id) => id} />);
    expect(await screen.findByText(/No samples yet/)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Incidents" })).not.toBeInTheDocument();
  });

  it("lists each connection's success rate, errors, fallbacks, latency, top failure and cost", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/usage/connections?")) {
        return Promise.resolve({ data: {
          connections: [
            { attempts: 20, canceled: 0, duration: latency(900, 2400), failed: 2, failures: [{ code: "upstream_rate_limited", count: 2 }], fell_back: 2, first_byte: latency(300, 800), rate_limited: 2, server_errors: 0, succeeded: 18, upstream: "openai", usage },
            { attempts: 3, canceled: 1, duration: latency(0, 0, 0), failed: 0, failures: [], fell_back: 0, first_byte: latency(0, 0, 0), rate_limited: 0, server_errors: 0, succeeded: 2, upstream: "anthropic", usage: { ...usage, cost_nano_usd: 0 } }
          ],
          end: instant, environment_id: environmentID, start: instant, truncated: false
        } });
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    wrap(<ConnectionHealthTable environmentID={environmentID} environmentName="Production" />);
    const table = await screen.findByRole("table", { name: "AI connections in Production" });
    const [openai, anthropic] = within(table).getAllByRole("row").slice(1);
    expect(openai).toHaveTextContent("90%");
    expect(openai).toHaveTextContent("2 · 0");
    expect(openai).toHaveTextContent("300 · 800 ms");
    expect(openai).toHaveTextContent("upstream_rate_limited ×2");
    expect(openai).toHaveTextContent("$1.25");
    expect(anthropic).toHaveTextContent("100%");
    expect(anthropic).toHaveTextContent("None");
  });

  it("says when an environment had no attempts", async () => {
    adminRequestMock.mockResolvedValue({ data: { connections: [], end: instant, environment_id: environmentID, start: instant, truncated: false } });
    wrap(<ConnectionHealthTable environmentID={environmentID} environmentName="Production" />);
    expect(await screen.findByText("No attempts in Production in the last 24 hours.")).toBeInTheDocument();
  });

  it("lists recent runs, loads more pages and opens one", async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    adminRequestMock.mockImplementation((path: string) => {
      const cursor = new URLSearchParams(path.split("?")[1]).get("cursor");
      if (path.startsWith("/admin/v1/self-tests?") && !cursor) return Promise.resolve({ data: { items: [run("tst_0123456789abcdef", "failed", { schedule_id: "sts_0123456789abcdef" })], page: { has_more: true, next_cursor: "next" } } });
      if (path.startsWith("/admin/v1/self-tests?") && cursor === "next") return Promise.resolve({ data: { items: [run("tst_1123456789abcdef", "passed")], page: { has_more: false } } });
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    wrap(<SelfTestRuns environmentID={environmentID} onOpen={onOpen} />);
    const table = await screen.findByRole("table", { name: "Recent runs" });
    expect(within(table).getByText("upstream · scheduled")).toBeInTheDocument();
    expect(within(table).getByText("Failed")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Load More" }));
    expect(await within(table).findByText("tst_1123456789abcdef")).toBeInTheDocument();
    await user.click(within(table).getByText("tst_1123456789abcdef"));
    expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: "tst_1123456789abcdef", state: "passed" }));
    expect(new URLSearchParams(String(adminRequestMock.mock.calls[0]?.[0]).split("?")[1]).get("environment_id")).toBe(environmentID);
  });
});

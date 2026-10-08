import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));
vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));

import { LimitImpact, OverrideList, PlanOverrides, PlanShare } from "./policy-insights";
import { impactRange, projectableLimit } from "./policy-insights-model";

const environmentID = "env_0123456789abcdef";
const instant = "2026-10-08T00:00:00Z";

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{children}</QueryClientProvider>);
}

function params(path: string): URLSearchParams {
  return new URLSearchParams(path.split("?")[1] ?? "");
}

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("policy insight helpers", () => {
  it("projects only calendar limits on usage metrics scoped to users, features or installations", () => {
    expect(projectableLimit({ algorithm: "calendar", maximum: 50, metric: "total_tokens", scope: ["user", "feature"], timezone: "UTC", window: "1d" })).toEqual({ maximum: 50, metric: "total_tokens", scope: ["user", "feature"], timezone: "UTC", window: "1d" });
    expect(projectableLimit({ algorithm: "token_bucket", capacity: 10, metric: "logical_requests", scope: ["user"] })).toBeUndefined();
    expect(projectableLimit({ algorithm: "calendar", maximum: 50, metric: "request_bytes", scope: ["user"], window: "1d" })).toBeUndefined();
    expect(projectableLimit({ algorithm: "calendar", maximum: 50, metric: "total_tokens", scope: ["platform"], window: "1d" })).toBeUndefined();
  });

  it("looks back far enough for the window without passing 2,000 windows", () => {
    const now = Date.parse("2026-10-08T00:00:00Z");
    expect(impactRange("1d", now)).toMatchObject({ days: 30, start: "2026-09-08T00:00:00.000Z" });
    expect(impactRange("1mo", now).days).toBe(90);
    expect(impactRange("1w", now).days).toBe(60);
    expect(impactRange("1m", now).days).toBe(1);
    expect(impactRange("1h", now).days * 24).toBeLessThanOrEqual(2_000);
  });
});

describe("policy insights", () => {
  it("says how many users each projectable limit would have stopped", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/usage/distribution?")) {
        const query = params(path);
        return Promise.resolve({ data: {
          end: instant, environment_id: query.get("environment_id"), histogram: [{ from: 1, subjects: 4210, to: 100000 }], limit_plan: query.get("limit_plan"),
          maximum: Number(query.get("maximum")), metric: query.get("metric"), over_subjects: 12, over_users: 12, peaks: { max: 210000, p50: 3000, p90: 40000, p99: 90000 },
          periods: 31, scope: ["user"], start: instant, subjects: 4210, timezone: "UTC", users: 4210, window: "1d"
        } });
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    wrap(<LimitImpact environmentID={environmentID} limits={[
      { algorithm: "calendar", hard: true, maximum: 50000, metric: "total_tokens", scope: ["user"], timezone: "UTC", window: "1d" },
      { algorithm: "token_bucket", capacity: 10, hard: true, metric: "logical_requests", refillPerSecond: 1, scope: ["user"] }
    ]} plan="free" />);
    expect(await screen.findByText(/12 users of 4,210 would have reached it at least once in the last 30 days on free/)).toBeInTheDocument();
    expect(screen.getByText(/not projected/)).toBeInTheDocument();
    const call = String(adminRequestMock.mock.calls[0]?.[0]);
    expect(Object.fromEntries(params(call))).toMatchObject({ limit_plan: "free", maximum: "50000", metric: "total_tokens", scope: "user", timezone: "UTC", window: "1d" });
  });

  it("lists active overrides for a plan being removed", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [
      { created_at: instant, created_by: "adm_0123456789abcdef", id: "uov_0123456789abcdef", limit_plan: "premium", reason: "Support", status: "active", user_id: "usr_0123456789abcdef" }
    ], page: { has_more: false } } });
    const onOpenUser = vi.fn();
    const user = userEvent.setup();
    wrap(<PlanOverrides environmentID={environmentID} onOpenUser={onOpenUser} plan="premium" />);
    expect(await screen.findByText("1 active override use premium")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "usr_0123456789abcdef" }));
    expect(onOpenUser).toHaveBeenCalledWith("usr_0123456789abcdef");
    expect(Object.fromEntries(params(String(adminRequestMock.mock.calls[0]?.[0])))).toMatchObject({ limit_plan: "premium", status: "active" });
  });

  it("shows how a feature's recent requests split across plans", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      const query = params(path);
      const empty = { truncated: false, values: [] };
      return Promise.resolve({ data: {
        end: instant, environment_id: environmentID, feature: query.get("feature"), requests: 4, start: instant,
        facets: { component_kind: empty, error_code: empty, feature: empty, limit_plan: { truncated: false, values: [{ count: 3, value: "free" }, { count: 1, value: "premium" }] }, model: empty, platform: empty, route: empty, status: empty, trust_source: empty, upstream: empty }
      } });
    });
    wrap(<PlanShare environmentID={environmentID} feature="chat" />);
    const share = await screen.findByRole("list", { name: "Plan share" });
    expect(share).toHaveTextContent("75% · 3");
    expect(share).toHaveTextContent("25% · 1");
  });

  it("switches between active and ended overrides and opens a user", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      const ended = params(path).get("status") === "ended";
      return Promise.resolve({ data: { items: [
        { created_at: instant, created_by: "adm_0123456789abcdef", id: ended ? "uov_1123456789abcdef" : "uov_0123456789abcdef", limit_plan: ended ? "free" : "premium", reason: ended ? "Trial ended" : "Support", ...(ended ? { revoked_at: instant } : {}), status: ended ? "revoked" : "active", user_id: ended ? "usr_1123456789abcdef" : "usr_0123456789abcdef" }
      ], page: { has_more: false } } });
    });
    const onOpenUser = vi.fn();
    const user = userEvent.setup();
    wrap(<OverrideList environmentID={environmentID} onOpenUser={onOpenUser} />);
    expect(await screen.findByText("Support")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Ended" }));
    const table = await screen.findByRole("table", { name: "Overrides" });
    expect(await within(table).findByText("Trial ended")).toBeInTheDocument();
    expect(within(table).getByText("Cleared")).toBeInTheDocument();
    await user.click(within(table).getByText("usr_1123456789abcdef"));
    expect(onOpenUser).toHaveBeenCalledWith("usr_1123456789abcdef");
  });
});

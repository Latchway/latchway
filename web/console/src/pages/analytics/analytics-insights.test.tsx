import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true, status: undefined as { server_capabilities: string[] } | undefined }
}));
vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { ConnectionBreakdownCard, ErrorCodesCard, MonthToDateCard, SettlementNotice } from "./analytics-insights";
import { summaryFixture, zero } from "./usage-fixture";

const environmentID = "env_0123456789abcdef";
const instant = "2026-10-08T00:00:00Z";
const day = { end: Date.parse("2026-10-08T00:00:00Z"), start: Date.parse("2026-10-07T00:00:00Z") };
const latency = (p50: number, p95: number, samples = 4) => ({ p50_ms: p50, p95_ms: p95, p99_ms: p95, samples });

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{children}</QueryClientProvider>);
}

function params(path: string): URLSearchParams {
  return new URLSearchParams(path.split("?")[1] ?? "");
}

function doctor(jobs: Record<string, unknown>, replicas: Record<string, unknown>, checks: unknown[] = []) {
  return { checks, facts: { jobs: { usage_settlement_backlog: 0, ...jobs }, replicas: { fresh_workers: 1, ...replicas } }, overall_state: "degraded" };
}

beforeEach(() => {
  adminRequestMock.mockReset();
  compatibility.status = undefined;
});
afterEach(() => {
  vi.useRealTimers();
});

describe("settlement notice", () => {
  it("says how many requests are waiting for usage settlement and that nothing is lost", async () => {
    adminRequestMock.mockResolvedValue({ data: doctor({ usage_settlement_backlog: 3 }, {}) });
    wrap(<SettlementNotice workspaceSearch={{}} />);
    expect(await screen.findByText("Recent totals may be low")).toBeInTheDocument();
    expect(screen.getByText(/3 requests are waiting for usage settlement on this server\./)).toHaveTextContent("nothing is lost");
    expect(screen.getByRole("link", { name: "Open System Health" })).toHaveAttribute("href", "/system-health");
  });

  it("warns when no worker is running to settle usage", async () => {
    adminRequestMock.mockResolvedValue({ data: doctor({}, { fresh_workers: 0 }) });
    wrap(<SettlementNotice workspaceSearch={{}} />);
    expect(await screen.findByText(/No background worker is running/)).toBeInTheDocument();
  });

  it("stays quiet when usage is settled and reconciliation is fresh", async () => {
    adminRequestMock.mockResolvedValue({ data: doctor({}, {}, [{ id: "usage_reconciliation_freshness", state: "passed", summary: "ok" }]) });
    const { container } = wrap(<SettlementNotice workspaceSearch={{}} />);
    await vi.waitFor(() => expect(adminRequestMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});

describe("month to date", () => {
  it("projects month-end cost from this UTC month and compares it with last month", async () => {
    vi.useFakeTimers({ now: Date.parse("2026-10-08T12:00:00Z"), toFake: ["Date"] });
    adminRequestMock.mockImplementation((path: string) => {
      const start = params(path).get("start");
      if (start === "2026-10-01T00:00:00Z") return Promise.resolve({ data: summaryFixture({ values: { ...zero, cost_nano_usd: 3_000_000_000, logical_requests: 30 } }) });
      if (start === "2026-09-01T00:00:00Z") return Promise.resolve({ data: summaryFixture({ values: { ...zero, cost_nano_usd: 10_000_000_000, logical_requests: 90 } }) });
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    wrap(<MonthToDateCard environmentID={environmentID} />);
    const card = screen.getByRole("region", { name: "This month" });
    expect(await within(card).findByText("$3.00")).toBeInTheDocument();
    expect(await within(card).findByText("$12.40")).toBeInTheDocument();
    expect(await within(card).findByText("$10.00")).toBeInTheDocument();
    expect(card).toHaveTextContent("If the rest of October runs at this pace");
    expect(card).toHaveTextContent("September");
    expect(params(String(adminRequestMock.mock.calls.find(([path]) => params(String(path)).get("start") === "2026-09-01T00:00:00Z")?.[0])).get("end")).toBe("2026-10-01T00:00:00Z");
  });

  it("waits for the first full day before projecting", async () => {
    vi.useFakeTimers({ now: Date.parse("2026-10-01T09:00:00Z"), toFake: ["Date"] });
    adminRequestMock.mockResolvedValue({ data: summaryFixture() });
    wrap(<MonthToDateCard environmentID={environmentID} />);
    expect(await screen.findByText("Projects after the first full day")).toBeInTheDocument();
  });
});

describe("connection breakdown", () => {
  function connections() {
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/usage/connections?")) {
        return Promise.resolve({ data: {
          connections: [
            { attempts: 20, canceled: 0, duration: latency(900, 2400), failed: 2, failures: [{ code: "upstream_rejected", count: 2 }], fell_back: 2, first_byte: latency(300, 800), rate_limited: 2, server_errors: 0, succeeded: 18, upstream: "openai", usage: { ...zero, cost_nano_usd: 1_000_000_000, logical_requests: 18, total_tokens: 1800 } },
            { attempts: 4, canceled: 0, duration: latency(1200, 1500), failed: 0, failures: [], fell_back: 0, first_byte: latency(400, 600), rate_limited: 0, server_errors: 0, succeeded: 4, upstream: "anthropic", usage: { ...zero, cost_nano_usd: 3_000_000_000, logical_requests: 4, total_tokens: 400 } }
          ],
          end: instant, environment_id: params(path).get("environment_id"), start: instant, truncated: false
        } });
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
  }

  it("ranks connections by cost with their share and opens a connection's requests", async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    compatibility.status = { server_capabilities: ["admin_operations_history"] };
    connections();
    wrap(<ConnectionBreakdownCard environmentID={environmentID} mode="cost" onOpen={onOpen} window={day} />);
    const table = await screen.findByRole("table", { name: "Cost by AI connection" });
    const [first, second] = within(table).getAllByRole("row").slice(1);
    expect(first).toHaveTextContent("anthropic");
    expect(first).toHaveTextContent("75%");
    expect(second).toHaveTextContent("$1.00");
    await user.click(within(table).getByText("openai"));
    expect(onOpen).toHaveBeenCalledWith("openai");
    expect(params(String(adminRequestMock.mock.calls[0]?.[0])).get("start")).toBe("2026-10-07T00:00:00Z");
  });

  it("shows latency and failures per connection", async () => {
    compatibility.status = { server_capabilities: ["admin_operations_history"] };
    connections();
    wrap(<><ConnectionBreakdownCard environmentID={environmentID} mode="performance" onOpen={vi.fn()} window={day} /><ConnectionBreakdownCard environmentID={environmentID} mode="reliability" onOpen={vi.fn()} window={day} /></>);
    const latencyTable = await screen.findByRole("table", { name: "Latency by AI connection" });
    expect(within(latencyTable).getAllByRole("row")[1]).toHaveTextContent("300 ms · 800 ms");
    const failures = await screen.findByRole("table", { name: "Failures by AI connection" });
    expect(within(failures).getAllByRole("row")[1]).toHaveTextContent("90%");
    expect(within(failures).getAllByRole("row")[1]).toHaveTextContent("upstream_rejected ×2");
  });

  it("explains instead of asking an older server or a range over 90 days", async () => {
    const { unmount } = wrap(<ConnectionBreakdownCard environmentID={environmentID} mode="cost" onOpen={vi.fn()} window={day} />);
    expect(screen.getByText("This server can't break usage down by AI connection.")).toBeInTheDocument();
    unmount();
    compatibility.status = { server_capabilities: ["admin_operations_history"] };
    wrap(<ConnectionBreakdownCard environmentID={environmentID} mode="cost" onOpen={vi.fn()} window={{ ...day, start: day.end - 120 * 86_400_000 }} />);
    expect(screen.getByText(/at most 90 days/)).toBeInTheDocument();
    expect(adminRequestMock).not.toHaveBeenCalled();
  });
});

describe("errors by code", () => {
  it("counts requests by final error code and opens a code's requests", async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    compatibility.status = { server_capabilities: ["admin_request_search"] };
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/requests/facets?")) {
        const empty = { truncated: false, values: [] };
        return Promise.resolve({ data: {
          end: instant, environment_id: params(path).get("environment_id"),
          facets: { component_kind: empty, error_code: { truncated: false, values: [{ count: 30, value: "quota_exceeded" }, { count: 10, value: "upstream_unavailable" }] }, feature: empty, limit_plan: empty, model: empty, platform: empty, route: empty, status: empty, trust_source: empty, upstream: empty },
          requests: 200, start: instant
        } });
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    wrap(<ErrorCodesCard environmentID={environmentID} onOpen={onOpen} window={day} />);
    const list = await screen.findByRole("list", { name: "Errors by code" });
    expect(within(list).getAllByRole("listitem")[0]).toHaveTextContent("30 · 15%");
    await user.click(within(list).getByRole("button", { name: "upstream_unavailable" }));
    expect(onOpen).toHaveBeenCalledWith("upstream_unavailable");
    expect(params(String(adminRequestMock.mock.calls[0]?.[0])).get("environment_id")).toBe(environmentID);
  });

  it("says an older server can't count by error code", () => {
    wrap(<ErrorCodesCard environmentID={environmentID} onOpen={vi.fn()} window={day} />);
    expect(screen.getByText("This server can't count requests by error code")).toBeInTheDocument();
    expect(adminRequestMock).not.toHaveBeenCalled();
  });
});

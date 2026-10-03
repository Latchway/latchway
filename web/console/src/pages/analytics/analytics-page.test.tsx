import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, navigateMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn(), navigateMock: vi.fn() }));

vi.mock("../../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/admin")>()),
  adminRequest: adminRequestMock
}));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: [], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: React.ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>,
  useNavigate: () => navigateMock
}));

import { dispatchAdminRefresh } from "../../api/admin-events";
import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
import { type AnalyticsTab, AnalyticsPage } from "./analytics-page";
import { summaryFixture, zero } from "./usage-fixture";

const ENV = "env_0123456789abcdef";
const missing = { provenance: [], recorded_units: null, reported_units: null, unknown_units: null };

function calls(prefix: string): URLSearchParams[] {
  return adminRequestMock.mock.calls.map(([path]) => String(path)).filter((path) => path.startsWith(prefix)).map((path) => new URLSearchParams(path.split("?")[1]));
}

function respond(summary = summaryFixture(), interval?: "hour" | "day") {
  adminRequestMock.mockImplementation(async (path: string) => {
    if (path.startsWith("/admin/v1/usage/summary")) return { data: summary };
    const requested = new URLSearchParams(path.split("?")[1]).get("interval") as "hour" | "day";
    const start = new URLSearchParams(path.split("?")[1]).get("start") ?? "";
    return { data: { interval: interval ?? requested, points: [{ timestamp: start.replace(/T.*/, "T00:00:00Z"), values: { ...zero, logical_requests: 3 } }] } };
  });
}

function renderAnalytics(tab: AnalyticsTab, initial: WorkspaceSearch = {}) {
  const organization = { created_at: "2026-08-29T00:00:00Z", display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: "2026-08-29T00:00:00Z", display_name: "Mobile App", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile-app", status: "active" as const };
  const environment = { application_id: application.id, created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: ENV, kind: "production" as const, slug: "production", status: "active" as const };
  function Harness() {
    const [search, setSearch] = useState<WorkspaceSearch>({ application: "mobile-app", environment: "production", organization: "example", ...initial });
    const value: WorkspaceContextValue = {
      application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false,
      isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(),
      updateSearch: (patch) => setSearch((current) => ({ ...current, ...patch }))
    };
    return <WorkspaceContext.Provider value={value}><AnalyticsPage tab={tab} /></WorkspaceContext.Provider>;
  }
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Harness /></QueryClientProvider>);
}

beforeEach(() => {
  adminRequestMock.mockReset();
  navigateMock.mockReset();
});
afterEach(cleanup);

describe("Analytics", () => {
  it("loads the period and the previous period from the usage API and shows usage tiles", async () => {
    respond();
    renderAnalytics("usage");
    expect(await screen.findByText("Requests", { selector: ".lw-stat__label" })).toBeInTheDocument();
    const summaries = calls("/admin/v1/usage/summary");
    expect(summaries).toHaveLength(2);
    expect(summaries[0]?.get("environment_id")).toBe(ENV);
    expect(summaries[0]?.get("breakdown_limit")).toBe("50");
    expect(Date.parse(summaries[0]?.get("start") ?? "") - Date.parse(summaries[1]?.get("start") ?? "")).toBe(7 * 86_400_000);
    expect(calls("/admin/v1/usage/timeseries")[0]?.get("interval")).toBe("day");
    expect(screen.getByText(/\(UTC days\)/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "How sure these numbers are" })).toBeInTheDocument();
  });

  it("skips the comparison calls when compare is off and fetches more rows on request", async () => {
    respond();
    const user = userEvent.setup();
    renderAnalytics("usage", { compare: "off" });
    await screen.findByText("Requests", { selector: ".lw-stat__label" });
    expect(calls("/admin/v1/usage/summary")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "200" }));
    await waitFor(() => expect(calls("/admin/v1/usage/summary").at(-1)?.get("breakdown_limit")).toBe("200"));
  });

  it("drills from a breakdown row and a chart bar into Requests with real filters", async () => {
    respond();
    const user = userEvent.setup();
    renderAnalytics("usage");
    await user.click(await screen.findByText("assistant"));
    expect(navigateMock).toHaveBeenLastCalledWith(expect.objectContaining({ search: expect.objectContaining({ feature: "assistant", start: expect.any(String) }), to: "/requests" }));
    const bars = screen.getAllByRole("button", { name: /^Sep|^[A-Z][a-z]{2} \d/ });
    await user.click(bars[0] as HTMLElement);
    const drill = navigateMock.mock.calls.at(-1)?.[0] as { search: { end: string; start: string } };
    expect(Date.parse(drill.search.end) - Date.parse(drill.search.start)).toBe(86_400_000);
    await user.click(screen.getByRole("button", { name: "Plan" }));
    await user.click(await screen.findByText("Before plan tracking"));
    expect(navigateMock).toHaveBeenLastCalledWith(expect.objectContaining({ to: "/limit-plans" }));
  });

  it("warns about models with usage but no recorded cost and labels provider-reported cost", async () => {
    const summary = summaryFixture();
    respond(summaryFixture({ analytics: { ...summary.analytics, by_model: { items: [{ active_users: 1, key: "opaque", request_count: 4, values: { ...zero, details: { cost_nano_usd: missing, input_tokens: missing, output_tokens: missing, total_tokens: missing } } }], limit: 50, truncated: false } } }));
    renderAnalytics("cost");
    expect(await screen.findByText("1 model has no recorded cost")).toBeInTheDocument();
    expect(screen.getByText(/opaque \(4 requests\)/)).toBeInTheDocument();
    expect(screen.getByText("openrouter_usage_cost", { selector: "code" })).toBeInTheDocument();
    expect(screen.getByText(/LATCHWAY_ADMIN_API_TOKEN/, { selector: "code" })).toBeInTheDocument();
  });

  it("states each rate over its real denominator", async () => {
    respond();
    renderAnalytics("reliability");
    const card = (await screen.findByRole("region", { name: "App verification failures" }));
    expect(within(card).getByText(/1 of 4 verification checks/)).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Fallbacks" })).getByText(/1 of 3 requests that reached a provider/)).toBeInTheDocument();
  });

  it("shows latency percentiles with sample counts", async () => {
    respond();
    renderAnalytics("performance");
    const card = await screen.findByRole("region", { name: "Request latency" });
    expect(within(card).getByText("3 samples")).toBeInTheDocument();
    expect(within(card).getByText("300 ms")).toBeInTheDocument();
  });

  it("rejects a timeseries for the wrong interval and refreshes on usage hints", async () => {
    respond(summaryFixture(), "hour");
    renderAnalytics("usage");
    expect(await screen.findByRole("alert")).toHaveTextContent("Analytics context mismatch");
    cleanup();
    adminRequestMock.mockReset();
    respond();
    renderAnalytics("usage", { end: "2026-09-03T00:00:00.000Z", start: "2026-09-01T00:00:00.000Z" });
    await screen.findByText("Requests", { selector: ".lw-stat__label" });
    expect(calls("/admin/v1/usage/timeseries")[0]?.get("interval")).toBe("hour");
    const before = calls("/admin/v1/usage/summary").length;
    act(() => dispatchAdminRefresh(["usage"]));
    await waitFor(() => expect(calls("/admin/v1/usage/summary").length).toBeGreaterThan(before));
  });
});

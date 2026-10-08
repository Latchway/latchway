import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility, navigateMock, readiness } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true, status: undefined as { server_capabilities: string[] } | undefined },
  navigateMock: vi.fn(),
  readiness: { current: undefined as unknown }
}));
vi.mock("../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../api/health", async (importOriginal) => ({ ...(await importOriginal<typeof import("../api/health")>()), useSystemHealth: () => ({ liveness: { data: undefined }, readiness: { data: readiness.current } }) }));
vi.mock("./console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, onClick, to }: { children: ReactNode; className?: string; onClick?: () => void; to: string }) => <a className={className} href={to} onClick={(event) => { event.preventDefault(); onClick?.(); }}>{children}</a>,
  useNavigate: () => navigateMock
}));

import { summaryFixture } from "../pages/analytics/usage-fixture";
import { AttentionButton } from "./attention-button";
import { WorkspaceContext, type WorkspaceContextValue } from "./workspace-context-value";

const organization = { created_at: "2026-08-29T00:00:00Z", display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
const application = { created_at: "2026-08-29T00:00:00Z", display_name: "Mobile App", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile-app", status: "active" as const };
const environment = { active_revision_id: "rev_0123456789abcdef", application_id: application.id, created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: "env_0123456789abcdef", kind: "production" as const, slug: "production", status: "active" as const };

function renderButton() {
  const value: WorkspaceContextValue = {
    application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false,
    isLoading: false, organization, search: { application: "mobile-app", environment: "production", organization: "example" }, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: vi.fn()
  };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><WorkspaceContext.Provider value={value}><AttentionButton /></WorkspaceContext.Provider></QueryClientProvider>);
}

function server({ sample, summary = summaryFixture() }: { sample?: Record<string, unknown>; summary?: ReturnType<typeof summaryFixture> } = {}) {
  adminRequestMock.mockImplementation((path: string) => {
    if (path.startsWith(`/admin/v1/environments/${environment.id}/config-revisions?`)) return Promise.resolve({ data: { items: [], page: { has_more: false } } });
    if (path === "/admin/v1/api-tokens") return Promise.reject(new Error("forbidden"));
    if (path.startsWith("/admin/v1/usage/summary?")) return Promise.resolve({ data: summary });
    if (path.startsWith("/admin/v1/system/health-history?")) return Promise.resolve({ data: { end: new Date().toISOString(), interval_seconds: 300, samples: sample ? [sample] : [], start: new Date().toISOString() } });
    return Promise.reject(new Error(`Unexpected request: ${path}`));
  });
}

beforeEach(() => {
  adminRequestMock.mockReset();
  navigateMock.mockReset();
  compatibility.status = undefined;
  readiness.current = undefined;
});

describe("header attention", () => {
  it("counts what needs attention from the last day and lists it, opening the page that fixes each", async () => {
    const user = userEvent.setup();
    compatibility.status = { server_capabilities: ["admin_operations_history"] };
    server({
      sample: { failed_checks: ["worker_heartbeat"], overall_state: "unhealthy", sampled_at: new Date().toISOString(), warning_checks: [] },
      summary: summaryFixture({ analytics: { ...summaryFixture().analytics, failure_rate: { denominator: 40, numerator: 4, parts_per_million: 100_000 } } })
    });
    renderButton();
    const button = await screen.findByRole("button", { name: "2 things need attention" });
    expect(button).toHaveTextContent("2");
    expect(button.querySelector(".lw-attn-btn__count")).toHaveClass("is-critical");
    const summary = adminRequestMock.mock.calls.map(([path]) => String(path)).find((path) => path.startsWith("/admin/v1/usage/summary?")) ?? "";
    const query = new URLSearchParams(summary.split("?")[1]);
    expect(Date.parse(query.get("end") ?? "") - Date.parse(query.get("start") ?? "")).toBe(86_400_000);

    await user.click(button);
    const dialog = screen.getByRole("dialog", { name: "Needs attention" });
    expect(within(dialog).getByText("The server's self-check is unhealthy")).toBeInTheDocument();
    expect(within(dialog).getByText(/% of requests failed/)).toBeInTheDocument();
    await user.click(within(dialog).getAllByRole("button", { name: "Open System Health" })[0] as HTMLElement);
    expect(navigateMock).toHaveBeenCalledWith(expect.objectContaining({ to: "/system-health" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("says nothing needs attention and closes on Escape", async () => {
    const user = userEvent.setup();
    server({ summary: summaryFixture({ analytics: { ...summaryFixture().analytics, failure_rate: { denominator: 3, numerator: 0, parts_per_million: 0 } } }) });
    renderButton();
    await vi.waitFor(() => expect(adminRequestMock.mock.calls.some(([path]) => String(path).startsWith("/admin/v1/usage/summary?"))).toBe(true));
    const button = await screen.findByRole("button", { name: "Nothing needs attention" });
    expect(button.querySelector(".lw-attn-btn__count")).toBeNull();
    await user.click(button);
    expect(screen.getByRole("dialog", { name: "Needs attention" })).toHaveTextContent("Nothing needs attention");
    expect(adminRequestMock.mock.calls.some(([path]) => String(path).includes("health-history"))).toBe(false);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(button).toHaveFocus();
  });
});

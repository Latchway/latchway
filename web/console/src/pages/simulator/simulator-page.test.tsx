import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { current: { mutationAllowed: true, status: undefined as { server_capabilities: string[] } | undefined } }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration", "inspect_users"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility.current }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
import type { RouteSimulation } from "../../api/admin";
import type { JSONRecord } from "../configuration-slice";
import { simulationFixture } from "./simulator-fixture";
import { SimulatorPage } from "./simulator-page";

const instant = "2026-08-29T00:00:00Z";
const environmentID = "env_0123456789abcdef";
const activeID = "rev_0123456789abcdef";
const userID = "usr_0123456789abcdef";

const live: JSONRecord = {
  apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: {},
  spec: { features: [{ id: "assistant" }], limitPlans: [{ id: "free", limits: [] }, { id: "premium", limits: [] }] }
};

type Options = { body?: unknown; method?: string } | undefined;
const searchLog: WorkspaceSearch[] = [];

function server(result: (body: JSONRecord) => JSONRecord) {
  adminRequestMock.mockImplementation((path: string, _schema: unknown, request: Options) => {
    if (path === `/admin/v1/environments/${environmentID}/config`) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: live, environment_id: environmentID, id: activeID, state: "active", version: 1 }, etag: '"active"' });
    if (path.startsWith(`/admin/v1/environments/${environmentID}/config-revisions?`)) return Promise.resolve({ data: { items: [], page: { has_more: false } } });
    if (path === `/admin/v1/config-revisions/${activeID}/simulate`) return Promise.resolve({ data: result(request?.body as JSONRecord) });
    if (path.startsWith(`/admin/v1/users/${userID}/effective-configuration`)) {
      return Promise.resolve({ data: { decision_stages: [], denial_reason: "access_denied", environment_id: environmentID, environment_kind: "production", evaluation_mode: "current_user_projection", feature: "assistant", inputs: [{ availability: "available", detail: "From the latest session", fact: "normalized_claims", source: "session" }], limits: [], policy_outcome: "denied", revision_id: activeID, routes: [], subject: { id: userID, kind: "user", user_id: userID }, warnings: [] } });
    }
    return Promise.reject(new Error(`Unexpected request: ${path}`));
  });
}

function Harness({ initial }: { initial: WorkspaceSearch }) {
  const [search, setSearch] = useState<WorkspaceSearch>(initial);
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Mobile", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile", status: "active" as const };
  const environment = { active_revision_id: activeID, application_id: application.id, created_at: instant, display_name: "Production", id: environmentID, kind: "production" as const, slug: "production", status: "active" as const };
  const value: WorkspaceContextValue = { application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: (patch) => { searchLog.push(patch as WorkspaceSearch); setSearch((current) => ({ ...current, ...patch })); } };
  return <WorkspaceContext.Provider value={value}><SimulatorPage /></WorkspaceContext.Provider>;
}

function renderPage(initial: WorkspaceSearch = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><Harness initial={initial} /></QueryClientProvider>);
}

beforeEach(() => {
  adminRequestMock.mockReset();
  searchLog.length = 0;
  compatibility.current = { mutationAllowed: true, status: undefined };
});

describe("Simulator", () => {
  it("runs a sample request, shows the decision trace, and keeps claims out of the URL", async () => {
    const user = userEvent.setup();
    server(() => simulationFixture({ limit_plan: "premium", revision_id: activeID }) as unknown as JSONRecord);
    renderPage();
    const plan = await screen.findByLabelText("Plan claim");
    await user.clear(plan);
    await user.type(plan, "premium");
    await user.selectOptions(screen.getByLabelText("Platform"), "web");
    await user.selectOptions(screen.getByLabelText("Trust level"), "app_verified");
    expect(screen.getByText(/A web page can't prove it's a genuine app/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Simulate" }));

    expect(await screen.findByText("Allowed")).toBeInTheDocument();
    expect(screen.getByText("premium · fast on openai")).toBeInTheDocument();
    expect([...document.querySelectorAll(".lw-trace__head strong")].map((node) => node.textContent)).toEqual(["Signed in", "App verified", "Feature access", "Limit plan", "Quota reserved", "Route"]);
    const call = adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/simulate"));
    expect((call?.[2] as Options)?.body).toMatchObject({ feature: "assistant", platform: "web", principal: { authenticated: true, claims: { plan: "premium" } }, trust_level: "app_verified" });
    expect(JSON.stringify(searchLog)).not.toContain("premium");
    expect(searchLog.at(-1)).toMatchObject({ feature: "assistant", platform: "web", trust_level: "app_verified" });

    await user.click(screen.getByRole("button", { name: "openai" }));
    expect(screen.getByText(/Handles it/)).toBeInTheDocument();
  });

  it("names the stage that denied the request and links to its fix", async () => {
    const user = userEvent.setup();
    server(() => simulationFixture({ allowed: false, explanation: ["The compiled access expression denied the simulated principal."], fallback_sequence: undefined, limit_plan: undefined, limits: undefined, model: undefined, reservation: undefined, revision_id: activeID, route: undefined, upstream: undefined }) as unknown as JSONRecord);
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Simulate" }));
    expect(await screen.findByText("Denied at Feature access")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Access & limits" })).toHaveAttribute("href", "/features");
    expect(screen.getAllByText("Not reached").length).toBe(3);
  });

  it("refuses to show a result that belongs to another revision", async () => {
    const user = userEvent.setup();
    server(() => simulationFixture({ revision_id: "rev_9999999999999999" }) as unknown as JSONRecord);
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Simulate" }));
    expect(await screen.findByText(/didn't match the selected revision and feature/)).toBeInTheDocument();
    expect(screen.queryByText("Allowed")).not.toBeInTheDocument();
  });

  it("checks a real user against the live revision and offers an override when denied", async () => {
    const user = userEvent.setup();
    server(() => ({}));
    renderPage({ mode: "user" });
    await user.type(await screen.findByLabelText("User ID"), userID);
    await user.click(screen.getByRole("button", { name: "Check User" }));
    expect(await screen.findByText("Denied · access_denied")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Override Plan" })).toHaveAttribute("href", "/user-overrides");
    expect(within(screen.getByText("Inputs").closest("section") ?? document.body).getByText("normalized_claims")).toBeInTheDocument();
  });

  describe("with policy insights", () => {
    const insights = { server_capabilities: ["admin_policy_insights"] };
    const attemptPlan = (condition: string): NonNullable<RouteSimulation["attempt_plan"]> => ({
      assumptions: ["Every retry delay fits within the request deadline."],
      attempts: [
        { condition, model: "fast", next: "fallback", number: 1, outcome: "failed", route: "primary", upstream: "openai" },
        { model: "slow", number: 2, outcome: "succeeded", route: "backup", upstream: "anthropic" }
      ],
      outcome: "served",
      served_by_route: "backup"
    });

    function insightServer() {
      const scenarios: JSONRecord[] = [];
      adminRequestMock.mockImplementation((path: string, _schema: unknown, request: Options) => {
        const body = request?.body as JSONRecord | undefined;
        if (path === `/admin/v1/environments/${environmentID}/config`) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: live, environment_id: environmentID, id: activeID, state: "active", version: 1 }, etag: '"active"' });
        if (path.startsWith(`/admin/v1/environments/${environmentID}/config-revisions?`)) return Promise.resolve({ data: { items: [], page: { has_more: false } } });
        if (path === `/admin/v1/config-revisions/${activeID}/simulate`) {
          const failures = body?.failures as Array<{ condition: string }> | undefined;
          return Promise.resolve({ data: simulationFixture({ revision_id: activeID, ...(failures ? { attempt_plan: attemptPlan(failures[0]?.condition ?? "") } : {}) }) });
        }
        if (path === `/admin/v1/config-revisions/${activeID}/simulate-batch`) {
          const requests = (body?.requests as unknown[]) ?? [];
          return Promise.resolve({ data: { items: requests.map((_, index) => ({ index, result: simulationFixture({ revision_id: activeID }) })) } });
        }
        if (path === "/admin/v1/applications/app_0123456789abcdef/simulation-scenarios" && (request?.method ?? "GET") === "GET") return Promise.resolve({ data: { items: scenarios } });
        if (path === "/admin/v1/applications/app_0123456789abcdef/simulation-scenarios" && request?.method === "POST") {
          const saved = { application_id: "app_0123456789abcdef", created_at: instant, created_by: "adm_0123456789abcdef", id: "ssc_01M4DPCZCBWV5683M275WHYQGA", input: body?.input, name: body?.name, updated_at: instant, updated_by: "adm_0123456789abcdef", version: 1 };
          scenarios.push(saved);
          return Promise.resolve({ data: saved });
        }
        if (path.startsWith("/admin/v1/simulation-scenarios/") && request?.method === "DELETE") { scenarios.length = 0; return Promise.resolve({ data: undefined }); }
        if (path.startsWith(`/admin/v1/users/${userID}/effective-configuration`)) {
          return Promise.resolve({ data: {
            decision_stages: [], environment_id: environmentID, environment_kind: "production", evaluation_mode: "current_user_projection", feature: "assistant", inputs: [],
            limit_plan: "free", limit_plan_source: "feature_limit_plan_expression",
            limits: [{ algorithm: "calendar", hard: true, index: 0, maximum: 50, metric: "logical_requests", scope: ["user", "feature"], source: "plan free", timezone: "UTC", usage: { maximum: 50, observed_at: instant, remaining: 38, reserved: 2, resets_at: "2026-08-30T00:00:00Z", used: 10 }, window: "1d" }],
            policy_outcome: "allowed", revision_id: activeID, routes: [], subject: { id: userID, kind: "user", user_id: userID }, warnings: []
          } });
        }
        return Promise.reject(new Error(`Unexpected request: ${request?.method ?? "GET"} ${path}`));
      });
      compatibility.current = { mutationAllowed: true, status: insights };
      return scenarios;
    }

    it("asks the server what happens when a connection is down", async () => {
      const user = userEvent.setup();
      insightServer();
      renderPage();
      await user.click(await screen.findByRole("button", { name: "Simulate" }));
      await user.click(await screen.findByRole("button", { name: "openai" }));
      const attempts = await screen.findByRole("list", { name: "Attempts" });
      expect(attempts).toHaveTextContent("Fails (connect_error) · falls back");
      expect(attempts).toHaveTextContent("Succeeds");
      const failing = adminRequestMock.mock.calls.filter(([path, , options]) => String(path).endsWith("/simulate") && (options as Options & { body?: JSONRecord })?.body && "failures" in ((options as { body: JSONRecord }).body));
      expect(((failing.at(-1)?.[2] as { body: JSONRecord }).body).failures).toEqual([{ condition: "connect_error", route: "primary" }]);
      await user.selectOptions(screen.getByLabelText("Fails with"), "status_429");
      expect(await screen.findByText(/Fails \(status_429\)/)).toBeInTheDocument();
      expect(screen.queryByText(/Worked out in the browser/)).not.toBeInTheDocument();
    });

    it("runs the coverage grid in one batch", async () => {
      const user = userEvent.setup();
      insightServer();
      renderPage({ mode: "grid" });
      const run = await screen.findByRole("button", { name: /^Run \d+ Requests$/ });
      await user.click(run);
      await screen.findAllByText("fast");
      const batches = adminRequestMock.mock.calls.filter(([path]) => String(path).endsWith("/simulate-batch"));
      const singles = adminRequestMock.mock.calls.filter(([path]) => String(path).endsWith("/simulate"));
      expect(batches).toHaveLength(1);
      expect(singles).toHaveLength(0);
      expect(((batches[0]?.[2] as { body: { requests: unknown[] } }).body.requests).length).toBe(Number(/Run (\d+)/.exec(run.textContent ?? "")?.[1]));
    });

    it("saves, loads and deletes a scenario", async () => {
      const user = userEvent.setup();
      insightServer();
      renderPage();
      const plan = await screen.findByLabelText("Plan claim");
      await user.clear(plan);
      await user.type(plan, "premium");
      await user.type(screen.getByLabelText("Save current inputs as"), "Premium on iOS");
      await user.click(screen.getByRole("button", { name: "Save" }));
      expect(await screen.findByText("Saved Premium on iOS.")).toBeInTheDocument();
      const save = adminRequestMock.mock.calls.find(([path, , options]) => String(path).endsWith("/simulation-scenarios") && (options as Options)?.method === "POST");
      expect((save?.[2] as { body: { input: JSONRecord; name: string } }).body).toMatchObject({ input: { feature: "assistant", principal: { claims: { plan: "premium" } } }, name: "Premium on iOS" });
      await user.clear(plan);
      await user.type(plan, "free");
      await user.click(screen.getByRole("button", { name: "Load" }));
      expect(screen.getByLabelText("Plan claim")).toHaveValue("premium");
      await user.click(screen.getByRole("button", { name: "Delete scenario" }));
      await user.click(within(screen.getByRole("alertdialog", { name: "Delete Premium on iOS?" })).getByRole("button", { name: "Delete Scenario" }));
      expect(await screen.findByText("Deleted Premium on iOS.")).toBeInTheDocument();
    });

    it("shows how much of each limit a real user has used", async () => {
      const user = userEvent.setup();
      insightServer();
      renderPage({ mode: "user" });
      await user.type(await screen.findByLabelText("User ID"), userID);
      await user.click(screen.getByRole("button", { name: "Check User" }));
      expect(await screen.findByText(/10 of 50 used, 2 in flight · 38 left/)).toBeInTheDocument();
      expect(screen.getByText(/for the user's current installation/)).toBeInTheDocument();
    });
  });
});

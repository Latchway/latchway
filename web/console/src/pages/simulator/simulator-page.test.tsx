import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration", "inspect_users"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => ({ mutationAllowed: true }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
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
});

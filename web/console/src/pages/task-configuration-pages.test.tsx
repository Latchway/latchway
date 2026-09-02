import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, runDevelopmentSampleMock } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  runDevelopmentSampleMock: vi.fn()
}));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock,
  runDevelopmentSample: runDevelopmentSampleMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration", "run_self_tests"], organization_id: "org_0123456789abcdef" } } })
}));

const workspace = {
  application: { created_at: "2026-08-29T00:00:00Z", display_name: "Habitify", id: "app_0123456789abcdef", organization_id: "org_0123456789abcdef", slug: "habitify", status: "active" as const },
  applications: [],
  environment: { active_revision_id: "rev_0123456789abcdef", application_id: "app_0123456789abcdef", created_at: "2026-08-29T00:00:00Z", display_name: "Development", id: "env_0123456789abcdef", kind: "development" as const, slug: "development", status: "active" as const },
  environments: [], invalidApplication: false, invalidEnvironment: false, isLoading: false,
  search: {}, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: vi.fn()
};

vi.mock("../app/workspace-context-value", () => ({ useOptionalWorkspace: () => workspace }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, to }: { children: React.ReactNode; to: string }) => <a href={to}>{children}</a>
}));

import { ConnectionWorkspacePage, UsagePlanWorkspacePage } from "./task-configuration-pages";

const instant = "2026-08-29T00:00:00Z";
const activeDocument = {
  apiVersion: "latchway.dev/v1alpha1",
  kind: "EnvironmentConfig",
  metadata: { application: "habitify", environment: "development", organization: "example" },
  spec: {
    features: [{ access: { expression: "principal.authenticated" }, id: "habit-assistant", protocol: "openai_responses", routes: [{ id: "primary", model: "fixture_model", priority: 10, when: "true" }] }],
    models: [{ capabilities: ["openai_responses"], id: "fixture_model", upstream: "development_mock", upstreamModel: "fixture-model" }],
    upstreams: [{ authentication: { type: "none" }, baseUrl: "http://127.0.0.1:19090", dangerousAllowInsecureHttp: true, id: "development_mock", type: "openai_compatible" }]
  }
};

beforeEach(() => {
  adminRequestMock.mockReset();
  runDevelopmentSampleMock.mockReset();
});

describe("development-first connection path", () => {
  it("runs the gateway-owned synthetic client and verifies its exact durable request", async () => {
    const user = userEvent.setup();
    runDevelopmentSampleMock.mockResolvedValue({ data: { feature: "habit-assistant", model: "fixture-model", protocol: "openai_responses", request_id: "req_0123456789abcdef", status: "succeeded" } });
    adminRequestMock.mockImplementation((path: string) => {
      if (path.endsWith("/config")) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      if (path === "/admin/v1/requests/req_0123456789abcdef") return Promise.resolve({ data: { attempts: [{ attempt_number: 1, id: "atm_0123456789abcdef", model: "fixture_model", route: "primary", started_at: instant, status: "succeeded", upstream: "development_mock" }], environment_id: workspace.environment.id, feature: "habit-assistant", id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef", protocol: "openai_responses", selected_physical_model: "fixture-model", started_at: instant, status: "succeeded", user_id: "usr_0123456789abcdef" } });
      if (path.startsWith("/admin/v1/requests?")) return Promise.resolve({ data: { items: [{ attempts: [{ attempt_number: 1, id: "atm_0123456789abcdef", model: "fixture_model", route: "primary", started_at: instant, status: "succeeded", upstream: "development_mock" }], environment_id: workspace.environment.id, feature: "habit-assistant", id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef", protocol: "openai_responses", started_at: instant, status: "succeeded", user_id: "usr_0123456789abcdef" }], page: { has_more: false } } });
      throw new Error(`Unexpected request: ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><ConnectionWorkspacePage /></QueryClientProvider>);

    expect(await screen.findByRole("heading", { name: "Local mock connection is ready." })).toBeInTheDocument();
    expect(screen.getByText(/not production attestation or physical-device proof/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run and verify development sample" }));
    expect(await screen.findByText(/Observed/)).toHaveTextContent("req_0123456789abcdef");
    expect(runDevelopmentSampleMock).toHaveBeenCalledOnce();
    expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/requests/req_0123456789abcdef", expect.anything());
  });
});

describe("usage-plan effective-limit inspection", () => {
  it("routes operators to the server-resolved Users inspector", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      if (path.endsWith("/config")) {
        return Promise.resolve({
          data: {
            activated_at: instant,
            created_at: instant,
            created_by: "adm_0123456789abcdef",
            document: activeDocument,
            environment_id: workspace.environment.id,
            id: "rev_0123456789abcdef",
            state: "active",
            version: 1
          },
          etag: '"active-etag"'
        });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><UsagePlanWorkspacePage /></QueryClientProvider>);

    const link = await screen.findByRole("link", { name: "Inspect resolved limits in Users" });
    expect(link).toHaveAttribute("href", "/users");
    expect(screen.queryByText(/no endpoint returns the fully resolved effective limits/i)).not.toBeInTheDocument();
  });
});

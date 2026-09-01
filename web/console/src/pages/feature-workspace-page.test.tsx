import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration"], organization_id: "org_0123456789abcdef" } } })
}));

const workspace = {
  application: { created_at: "2026-08-29T00:00:00Z", display_name: "Habitify", id: "app_0123456789abcdef", organization_id: "org_0123456789abcdef", slug: "habitify", status: "active" as "active" | "disabled" },
  applications: [],
  environment: { active_revision_id: "rev_0123456789abcdef", application_id: "app_0123456789abcdef", created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: "env_0123456789abcdef", kind: "production" as const, slug: "production", status: "active" as "active" | "disabled" },
  environments: [], invalidApplication: false, invalidEnvironment: false, isLoading: false,
  search: {}, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: vi.fn()
};

vi.mock("../app/workspace-context-value", () => ({
  useOptionalWorkspace: () => workspace
}));

import { FeatureWorkspacePage } from "./feature-workspace-page";
import type { JSONRecord } from "./configuration-slice";

const instant = "2026-08-29T00:00:00Z";
const activeID = "rev_0123456789abcdef";
const draftID = "rev_1123456789abcdef";

function activeDocument(): JSONRecord {
  return {
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: { application: "habitify", environment: "production", organization: "example", retained: "yes" },
    spec: {
      attestationPolicies: [{ id: "native", platforms: {} }],
      features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "weekly_summary", limitPlan: { expression: "'free'" }, output: { absoluteMaximumTokens: 1000, defaultMaximumTokens: 500 }, protocol: "openai_responses", routes: [{ id: "primary", model: "fast", priority: 10, when: "true" }] }],
      identityProviders: [{ id: "firebase", projectId: "example-mobile", type: "firebase" }],
      limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], window: "1d" }] }],
      models: [{ capabilities: ["openai_responses"], id: "fast", upstream: "primary", upstreamModel: "fast-model" }, { capabilities: ["openai_responses"], id: "reliable", upstream: "primary", upstreamModel: "reliable-model" }],
      upstreams: [{ authentication: { type: "none" }, baseUrl: "https://api.example.test/v1", id: "primary", type: "openai_compatible" }]
    }
  };
}

function revision(id: string, document: JSONRecord, state: "active" | "draft", version: number) {
  return { activated_at: state === "active" ? instant : undefined, created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: workspace.environment.id, id, state, version };
}

beforeEach(() => {
  adminRequestMock.mockReset();
  workspace.search = {};
  workspace.updateSearch.mockReset();
  workspace.application.status = "active";
  workspace.environment.status = "active";
});

describe("task-oriented feature setup", () => {
  it("stages and validates a preserved full document before explicit Production publish", async () => {
    const user = userEvent.setup();
    const original = activeDocument();
    let patched: JSONRecord | undefined;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { body?: unknown; etag?: string; method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: revision(activeID, original, "active", 1), etag: '"active-etag"' });
      if (path.endsWith("/config-revisions") && options?.method === "POST") return Promise.resolve({ data: revision(draftID, original, "draft", 2), etag: '"draft-etag-1"' });
      if (path === `/admin/v1/config-revisions/${draftID}` && options?.method === "PATCH") { patched = options.body as JSONRecord; return Promise.resolve({ data: revision(draftID, patched, "draft", 2), etag: '"draft-etag-2"' }); }
      if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
      if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [{ operation: "add", path: "/spec/features/1", summary: "Add habit assistant" }], from_revision_id: activeID, to_revision_id: draftID, warnings: [] } });
      if (path.endsWith("/activate")) return Promise.resolve({ data: revision(draftID, patched ?? original, "active", 2), etag: '"active-etag-2"' });
      throw new Error(`Unexpected request: ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><FeatureWorkspacePage /></QueryClientProvider>);

    expect(await screen.findByRole("heading", { name: "Create an AI capability." })).toBeInTheDocument();
    await screen.findByText("weekly_summary");
    await user.type(screen.getByLabelText("Client feature ID"), "habit_assistant");
    await user.selectOptions(screen.getByLabelText("Primary model"), "fast");
    await user.selectOptions(screen.getByLabelText("Fallback model"), "reliable");
    await user.selectOptions(screen.getByLabelText("User access"), "premium");
    await user.selectOptions(screen.getByLabelText("App verification"), "native");
    await user.selectOptions(screen.getByLabelText("Usage plan"), "free");
    await user.click(screen.getByRole("button", { name: "Review feature change" }));

    expect(await screen.findByRole("heading", { name: /Publish habit_assistant to Habitify \/ Production/ })).toBeInTheDocument();
    expect(adminRequestMock.mock.calls.some((call) => String(call[0]).endsWith("/activate"))).toBe(false);
    expect(patched?.metadata).toEqual(original.metadata);
    const features = ((patched?.spec as JSONRecord).features as JSONRecord[]);
    expect(features).toHaveLength(2);
    expect(features[1]).toMatchObject({
      access: { expression: "principal.authenticated && principal.claims.plan == 'premium'" },
      attestationPolicy: "native",
      id: "habit_assistant",
      limitPlan: { expression: "'free'" },
      routes: [{ id: "primary", model: "fast" }, { id: "fallback", model: "reliable" }]
    });

    await user.click(screen.getByRole("button", { name: "Publish to Production" }));
    await waitFor(() => expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/config-revisions/${draftID}/activate`, expect.anything(), { etag: '"draft-etag-2"', method: "POST" }));
  });

  it("keeps disabled scopes inspectable while preventing configuration mutation", async () => {
    workspace.environment.status = "disabled";
    const original = activeDocument();
    adminRequestMock.mockResolvedValue({ data: revision(activeID, original, "active", 1), etag: '"active-etag"' });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><FeatureWorkspacePage /></QueryClientProvider>);

    expect(await screen.findByText("weekly_summary")).toBeInTheDocument();
    expect(screen.getByText("Selected scope is disabled").closest("section")).toHaveAttribute("role", "status");
    expect(screen.getByRole("button", { name: "Review feature change" })).toBeDisabled();
    expect(screen.getByText(/Re-enable both the application and environment/)).toBeInTheDocument();
  });

  it("restores and closes a validated feature selection without sharing builder inputs", async () => {
    workspace.search = { feature: "weekly_summary" };
    adminRequestMock.mockResolvedValue({ data: revision(activeID, activeDocument(), "active", 1), etag: '"active-etag"' });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={queryClient}><FeatureWorkspacePage /></QueryClientProvider>);

    expect(await screen.findByRole("heading", { name: "weekly_summary" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close feature" }));
    expect(workspace.updateSearch).toHaveBeenLastCalledWith({ feature: undefined });
    await user.click(screen.getByRole("button", { name: "weekly_summary" }));
    expect(workspace.updateSearch).toHaveBeenLastCalledWith({ feature: "weekly_summary" }, { replace: false });
    expect(workspace.updateSearch.mock.calls.flat().join(" ")).not.toMatch(/custom_access|limit_plan|primary_model|secret|token/i);
  });
});

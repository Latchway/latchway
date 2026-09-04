import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
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
vi.mock("../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => ({ mutationAllowed: true })
}));

const workspace = {
  application: { created_at: "2026-08-29T00:00:00Z", display_name: "Habitify", id: "app_01J00000000000000000000000", organization_id: "org_0123456789abcdef", slug: "habitify", status: "active" as "active" | "disabled" },
  applications: [],
  environment: { active_revision_id: "rev_0123456789abcdef", application_id: "app_0123456789abcdef", created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: "env_0123456789abcdef", kind: "production" as const, slug: "production", status: "active" as "active" | "disabled" },
  environments: [], invalidApplication: false, invalidEnvironment: false, isLoading: false,
  search: {}, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: vi.fn()
};

vi.mock("../app/workspace-context-value", () => ({
  useOptionalWorkspace: () => workspace
}));

import { buildFeatureClientSetupSnippets, FeatureWorkspacePage } from "./feature-workspace-page";
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
      attestationPolicies: [{ id: "native", platforms: {
        android: { minimumTrustLevel: "app_verified", mode: "required", playIntegrity: { cloudProjectNumber: 123456 }, provider: "play_integrity" },
        ios: { appAttest: {}, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" },
        react_native_android: { minimumTrustLevel: "app_verified", mode: "required", playIntegrity: { cloudProjectNumber: 654321 }, provider: "play_integrity" },
        react_native_ios: { appAttest: {}, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" },
        web: { allowedOrigins: ["https://app.example.test"], minimumTrustLevel: "web_risk_verified", mode: "required", provider: "turnstile", secretRef: "secret/turnstile_private_do_not_render", turnstile: { allowedHostnames: ["app.example.test"], expectedAction: "latchway_session" } }
      } }],
      componentDefinitions: [
        { allowedFeatures: ["weekly_summary"], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: "ios_main", kind: "main_app", platform: "ios" },
        { allowedFeatures: ["weekly_summary"], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: "android_main", kind: "android_app", platform: "android" },
        { allowedFeatures: ["weekly_summary"], attestation: { provider: "turnstile", strategy: "direct" }, familyRole: "root", id: "web_main", kind: "browser", platform: "web" },
        { allowedFeatures: ["weekly_summary"], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: "react_native_ios_main", kind: "main_app", platform: "react_native_ios" },
        { allowedFeatures: ["weekly_summary"], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: "react_native_android_main", kind: "android_app", platform: "react_native_android" }
      ],
      features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "weekly_summary", limitPlan: { expression: "'free'" }, output: { absoluteMaximumTokens: 1000, defaultMaximumTokens: 500 }, protocol: "openai_responses", routes: [{ id: "primary", model: "fast", priority: 10, when: "true" }] }],
      identityProviders: [{ id: "firebase", projectId: "example-mobile", type: "firebase" }],
      limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], window: "1d" }] }],
      models: [{ capabilities: ["openai_responses"], id: "fast", upstream: "primary", upstreamModel: "fast-model" }, { capabilities: ["openai_responses"], id: "reliable", upstream: "primary", upstreamModel: "reliable-model" }],
      upstreams: [{ authentication: { secretRef: "secret/provider_super_secret", type: "bearer" }, baseUrl: "https://api.example.test/v1", id: "primary", type: "openai_compatible" }]
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
    await screen.findByRole("button", { name: "weekly_summary" });
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

    expect(await screen.findByRole("button", { name: "weekly_summary" })).toBeInTheDocument();
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

  it("renders personalized copyable iOS, Android, Web, and React Native snippets without server secrets", async () => {
    adminRequestMock.mockResolvedValue({ data: revision(activeID, activeDocument(), "active", 1), etag: '"active-etag"' });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    const clipboardWrite = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    const { container } = render(<QueryClientProvider client={queryClient}><FeatureWorkspacePage /></QueryClientProvider>);

    expect(await screen.findByRole("heading", { name: "Use weekly_summary from each supported client." })).toBeInTheDocument();
    const cards = container.querySelectorAll("[data-client-surface]");
    expect([...cards].map((card) => card.getAttribute("data-client-surface"))).toEqual(["ios", "android", "web", "react_native"]);
    const ios = container.querySelector('[data-client-surface="ios"]') as HTMLElement;
    const android = container.querySelector('[data-client-surface="android"]') as HTMLElement;
    const web = container.querySelector('[data-client-surface="web"]') as HTMLElement;
    const reactNative = container.querySelector('[data-client-surface="react_native"]') as HTMLElement;
    expect(ios).toHaveTextContent('applicationID: "app_01J00000000000000000000000"');
    expect(ios).toHaveTextContent('environment: "production"');
    expect(ios).toHaveTextContent("attestationProvider: appAttest");
    expect(android).toHaveTextContent("cloudProjectNumber = 123456L");
    expect(web).toHaveTextContent('createTurnstileProvider');
    expect(web).toHaveTextContent("latchway.fetch" + '("/v1/responses"');
    expect(web).toHaveTextContent('latchwayFeature: "weekly_summary"');
    expect(reactNative).toHaveTextContent('playIntegrityCloudProjectNumber: "654321"');
    expect(reactNative).toHaveTextContent('rootKeychainAccessGroup: "YOUR_FULLY_RESOLVED_PRIVATE_APP_ID_GROUP"');
    expect(container).not.toHaveTextContent("turnstile_private_do_not_render");
    expect(container).not.toHaveTextContent("provider_super_secret");

    await user.click(within(web).getByRole("button", { name: "Copy Web snippet" }));
    expect(clipboardWrite).toHaveBeenCalledOnce();
    expect(clipboardWrite.mock.calls[0]?.[0]).toContain('applicationID: "app_01J00000000000000000000000"');
    expect(clipboardWrite.mock.calls[0]?.[0]).not.toMatch(/turnstile_private_do_not_render|provider_super_secret/);
    expect(await within(web).findByRole("status")).toHaveTextContent("Web snippet copied.");
  });

  it("fails snippet personalization closed instead of copying malformed or credential-bearing facts", () => {
    const snippets = buildFeatureClientSetupSnippets({
      applicationID: "app_81J00000000000000000000000",
      document: activeDocument(),
      environmentSlug: "production\"; const stolen = secret",
      featureID: "weekly_summary",
      gatewayURL: "https://operator:gateway-secret@example.test/"
    });
    const rendered = snippets.map((snippet) => `${snippet.status}\n${snippet.code}`).join("\n");
    expect(rendered).not.toMatch(/app_81J00000000000000000000000|gateway-secret|const stolen/);
    expect(rendered).toContain("YOUR_LATCHWAY_APPLICATION_ID");
    expect(rendered).toContain("YOUR_ENVIRONMENT_SLUG");
    expect(rendered).toContain("YOUR_LATCHWAY_GATEWAY");
    expect(snippets.every((snippet) => !snippet.available)).toBe(true);
  });

  it("never presents a Responses endpoint as usable for an unresolved opaque feature", () => {
    const document = activeDocument();
    const feature = ((document.spec as JSONRecord).features as JSONRecord[])[0];
    if (!feature) throw new Error("fixture feature missing");
    feature.protocol = "opaque_http";
    feature.opaqueHttp = {
      allowedMethods: ["GET"],
      maxBodyBytes: 0,
      pathTemplates: ["/widgets/{widget_id}"]
    };

    const snippets = buildFeatureClientSetupSnippets({
      applicationID: workspace.application.id,
      document,
      environmentSlug: workspace.environment.slug,
      featureID: "weekly_summary",
      gatewayURL: "https://gateway.example.test"
    });
    const rendered = snippets.map((snippet) => `${snippet.status}\n${snippet.code}`).join("\n");

    expect(snippets.every((snippet) => !snippet.available)).toBe(true);
    expect(rendered).toContain("a concrete capture-free allowed opaque proxy path");
    expect(rendered).toContain('/proxy/weekly_summary/YOUR_ALLOWED_RELATIVE_PATH');
    expect(rendered).toContain('method: "GET"');
    expect(rendered).not.toContain("/v1/responses");
  });

  it("derives a usable opaque request only from an exact capture-free configured path", () => {
    const document = activeDocument();
    const feature = ((document.spec as JSONRecord).features as JSONRecord[])[0];
    if (!feature) throw new Error("fixture feature missing");
    feature.protocol = "opaque_http";
    feature.opaqueHttp = {
      allowedMethods: ["GET"],
      maxBodyBytes: 0,
      pathTemplates: ["/widgets/status"]
    };

    const snippets = buildFeatureClientSetupSnippets({
      applicationID: workspace.application.id,
      document,
      environmentSlug: workspace.environment.slug,
      featureID: "weekly_summary",
      gatewayURL: "https://gateway.example.test"
    });
    const rendered = snippets.map((snippet) => snippet.code).join("\n");

    expect(snippets.every((snippet) => snippet.available)).toBe(true);
    expect(rendered).toContain('/proxy/weekly_summary/widgets/status');
    expect(rendered).toContain('method: "GET"');
    expect(rendered).not.toContain("YOUR_ALLOWED_RELATIVE_PATH");
    expect(rendered).not.toContain("/v1/responses");
  });
});

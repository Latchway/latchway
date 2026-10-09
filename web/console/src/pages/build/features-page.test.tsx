import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/admin")>()),
  adminRequest: adminRequestMock
}));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => ({ mutationAllowed: true })
}));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
import type { JSONRecord } from "../configuration-slice";
import { buildFeatureClientSetupSnippets } from "./feature-model";
import { FeaturesPage } from "./features-page";

const instant = "2026-08-29T00:00:00Z";
const activeID = "rev_0123456789abcdef";
const draftID = "rev_1123456789abcdef";
const applicationID = "app_01J00000000000000000000000";
const environmentID = "env_0123456789abcdef";
const scope = { application: "active" as "active" | "disabled", environment: "active" as "active" | "disabled" };
const searchLog: WorkspaceSearch[] = [];

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

function revision(id: string, document: JSONRecord, state: string, version: number) {
  return { activated_at: state === "active" ? instant : undefined, created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: environmentID, id, state, version };
}

type Options = { body?: unknown; etag?: string; method?: string } | undefined;

/** One active revision and, once created, one working draft. */
function server() {
  const active = activeDocument();
  const state: { draft?: { document: JSONRecord; etag: string } } = {};
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    const method = options?.method ?? "GET";
    if (path === `/admin/v1/environments/${environmentID}/config` && method === "GET") return Promise.resolve({ data: revision(activeID, active, "active", 1), etag: '"active-etag"' });
    if (path.startsWith(`/admin/v1/environments/${environmentID}/config-revisions?`)) return Promise.resolve({ data: { items: [state.draft ? revision(draftID, state.draft.document, "valid", 2) : revision(activeID, active, "active", 1)], page: { has_more: false } } });
    if (path === `/admin/v1/environments/${environmentID}/config-revisions` && method === "POST") {
      state.draft = { document: active, etag: '"draft-etag-1"' };
      return Promise.resolve({ data: revision(draftID, active, "draft", 2), etag: state.draft.etag });
    }
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "GET" && state.draft) return Promise.resolve({ data: revision(draftID, state.draft.document, "valid", 2), etag: state.draft.etag });
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "PATCH" && state.draft) {
      state.draft = { document: options?.body as JSONRecord, etag: '"draft-etag-2"' };
      return Promise.resolve({ data: revision(draftID, state.draft.document, "draft", 2), etag: state.draft.etag });
    }
    if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
    if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [{ operation: "add", path: "/spec/features/1" }], from_revision_id: activeID, to_revision_id: draftID, warnings: [] } });
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
  return state;
}

function workspaceValue(search: WorkspaceSearch, updateSearch: WorkspaceContextValue["updateSearch"]): WorkspaceContextValue {
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Habitify", id: applicationID, organization_id: organization.id, slug: "habitify", status: scope.application };
  const environment = { active_revision_id: activeID, application_id: applicationID, created_at: instant, display_name: "Production", id: environmentID, kind: "production" as const, slug: "production", status: scope.environment };
  return { application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch };
}

function Harness({ initial }: { initial: WorkspaceSearch }) {
  const [search, setSearch] = useState<WorkspaceSearch>(initial);
  const updateSearch: WorkspaceContextValue["updateSearch"] = (patch) => {
    searchLog.push(patch as WorkspaceSearch);
    setSearch((current) => ({ ...current, ...patch }));
  };
  return <WorkspaceContext.Provider value={workspaceValue(search, updateSearch)}><FeaturesPage /></WorkspaceContext.Provider>;
}

function renderPage(initial: WorkspaceSearch = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><Harness initial={initial} /></QueryClientProvider>);
}

beforeEach(() => {
  adminRequestMock.mockReset();
  searchLog.length = 0;
  scope.application = "active";
  scope.environment = "active";
});

describe("Features", () => {
  it("saves a new feature into the draft, preserving the rest of the document, and never publishes", async () => {
    const user = userEvent.setup();
    const state = server();
    renderPage();

    expect(await screen.findByText("weekly_summary")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "New Feature" }));
    const drawer = screen.getByRole("complementary", { name: "New feature" });
    await user.type(within(drawer).getByLabelText("Feature ID"), "habit_assistant");
    await user.selectOptions(within(drawer).getByLabelText("First-choice model"), "fast");
    await user.selectOptions(within(drawer).getByLabelText("Backup model"), "reliable");
    await user.selectOptions(within(drawer).getByLabelText("Who can call it"), "premium");
    await user.selectOptions(within(drawer).getByLabelText("Limit plan"), "free");
    await user.selectOptions(within(drawer).getByLabelText("App verification"), "native");
    await user.click(within(drawer).getByRole("button", { name: "Save to Draft" }));

    expect(await screen.findByRole("tab", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "habit_assistant" })).toBeInTheDocument();
    expect(searchLog.at(-1)).toEqual({ feature: "habit_assistant", tab: undefined });
    const saved = state.draft?.document as JSONRecord;
    expect(saved.metadata).toEqual(activeDocument().metadata);
    const features = (saved.spec as JSONRecord).features as JSONRecord[];
    expect(features).toHaveLength(2);
    expect(features[1]).toMatchObject({
      access: { expression: "principal.authenticated && principal.claims.plan == 'premium'" },
      attestationPolicy: "native",
      id: "habit_assistant",
      limitPlan: { expression: "'free'" },
      routes: [{ id: "primary", model: "fast", priority: 10 }, { id: "fallback", model: "reliable", priority: 20 }]
    });
    expect(adminRequestMock.mock.calls.some(([path]) => String(path).endsWith("/activate"))).toBe(false);
    await waitFor(() => expect(screen.getByText("New")).toBeInTheDocument());
  });

  it("refuses a duplicate feature ID locally", async () => {
    const user = userEvent.setup();
    server();
    renderPage();
    await screen.findByText("weekly_summary");
    await user.click(screen.getByRole("button", { name: "New Feature" }));
    await user.type(screen.getByLabelText("Feature ID"), "weekly_summary");
    expect(screen.getByText("A feature named weekly_summary already exists.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save to Draft" }));
    expect(adminRequestMock.mock.calls.some(([, , options]) => (options as Options)?.method)).toBe(false);
  });

  it("keeps a disabled scope readable without offering changes", async () => {
    scope.environment = "disabled";
    server();
    renderPage();
    expect(await screen.findByText("weekly_summary")).toBeInTheDocument();
    expect(screen.getByText("Selected scope is disabled").closest("[role=status]")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New Feature" })).not.toBeInTheDocument();
  });

  it("restores a feature page and its tab from the URL, and refuses an unknown feature without opening another", async () => {
    const user = userEvent.setup();
    server();
    const first = renderPage({ feature: "weekly_summary", tab: "routing" });
    expect(await screen.findByRole("tab", { name: "Routing" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("heading", { level: 1, name: "weekly_summary" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Features" }));
    expect(searchLog.at(-1)).toEqual({ feature: undefined, tab: undefined });
    expect(await screen.findByRole("heading", { level: 1, name: "Features" })).toBeInTheDocument();
    first.unmount();

    renderPage({ feature: "missing_feature" });
    expect(await screen.findByText("Feature not found")).toBeInTheDocument();
    expect(screen.queryByText("weekly_summary")).not.toBeInTheDocument();
  });

  it("renders personalized copyable client snippets without server secrets", async () => {
    const user = userEvent.setup();
    server();
    const clipboardWrite = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    const { container } = renderPage({ feature: "weekly_summary", tab: "setup" });

    await screen.findByRole("heading", { level: 1, name: "weekly_summary" });
    await waitFor(() => expect(container.querySelectorAll("[data-client-surface]")).toHaveLength(4));
    expect([...container.querySelectorAll("[data-client-surface]")].map((card) => card.getAttribute("data-client-surface"))).toEqual(["ios", "android", "web", "react_native"]);
    const ios = container.querySelector('[data-client-surface="ios"]') as HTMLElement;
    const android = container.querySelector('[data-client-surface="android"]') as HTMLElement;
    const web = container.querySelector('[data-client-surface="web"]') as HTMLElement;
    const reactNative = container.querySelector('[data-client-surface="react_native"]') as HTMLElement;
    expect(ios).toHaveTextContent(`applicationID: "${applicationID}"`);
    expect(ios).toHaveTextContent('environment: "production"');
    expect(ios).toHaveTextContent("attestationProvider: appAttest");
    expect(android).toHaveTextContent("cloudProjectNumber = 123456L");
    expect(web).toHaveTextContent("createTurnstileProvider");
    expect(web).toHaveTextContent('latchwayFeature: "weekly_summary"');
    expect(reactNative).toHaveTextContent('playIntegrityCloudProjectNumber: "654321"');
    expect(container).not.toHaveTextContent("turnstile_private_do_not_render");
    expect(container).not.toHaveTextContent("provider_super_secret");

    await user.click(screen.getByRole("button", { name: "Copy Web snippet" }));
    expect(clipboardWrite).toHaveBeenCalledOnce();
    expect(clipboardWrite.mock.calls[0]?.[0]).toContain(`applicationID: "${applicationID}"`);
    expect(clipboardWrite.mock.calls[0]?.[0]).not.toMatch(/turnstile_private_do_not_render|provider_super_secret/);
  });
});

describe("client setup snippets", () => {
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
      applicationID: applicationID,
      document,
      environmentSlug: "production",
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
      applicationID: applicationID,
      document,
      environmentSlug: "production",
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

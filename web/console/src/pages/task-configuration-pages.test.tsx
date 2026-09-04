import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, capabilities, compatibility, runDevelopmentSampleMock } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  capabilities: ["activate_configuration", "run_self_tests"],
  compatibility: { mutationAllowed: true },
  runDevelopmentSampleMock: vi.fn()
}));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock,
  runDevelopmentSample: runDevelopmentSampleMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities, organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => compatibility
}));

const workspace = {
  application: { created_at: "2026-08-29T00:00:00Z", display_name: "Habitify", id: "app_0123456789abcdef", organization_id: "org_0123456789abcdef", slug: "habitify", status: "active" as const },
  applications: [],
  environment: { active_revision_id: "rev_0123456789abcdef", application_id: "app_0123456789abcdef", created_at: "2026-08-29T00:00:00Z", display_name: "Development", id: "env_0123456789abcdef", kind: "development" as const, slug: "development", status: "active" as const },
  environments: [], invalidApplication: false, invalidEnvironment: false, isLoading: false,
  search: {}, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: vi.fn()
};
const initialApplicationID = workspace.application.id;
const initialEnvironmentID = workspace.environment.id;

vi.mock("../app/workspace-context-value", () => ({ useOptionalWorkspace: () => workspace }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, to }: { children: React.ReactNode; to: string }) => <a href={to}>{children}</a>
}));

import { ClientAccessWorkspacePage, ConnectionWorkspacePage, UsagePlanWorkspacePage } from "./task-configuration-pages";

const instant = "2026-08-29T00:00:00Z";
const providerSecretMetadata = {
  algorithm: "AES-256-GCM",
  created_at: instant,
  environment_id: workspace.environment.id,
  id: "sec_0123456789abcdef",
  master_key_id: "primary",
  name: "provider_api_key",
  version: 1
};
const turnstileSecretMetadata = {
  ...providerSecretMetadata,
  id: "sec_1123456789abcdef",
  name: "turnstile_secret"
};
const playSecretMetadata = {
  ...providerSecretMetadata,
  id: "sec_2123456789abcdef",
  name: "play_integrity_service_account"
};
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
  capabilities.splice(0, capabilities.length, "activate_configuration", "run_self_tests");
  compatibility.mutationAllowed = true;
  workspace.application.id = initialApplicationID;
  workspace.environment.application_id = initialApplicationID;
  workspace.environment.id = initialEnvironmentID;
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
    expect(screen.getByLabelText("Provider credential")).toBeDisabled();
    expect(screen.getByText("Secret management required")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run and verify development sample" }));
    expect(await screen.findByText(/Observed/)).toHaveTextContent("req_0123456789abcdef");
    expect(runDevelopmentSampleMock).toHaveBeenCalledOnce();
    expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/requests/req_0123456789abcdef", expect.anything());
  });

  it("preserves connection reads but blocks task and synthetic-request mutations in global safe mode", async () => {
    compatibility.mutationAllowed = false;
    adminRequestMock.mockImplementation((path: string) => {
      if (path.endsWith("/config")) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      throw new Error(`Unexpected request: ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><ConnectionWorkspacePage /></QueryClientProvider>);

    expect(await screen.findByRole("heading", { name: "Connections" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run and verify development sample" })).toBeDisabled();
    const review = screen.getByRole("button", { name: "Review connection change" });
    expect(review).toBeDisabled();
    fireEvent.submit(review.closest("form") as HTMLFormElement);
    fireEvent.click(screen.getByRole("button", { name: "Run and verify development sample" }));
    expect(runDevelopmentSampleMock).not.toHaveBeenCalled();
    expect(adminRequestMock.mock.calls.some(([, , options]) => options?.method)).toBe(false);
  });

  it("reuses a successfully created credential after downstream draft failure", async () => {
    capabilities.push("manage_secrets");
    let secretReads = 0;
    let draftAttempts = 0;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        secretReads += 1;
        return Promise.resolve({ data: { items: secretReads === 1 ? [] : [providerSecretMetadata], page: { has_more: false } } });
      }
      if (path === "/admin/v1/secrets" && options?.method === "POST") return Promise.resolve({ data: providerSecretMetadata });
      if (path.endsWith("/config-revisions") && options?.method === "POST") {
        draftAttempts += 1;
        return Promise.reject(new Error("draft unavailable"));
      }
      throw new Error(`Unexpected request: ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={queryClient}><ConnectionWorkspacePage /></QueryClientProvider>);

    await screen.findByRole("heading", { name: "Connections" });
    const credential = screen.getByLabelText("Provider credential");
    await user.type(credential, "one-time-provider-value");
    await user.click(screen.getByRole("button", { name: "Review connection change" }));

    expect(await screen.findByText("Credential stored")).toBeInTheDocument();
    expect(credential).toHaveValue("");
    expect(screen.getByLabelText("Credential operation")).toHaveValue("use_existing");
    await waitFor(() => expect(draftAttempts).toBe(1));

    await user.click(screen.getByRole("button", { name: "Review connection change" }));
    await waitFor(() => expect(draftAttempts).toBe(2));
    expect(adminRequestMock.mock.calls.filter(([path, , options]) => path === "/admin/v1/secrets" && options?.method === "POST")).toHaveLength(1);
    expect(secretReads).toBe(2);
  });

  it("requires explicit use-existing confirmation after an indeterminate create response", async () => {
    capabilities.push("manage_secrets");
    let secretReads = 0;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        secretReads += 1;
        return Promise.resolve({ data: { items: secretReads === 1 ? [] : [providerSecretMetadata], page: { has_more: false } } });
      }
      if (path === "/admin/v1/secrets" && options?.method === "POST") return Promise.reject(new Error("response lost"));
      throw new Error(`Unexpected request: ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={queryClient}><ConnectionWorkspacePage /></QueryClientProvider>);

    await screen.findByRole("heading", { name: "Connections" });
    const credential = screen.getByLabelText("Provider credential");
    await user.type(credential, "indeterminate-provider-value");
    await user.click(screen.getByRole("button", { name: "Review connection change" }));

    expect(await screen.findByText("Credential metadata requires confirmation")).toBeInTheDocument();
    expect(screen.getByText(/did not read or infer its value/)).toBeInTheDocument();
    expect(credential).toHaveValue("");
    expect(screen.getByLabelText("Credential operation")).toHaveValue("create");
    expect(adminRequestMock.mock.calls.some(([path]) => String(path).endsWith("/config-revisions"))).toBe(false);
    await user.click(screen.getByRole("button", { name: "Use this existing named secret on next review" }));
    expect(screen.getByLabelText("Credential operation")).toHaveValue("use_existing");
  });

  it("clears credential plaintext before early local validation rejects the connection", async () => {
    capabilities.push("manage_secrets");
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      throw new Error(`Unexpected request: ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><ConnectionWorkspacePage /></QueryClientProvider>);

    await screen.findByRole("heading", { name: "Connections" });
    const credential = screen.getByLabelText("Provider credential");
    fireEvent.change(credential, { target: { value: "must-not-survive-validation" } });
    fireEvent.change(screen.getByLabelText("Base URL"), { target: { value: "http://provider.example.test/v1" } });
    fireEvent.submit(screen.getByRole("button", { name: "Review connection change" }).closest("form") as HTMLFormElement);

    expect(credential).toHaveValue("");
    expect(await screen.findByRole("alert")).toHaveTextContent("HTTPS");
    expect(adminRequestMock.mock.calls.some(([path]) => String(path).startsWith("/admin/v1/secrets"))).toBe(false);
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

describe("platform-oriented client access", () => {
  async function chooseTurnstile(user: ReturnType<typeof userEvent.setup>): Promise<HTMLInputElement> {
    await user.click(screen.getByRole("button", { name: "Web" }));
    await user.selectOptions(screen.getByLabelText("Protection provider"), "turnstile");
    await user.type(screen.getByLabelText("Exact customer web-app origin"), "https://app.example.test");
    return screen.getByLabelText("New Turnstile secret (write-only)") as HTMLInputElement;
  }

  async function choosePlayServiceAccount(user: ReturnType<typeof userEvent.setup>): Promise<HTMLInputElement> {
    await user.click(screen.getByRole("button", { name: "Android" }));
    await user.type(screen.getByLabelText("Package name"), "dev.latchway.android");
    await user.type(screen.getByLabelText("Cloud project number"), "123456789");
    await user.type(screen.getByLabelText("Signing certificate SHA-256 (base64url)"), "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
    await user.type(screen.getByLabelText("Exact version code"), "1");
    await user.selectOptions(screen.getByLabelText("Server credential source"), "service_account");
    return screen.getByLabelText("New service-account JSON (write-only)") as HTMLInputElement;
  }

  it("shows separate readiness, test, and documentation cards and exposes both exact React Native runtimes", async () => {
    const platformDocument = {
      apiVersion: "latchway.dev/v1alpha1",
      kind: "EnvironmentConfig",
      metadata: { application: "habitify", environment: "development", organization: "example" },
      spec: {
        attestationPolicies: [{
          id: "clients",
          platforms: {
            android: { mode: "required", provider: "play_integrity", playIntegrity: {} },
            ios: { appAttest: {}, mode: "required", provider: "app_attest" },
            react_native_android: { mode: "required", provider: "play_integrity", playIntegrity: {} },
            react_native_ios: { appAttest: {}, mode: "required", provider: "app_attest" },
            web: { firebaseAppCheck: {}, mode: "required", provider: "firebase_app_check" }
          }
        }],
        componentDefinitions: [
          { allowedFeatures: ["habit-assistant"], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: "ios_main", kind: "main_app", platform: "ios" },
          { allowedFeatures: ["habit-assistant"], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: "android_main", kind: "android_app", platform: "android" },
          { allowedFeatures: ["habit-assistant"], attestation: { provider: "firebase_app_check", strategy: "direct" }, familyRole: "root", id: "web_main", kind: "browser", platform: "web" },
          { allowedFeatures: ["habit-assistant"], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: "rn_ios_main", kind: "main_app", platform: "react_native_ios" },
          { allowedFeatures: ["habit-assistant"], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: "rn_android_main", kind: "android_app", platform: "react_native_android" }
        ],
        features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "clients", id: "habit-assistant", protocol: "openai_responses", routes: [] }],
        identityProviders: [{ id: "firebase", projectId: "habitify-dev", type: "firebase" }]
      }
    };
    adminRequestMock.mockImplementation((path: string) => {
      if (path.endsWith("/config")) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: platformDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      throw new Error(`Unexpected request: ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    const { container } = render(<QueryClientProvider client={queryClient}><ClientAccessWorkspacePage /></QueryClientProvider>);

    expect(await screen.findByRole("heading", { name: "Platform readiness" })).toBeInTheDocument();
    const cards = container.querySelectorAll("[data-platform]");
    expect([...cards].map((card) => card.getAttribute("data-platform"))).toEqual(["ios", "android", "web", "react_native_ios", "react_native_android"]);
    for (const card of cards) {
      expect(within(card as HTMLElement).getByText("Configuration ready")).toBeInTheDocument();
      expect(within(card as HTMLElement).getByRole("link", { name: "Inspect requests" })).toBeInTheDocument();
      expect(within(card as HTMLElement).getByRole("link", { name: "Client documentation" })).toHaveAttribute("href", expect.stringMatching(/^https:\/\/docs\.latchway\.dev\/clients\//));
    }

    await user.click(screen.getByRole("button", { name: "React Native iOS" }));
    expect(screen.getByRole("group", { name: "Client platform" })).toHaveTextContent("React Native Android");
    expect(screen.getAllByText("react_native_ios").length).toBeGreaterThan(0);
    expect(screen.getByRole("group", { name: /Apple App Attest · React Native iOS/ })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Web" }));
    await user.selectOptions(screen.getByLabelText("Protection provider"), "turnstile");
    expect(screen.getByLabelText("Expected widget action")).toHaveValue("latchway_session");
    expect(screen.getByLabelText("New Turnstile secret (write-only)")).toHaveAttribute("type", "password");
    expect(screen.getByLabelText("New Turnstile secret (write-only)")).toBeDisabled();
    expect(screen.getByText("Secret management required")).toBeInTheDocument();
    expect(screen.queryByLabelText("Firebase web app ID")).not.toBeInTheDocument();
  });

  it("reuses a created Turnstile secret after downstream draft failure without another plaintext POST", async () => {
    capabilities.push("manage_secrets");
    let secretStored = false;
    let draftAttempts = 0;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) return Promise.resolve({ data: { items: secretStored ? [turnstileSecretMetadata] : [], page: { has_more: false } } });
      if (path === "/admin/v1/secrets" && options?.method === "POST") { secretStored = true; return Promise.resolve({ data: turnstileSecretMetadata }); }
      if (path.endsWith("/config-revisions") && options?.method === "POST") { draftAttempts += 1; return Promise.reject(new Error("draft unavailable")); }
      throw new Error(`Unexpected request: ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={queryClient}><ClientAccessWorkspacePage /></QueryClientProvider>);

    await screen.findByRole("heading", { name: "Platform readiness" });
    const credential = await chooseTurnstile(user);
    await user.type(credential, "one-time-turnstile-value");
    await user.click(screen.getByRole("button", { name: "Review client-access change" }));

    expect(await screen.findByText("Verification secret stored")).toBeInTheDocument();
    expect(credential).toHaveValue("");
    expect(screen.getByLabelText("Turnstile credential operation")).toHaveValue("use_existing");
    await waitFor(() => expect(draftAttempts).toBe(1));

    await user.click(screen.getByRole("button", { name: "Review client-access change" }));
    await waitFor(() => expect(draftAttempts).toBe(2));
    expect(adminRequestMock.mock.calls.filter(([path, , options]) => path === "/admin/v1/secrets" && options?.method === "POST")).toHaveLength(1);
  });

  it("requires explicit use-existing confirmation after an indeterminate Play credential create", async () => {
    capabilities.push("manage_secrets");
    let secretReads = 0;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        secretReads += 1;
        return Promise.resolve({ data: { items: secretReads === 1 ? [] : [playSecretMetadata], page: { has_more: false } } });
      }
      if (path === "/admin/v1/secrets" && options?.method === "POST") return Promise.reject(new Error("response lost"));
      throw new Error(`Unexpected request: ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={queryClient}><ClientAccessWorkspacePage /></QueryClientProvider>);

    await screen.findByRole("heading", { name: "Platform readiness" });
    const credential = await choosePlayServiceAccount(user);
    await user.type(credential, "indeterminate-play-value");
    await user.click(screen.getByRole("button", { name: "Review client-access change" }));

    expect(await screen.findByText("Verification credential metadata needs explicit confirmation")).toBeInTheDocument();
    expect(credential).toHaveValue("");
    expect(screen.getByLabelText("Play Integrity credential operation")).toHaveValue("create");
    expect(adminRequestMock.mock.calls.some(([path]) => String(path).endsWith("/config-revisions"))).toBe(false);
    await user.click(screen.getByRole("button", { name: "Use this existing named verification secret on next review" }));
    expect(screen.getByLabelText("Play Integrity credential operation")).toHaveValue("use_existing");
  });

  it("clears disabled Turnstile plaintext before the programmatic safe-mode guard returns", async () => {
    capabilities.push("manage_secrets");
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: workspace.environment.id, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      throw new Error(`Unexpected request: ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    const page = <QueryClientProvider client={queryClient}><ClientAccessWorkspacePage /></QueryClientProvider>;
    const { rerender } = render(page);

    await screen.findByRole("heading", { name: "Platform readiness" });
    const credential = await chooseTurnstile(user);
    await user.type(credential, "must-not-survive-safe-mode");
    compatibility.mutationAllowed = false;
    rerender(<QueryClientProvider client={queryClient}><ClientAccessWorkspacePage /></QueryClientProvider>);
    expect(credential).toBeDisabled();
    fireEvent.submit(screen.getByRole("button", { name: "Review client-access change" }).closest("form") as HTMLFormElement);

    expect(credential).toHaveValue("");
    expect(adminRequestMock.mock.calls.some(([, , options]) => options?.method)).toBe(false);
  });

  it("resets task-local client state when the selected application or environment changes", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      if (path.endsWith("/config")) {
        const environmentID = path.split("/").at(-2) ?? "";
        return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: activeDocument, environment_id: environmentID, id: "rev_0123456789abcdef", state: "active", version: 1 }, etag: '"active-etag"' });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    const page = <QueryClientProvider client={queryClient}><ClientAccessWorkspacePage /></QueryClientProvider>;
    const { rerender } = render(page);

    await screen.findByRole("heading", { name: "Platform readiness" });
    await user.click(screen.getByRole("button", { name: "Web" }));
    expect(screen.getByRole("button", { name: "Web" })).toHaveAttribute("aria-pressed", "true");

    workspace.application.id = "app_1123456789abcdef";
    workspace.environment.application_id = workspace.application.id;
    workspace.environment.id = "env_1123456789abcdef";
    rerender(<QueryClientProvider client={queryClient}><ClientAccessWorkspacePage /></QueryClientProvider>);

    await screen.findByRole("heading", { name: "Platform readiness" });
    await waitFor(() => expect(screen.getByRole("button", { name: "iOS" })).toHaveAttribute("aria-pressed", "true"));
    expect(screen.getByRole("button", { name: "Web" })).toHaveAttribute("aria-pressed", "false");
  });
});

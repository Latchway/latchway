import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdminRequestError } from "../api/auth";

const mocks = vi.hoisted(() => ({
  adminRequest: vi.fn(),
  capabilities: ["activate_configuration", "inspect_users", "manage_secrets", "run_self_tests"],
  compatibility: { mutationAllowed: true },
  workspace: {
    application: {
      created_at: "2026-09-01T00:00:00Z",
      display_name: "Latchway Mobile",
      id: "app_01J00000000000000000000000",
      organization_id: "org_01J00000000000000000000000",
      slug: "latchway-mobile",
      status: "active" as const
    },
    applications: [],
    environment: {
      active_revision_id: "rev_01J00000000000000000000000",
      application_id: "app_01J00000000000000000000000",
      created_at: "2026-09-01T00:00:00Z",
      display_name: "Development",
      id: "env_01J00000000000000000000000",
      kind: "development" as const,
      slug: "development",
      status: "active" as const
    },
    environments: [],
    invalidApplication: false,
    invalidEnvironment: false,
    isLoading: false,
    organization: {
      created_at: "2026-09-01T00:00:00Z",
      display_name: "Latchway",
      id: "org_01J00000000000000000000000",
      slug: "latchway"
    },
    search: {},
    selectApplication: vi.fn(),
    selectEnvironment: vi.fn(),
    updateSearch: vi.fn()
  }
}));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: mocks.adminRequest
}));
vi.mock("../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: {
    capabilities: mocks.capabilities,
    organization_id: "org_01J00000000000000000000000"
  } } })
}));
vi.mock("../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => mocks.compatibility
}));
vi.mock("../app/workspace-context-value", () => ({
  useOptionalWorkspace: () => mocks.workspace
}));

import { buildFirstRunTemplate, resumeSetupPageWorkspace, SetupWizardPage } from "./configuration-pages";
import {
  createValidateActivate,
  findOrCreateApplication,
  findOrCreateEnvironment
} from "./setup-wizard-api";

const configuration = JSON.parse(buildFirstRunTemplate({
  application: "latchway-mobile",
  environment: "development",
  environmentKind: "development",
  organization: "latchway",
  firebaseProject: "latchway-mobile",
  appIDPrefix: "PFK5S2E4H5",
  bundleID: "dev.latchway",
  bundleVersion: "1",
  appleDistribution: "development",
  packageName: "dev.latchway.android",
  androidVersionCode: 1,
  playIntegrityCredential: { type: "metadata" },
  platformScope: "react_native_both",
  cloudProject: 123456789,
  certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
  upstreamURL: "https://fixture.example.test/v1",
  physicalModel: "fixture-model",
  maximumFramingTokensPerRequest: 8,
  maximumFramingTokensPerMessage: 4,
  maximumContextTokens: 4096,
  authentication: { type: "bearer", secretName: "primary_api_key" },
  inputNanoUsdPerMillion: 0,
  outputNanoUsdPerMillion: 0,
  requestNanoUsd: 0,
  dailyInputTokenMaximum: 1000,
  dailyOutputTokenMaximum: 1000,
  dailyTotalTokenMaximum: 2000,
  perRequestInputTokenMaximum: 100
})) as unknown;

const activeConfigurationPath = "/admin/v1/environments/env_01J00000000000000000000000/config";

function activeRevision(document: unknown = configuration, version = 1) {
  return {
    activated_at: "2026-09-01T00:05:00Z",
    created_at: "2026-09-01T00:01:00Z",
    created_by: "adm_01J00000000000000000000000",
    document,
    environment_id: "env_01J00000000000000000000000",
    id: "rev_01J00000000000000000000000",
    state: "active",
    validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
    version
  };
}

const playSecretMetadata = {
  algorithm: "AES-256-GCM",
  created_at: "2026-09-01T00:02:00Z",
  environment_id: "env_01J00000000000000000000000",
  id: "sec_01J00000000000000000000000",
  master_key_id: "primary",
  name: "play_integrity_service_account",
  version: 1
};
const upstreamSecretMetadata = {
  ...playSecretMetadata,
  id: "sec_11J00000000000000000000000",
  name: "primary_api_key"
};

async function fillFirstRunPlayServiceAccount(value: string): Promise<HTMLInputElement> {
  fireEvent.change(await screen.findByLabelText(/^Firebase project ID/), { target: { value: "latchway-mobile" } });
  fireEvent.change(screen.getByLabelText(/^App ID prefix/), { target: { value: "PFK5S2E4H5" } });
  fireEvent.change(screen.getByLabelText(/^Bundle ID/), { target: { value: "dev.latchway" } });
  fireEvent.change(screen.getByLabelText(/^Allowed CFBundleVersion/), { target: { value: "1" } });
  fireEvent.change(screen.getByLabelText(/^Package name/), { target: { value: "dev.latchway.android" } });
  fireEvent.change(screen.getByLabelText(/^Cloud project number/), { target: { value: "123456789" } });
  fireEvent.change(screen.getByLabelText(/^Certificate SHA-256 digest/), { target: { value: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" } });
  fireEvent.change(screen.getByLabelText(/^Exact version code/), { target: { value: "1" } });
  fireEvent.change(screen.getByLabelText("Server credential source"), { target: { value: "service_account" } });
  const secret = await screen.findByLabelText("Google service-account JSON (write-only)") as HTMLInputElement;
  fireEvent.change(secret, { target: { value } });
  fireEvent.change(screen.getByLabelText("Authentication mode"), { target: { value: "none" } });
  fireEvent.change(screen.getByLabelText("Input price (nano-USD per million tokens)"), { target: { value: "0" } });
  fireEvent.change(screen.getByLabelText("Output price (nano-USD per million tokens)"), { target: { value: "0" } });
  return secret;
}

describe("resumable setup wizard", () => {
  beforeEach(() => {
    mocks.adminRequest.mockReset();
    mocks.compatibility.mutationAllowed = true;
    mocks.capabilities.splice(0, mocks.capabilities.length, "activate_configuration", "inspect_users", "manage_secrets", "run_self_tests");
  });

  it("resumes only an exact bounded first-run document", () => {
    expect(resumeSetupPageWorkspace({
      applicationID: mocks.workspace.application.id,
      applicationSlug: mocks.workspace.application.slug,
      document: configuration,
      environmentID: mocks.workspace.environment.id,
      environmentSlug: mocks.workspace.environment.slug
    })).toBeDefined();

    const custom = structuredClone(configuration) as { spec: { privacy?: { requestBodyLogging: boolean } } };
    custom.spec.privacy = { requestBodyLogging: false };
    expect(resumeSetupPageWorkspace({
      applicationID: mocks.workspace.application.id,
      applicationSlug: mocks.workspace.application.slug,
      document: custom,
      environmentID: mocks.workspace.environment.id,
      environmentSlug: mocks.workspace.environment.slug
    })).toBeUndefined();
  });

  it("blocks secret-requiring first-run selections before creating resources when manage_secrets is absent", async () => {
    mocks.capabilities.splice(mocks.capabilities.indexOf("manage_secrets"), 1);
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const create = await screen.findByRole("button", { name: "Create application and environment" });
    expect(create).toBeDisabled();
    expect(screen.getByText("Secret management required")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Authentication mode"), { target: { value: "none" } });
    await waitFor(() => expect(create).toBeEnabled());
    fireEvent.change(screen.getByLabelText("Server credential source"), { target: { value: "service_account" } });
    expect(create).toBeDisabled();
    expect(screen.getByLabelText("Google service-account JSON (write-only)")).toBeDisabled();
    expect(mocks.adminRequest.mock.calls.some(([path, , options]) => options?.method === "POST" || path === "/admin/v1/secrets")).toBe(false);
  });

  it("keeps the first-run wizard mutation-closed when global compatibility is unavailable", async () => {
    mocks.compatibility.mutationAllowed = false;
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(await screen.findByText("First-run setup inputs are unavailable until Console compatibility and configuration authority are restored.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create application and environment" })).not.toBeInTheDocument();
    expect(mocks.adminRequest.mock.calls.some(([, , options]) => options?.method)).toBe(false);
  });

  it("unmounts populated first-run Play plaintext when compatibility closes", async () => {
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const view = render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);
    await fillFirstRunPlayServiceAccount("temporary-play-service-account-json");
    expect(screen.getByLabelText("Google service-account JSON (write-only)")).toHaveValue("temporary-play-service-account-json");

    mocks.compatibility.mutationAllowed = false;
    view.rerender(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(screen.queryByLabelText("Google service-account JSON (write-only)")).not.toBeInTheDocument();
    expect(screen.getByText("First-run setup inputs are unavailable until Console compatibility and configuration authority are restored.")).toBeInTheDocument();
  });

  it("keeps resumed first-run reads available while disabling every workflow mutation in safe mode", async () => {
    mocks.compatibility.mutationAllowed = false;
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) {
        return { data: { items: [activeRevision()], page: { has_more: false } } };
      }
      if (path === activeConfigurationPath) return { data: activeRevision() };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{
        algorithm: "AES-256-GCM",
        created_at: "2026-09-01T00:02:00Z",
        environment_id: mocks.workspace.environment.id,
        id: "sec_01J00000000000000000000000",
        master_key_id: "primary",
        name: "primary_api_key",
        version: 1
      }], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/requests?")) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(await screen.findByText(/Resumed from server-owned revision/)).toBeInTheDocument();
    expect(await screen.findByText("Write-only credential input is removed until Console compatibility and secret-management authority are restored.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Secret value")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Validate and plan only" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Validate and activate with ETag" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run bounded upstream self-test" })).toBeDisabled();
    expect(mocks.adminRequest.mock.calls.some(([, , options]) => options?.method)).toBe(false);
  });

  it("unmounts populated resumed upstream plaintext when compatibility closes", async () => {
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [activeRevision()], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: activeRevision() };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/requests?")) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const view = render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);
    const secret = await screen.findByLabelText("Secret value");
    fireEvent.change(secret, { target: { value: "temporary-upstream-secret" } });
    expect(secret).toHaveValue("temporary-upstream-secret");

    mocks.compatibility.mutationAllowed = false;
    view.rerender(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(screen.queryByLabelText("Secret value")).not.toBeInTheDocument();
    expect(screen.getByText("Write-only credential input is removed until Console compatibility and secret-management authority are restored.")).toBeInTheDocument();
  });

  it("retains Play secret metadata after draft creation fails and retries without resending plaintext", async () => {
    let secretStored = false;
    let draftAttempts = 0;
    mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.includes("/config-revisions?page_size=1") && !options?.method) return { data: { items: [], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/applications?") && !options?.method) return { data: { items: [mocks.workspace.application], page: { has_more: false } } };
      if (path.endsWith("/environments") && !options?.method) return { data: { items: [mocks.workspace.environment] } };
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) return { data: { items: secretStored ? [playSecretMetadata] : [], page: { has_more: false } } };
      if (path === "/admin/v1/secrets" && options?.method === "POST") {
        secretStored = true;
        return { data: playSecretMetadata };
      }
      if (path.endsWith("/config-revisions") && options?.method === "POST") {
        draftAttempts += 1;
        throw new Error("draft unavailable");
      }
      throw new Error(`unexpected request ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const secretInput = await fillFirstRunPlayServiceAccount("one-time-play-json");
    fireEvent.submit(screen.getByRole("button", { name: "Create application and environment" }).closest("form") as HTMLFormElement);

    expect(await screen.findByRole("heading", { name: "Schema-backed full configuration document" })).toBeInTheDocument();
    expect(secretInput).toHaveValue("");
    const retry = screen.getByRole("button", { name: "Validate and plan only" });
    await waitFor(() => expect(retry).toBeEnabled());
    expect(draftAttempts).toBe(1);
    fireEvent.click(retry);
    await waitFor(() => expect(draftAttempts).toBe(2));
    expect(mocks.adminRequest.mock.calls.filter(([path, , options]) => path === "/admin/v1/secrets" && options?.method === "POST")).toHaveLength(1);
  });

  it("requires explicit Play metadata confirmation after an indeterminate create response", async () => {
    let secretReads = 0;
    mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.includes("/config-revisions?page_size=1") && !options?.method) return { data: { items: [], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/applications?") && !options?.method) return { data: { items: [mocks.workspace.application], page: { has_more: false } } };
      if (path.endsWith("/environments") && !options?.method) return { data: { items: [mocks.workspace.environment] } };
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        secretReads += 1;
        return { data: { items: secretReads === 1 ? [] : [playSecretMetadata], page: { has_more: false } } };
      }
      if (path === "/admin/v1/secrets" && options?.method === "POST") throw new AdminRequestError({
        code: "operation_indeterminate",
        detail: "response lost",
        operationId: "arq_00000000000000000000000000",
        requestId: "request_test_1234",
        retryable: true,
        status: 503,
        title: "Operation outcome unknown"
      });
      throw new Error(`unexpected request ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const secretInput = await fillFirstRunPlayServiceAccount("indeterminate-play-json");
    fireEvent.submit(screen.getByRole("button", { name: "Create application and environment" }).closest("form") as HTMLFormElement);

    expect(await screen.findByRole("heading", { name: "Confirm existing Play Integrity credential metadata" })).toBeInTheDocument();
    expect(secretInput).toHaveValue("");
    const validate = screen.getByRole("button", { name: "Validate and plan only" });
    expect(validate).toBeDisabled();
    expect(mocks.adminRequest.mock.calls.some(([path, , options]) => String(path).endsWith("/config-revisions") && options?.method === "POST")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Use this existing named Play secret" }));
    expect(validate).toBeEnabled();
    expect(screen.getByText(/no value was read or inferred/i)).toBeInTheDocument();
  });

  it("clears first-run Play plaintext before early template validation fails", async () => {
    mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.includes("/config-revisions?page_size=1") && !options?.method) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const secretInput = await fillFirstRunPlayServiceAccount("must-not-survive-template-validation");
    fireEvent.change(screen.getByLabelText("Upstream HTTPS base URL"), { target: { value: "http://provider.example.test/v1" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create application and environment" }).closest("form") as HTMLFormElement);

    expect(secretInput).toHaveValue("");
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(mocks.adminRequest.mock.calls.some(([path, , options]) => options?.method === "POST" || path === "/admin/v1/secrets")).toBe(false);
  });

  it("reconciles an indeterminate upstream create explicitly and reloads from exact metadata without another POST", async () => {
    let secretReads = 0;
    let reloadPhase = false;
    mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.includes("/config-revisions?page_size=1") && !options?.method) return { data: { items: [activeRevision()], page: { has_more: false } } };
      if (path === activeConfigurationPath && !options?.method) return { data: activeRevision() };
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        secretReads += 1;
        return { data: { items: reloadPhase || secretReads >= 3 ? [upstreamSecretMetadata] : [], page: { has_more: false } } };
      }
      if (path === "/admin/v1/secrets" && options?.method === "POST") throw new AdminRequestError({
        code: "operation_indeterminate",
        detail: "response lost",
        operationId: "arq_00000000000000000000000000",
        requestId: "request_test_1234",
        retryable: true,
        status: 503,
        title: "Operation outcome unknown"
      });
      throw new Error(`unexpected request ${options?.method ?? "GET"} ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const rendered = render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const credential = await screen.findByLabelText("Secret value") as HTMLInputElement;
    fireEvent.change(credential, { target: { value: "indeterminate-upstream-value" } });
    fireEvent.submit(screen.getByRole("button", { name: "Add credential" }).closest("form") as HTMLFormElement);

    expect(await screen.findByRole("heading", { name: "Confirm existing upstream credential metadata" })).toBeInTheDocument();
    expect(screen.getByText(/Preserve operation arq_00000000000000000000000000/)).toBeInTheDocument();
    expect(credential).toHaveValue("");
    expect(screen.getByLabelText("Upstream credential operation")).toHaveValue("create");
    expect(mocks.adminRequest.mock.calls.filter(([path, , options]) => path === "/admin/v1/secrets" && options?.method === "POST")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Use this existing named upstream secret on next review" }));
    expect(screen.getByLabelText("Upstream credential operation")).toHaveValue("use_existing");
    fireEvent.submit(screen.getByRole("button", { name: "Confirm existing credential" }).closest("form") as HTMLFormElement);
    expect(await screen.findByRole("button", { name: "Credential added" })).toBeDisabled();
    expect(mocks.adminRequest.mock.calls.filter(([path, , options]) => path === "/admin/v1/secrets" && options?.method === "POST")).toHaveLength(1);
    rendered.unmount();

    reloadPhase = true;
    const reloadedQueryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={reloadedQueryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(await screen.findByRole("button", { name: "Credential added" })).toBeDisabled();
    expect(screen.getByLabelText("Secret value")).toHaveValue("");
    expect(mocks.adminRequest.mock.calls.filter(([path, , options]) => path === "/admin/v1/secrets" && options?.method === "POST")).toHaveLength(1);
  });

  it("hydrates non-secret progress from the latest server revision and secret metadata", async () => {
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [{
        activated_at: "2026-09-01T00:05:00Z",
        created_at: "2026-09-01T00:01:00Z",
        created_by: "adm_01J00000000000000000000000",
        document: configuration,
        environment_id: "env_01J00000000000000000000000",
        id: "rev_01J00000000000000000000000",
        state: "active",
        validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
        version: 1
      }], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: activeRevision() };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{
        algorithm: "AES-256-GCM",
        created_at: "2026-09-01T00:02:00Z",
        environment_id: "env_01J00000000000000000000000",
        id: "sec_01J00000000000000000000000",
        master_key_id: "primary",
        name: "primary_api_key",
        version: 1
      }], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/requests?")) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(await screen.findByText(/Resumed from server-owned revision/)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Credential added" })).toBeDisabled();
    expect(screen.getByText(/Revision/).closest("p")).toHaveTextContent("active");
    expect(screen.getByLabelText("Secret value")).toHaveValue("");
    expect(screen.getByRole("link", { name: "Open AI connections" })).toHaveAttribute(
      "href",
      expect.stringMatching(/^\/upstreams(?:\?|$)/)
    );
    const snippet = container.querySelector("pre");
    expect(snippet).toHaveTextContent('import { createLatchwayClient } from "@latchway/react-native";');
    expect(snippet).toHaveTextContent("apple:");
    expect(snippet).toHaveTextContent('rootKeychainAccessGroup: "YOUR_FULLY_RESOLVED_PRIVATE_APP_ID_GROUP"');
    expect(snippet).toHaveTextContent('playIntegrityCloudProjectNumber: "123456789"');

    fireEvent.change(screen.getByLabelText("Full configuration JSON"), { target: { value: "{}" } });
    const beforeUnload = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(beforeUnload)).toBe(false);
  });

  it("completes verified sample progress only from matching durable request evidence", async () => {
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [{
        activated_at: "2026-09-01T00:05:00Z",
        created_at: "2026-09-01T00:01:00Z",
        created_by: "adm_01J00000000000000000000000",
        document: configuration,
        environment_id: "env_01J00000000000000000000000",
        id: "rev_01J00000000000000000000000",
        state: "active",
        validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
        version: 1
      }], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: activeRevision() };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{
        algorithm: "AES-256-GCM",
        created_at: "2026-09-01T00:02:00Z",
        environment_id: "env_01J00000000000000000000000",
        id: "sec_01J00000000000000000000000",
        master_key_id: "primary",
        name: "primary_api_key",
        version: 1
      }], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/requests?")) return { data: { items: [{
        attempts: [{ model: "fixture-model" }],
        completed_at: "2026-09-01T00:06:00Z",
        config_revision_id: "rev_01J00000000000000000000000",
        environment_id: "env_01J00000000000000000000000",
        feature: "assistant",
        id: "req_01J00000000000000000000000",
        protocol: "openai_responses",
        status: "succeeded"
      }], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const check = await screen.findByRole("button", { name: "Check durable client request" });
    await waitFor(() => expect(check).toBeEnabled());
    fireEvent.click(check);
    expect(await screen.findByText(/Verified durable request/)).toHaveTextContent("req_01J00000000000000000000000");
    expect(screen.getByText("Verified sample request").closest("li")).toHaveClass("wizard-progress__done");
    expect(mocks.adminRequest.mock.calls.find(([path]) => String(path).startsWith("/admin/v1/requests?"))?.[0]).toContain("environment_id=env_01J00000000000000000000000");
  });

  it("fails closed when request-list evidence does not match the configured protocol", async () => {
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [{
        activated_at: "2026-09-01T00:05:00Z",
        created_at: "2026-09-01T00:01:00Z",
        created_by: "adm_01J00000000000000000000000",
        document: configuration,
        environment_id: "env_01J00000000000000000000000",
        id: "rev_01J00000000000000000000000",
        state: "active",
        validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
        version: 1
      }], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: activeRevision() };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{ name: "primary_api_key" }], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/requests?")) return { data: { items: [{
        completed_at: "2026-09-01T00:06:00Z",
        config_revision_id: "rev_01J00000000000000000000000",
        environment_id: "env_01J00000000000000000000000",
        feature: "assistant",
        id: "req_01J00000000000000000000000",
        protocol: "openai_chat",
        status: "succeeded"
      }], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const check = await screen.findByRole("button", { name: "Check durable client request" });
    await waitFor(() => expect(check).toBeEnabled());
    expect(screen.getByText("Verified sample request").closest("li")).not.toHaveClass("wizard-progress__done");
    fireEvent.click(check);
    expect(await screen.findByRole("alert")).toHaveTextContent("Verified client request not observed");
    expect(screen.queryByText(/Verified durable request/)).not.toBeInTheDocument();
  });

  it("fails closed when durable request evidence belongs to another revision", async () => {
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [{
        activated_at: "2026-09-01T00:05:00Z",
        created_at: "2026-09-01T00:01:00Z",
        created_by: "adm_01J00000000000000000000000",
        document: configuration,
        environment_id: "env_01J00000000000000000000000",
        id: "rev_01J00000000000000000000000",
        state: "active",
        validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
        version: 2
      }], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: activeRevision(configuration, 2) };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{ name: "primary_api_key" }], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/requests?")) return { data: { items: [{
        attempts: [],
        completed_at: "2026-09-01T00:06:00Z",
        config_revision_id: "rev_11J00000000000000000000000",
        environment_id: "env_01J00000000000000000000000",
        feature: "assistant",
        id: "req_01J00000000000000000000000",
        protocol: "openai_responses",
        status: "succeeded"
      }], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const check = await screen.findByRole("button", { name: "Check durable client request" });
    await waitFor(() => expect(check).toBeEnabled());
    expect(screen.getByText("Verified sample request").closest("li")).not.toHaveClass("wizard-progress__done");
    fireEvent.click(check);
    expect(await screen.findByRole("alert")).toHaveTextContent("active revision rev_01J00000000000000000000000");
    expect(screen.queryByText(/Verified durable request/)).not.toBeInTheDocument();
  });

  it("fails closed when the active revision changes during request evidence inspection", async () => {
    let requestRead = false;
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [activeRevision()], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: requestRead
        ? { ...activeRevision(), id: "rev_11J00000000000000000000000" }
        : activeRevision() };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{ name: "primary_api_key" }], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/requests?")) {
        requestRead = true;
        return { data: { items: [], page: { has_more: false } } };
      }
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const check = await screen.findByRole("button", { name: "Check durable client request" });
    await waitFor(() => expect(check).toBeEnabled());
    fireEvent.click(check);
    expect(await screen.findByRole("alert")).toHaveTextContent("active configuration changed");
    expect(screen.queryByText(/Verified durable request/)).not.toBeInTheDocument();
  });

  it("keeps server-configuration progress incomplete before a valid revision is activated", async () => {
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [{
        created_at: "2026-09-01T00:01:00Z",
        created_by: "adm_01J00000000000000000000000",
        document: configuration,
        environment_id: "env_01J00000000000000000000000",
        id: "rev_01J00000000000000000000000",
        state: "valid",
        validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
        version: 1
      }], page: { has_more: false } } };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{ name: "primary_api_key" }], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    const revisionResult = await screen.findByText(/Revision/);
    expect(revisionResult.closest("p")).toHaveTextContent("valid");
    for (const label of ["Identity provider", "Attestation & components", "Upstream target", "Feature and route", "Limits", "SDK snippets"]) {
      expect(screen.getByText(label).closest("li")).not.toHaveClass("wizard-progress__done");
    }
    expect(screen.getByRole("button", { name: "Check durable client request" })).toBeDisabled();
    expect(mocks.adminRequest.mock.calls.some(([path]) => String(path).startsWith("/admin/v1/requests?"))).toBe(false);
  });

  it("renders an iOS snippet with required App Attest and root Keychain wiring", async () => {
    const iosConfiguration = JSON.parse(buildFirstRunTemplate({
      appIDPrefix: "TEAM1234",
      appleDistribution: "app_store",
      application: "latchway-mobile",
      authentication: { type: "none" },
      bundleID: "dev.latchway",
      bundleVersion: "1",
      dailyInputTokenMaximum: 1000,
      dailyOutputTokenMaximum: 1000,
      dailyTotalTokenMaximum: 2000,
      environment: "development",
      environmentKind: "development",
      firebaseProject: "latchway-mobile",
      inputNanoUsdPerMillion: 0,
      maximumContextTokens: 4096,
      maximumFramingTokensPerMessage: 4,
      maximumFramingTokensPerRequest: 8,
      organization: "latchway",
      outputNanoUsdPerMillion: 0,
      perRequestInputTokenMaximum: 100,
      physicalModel: "fixture-model",
      platformScope: "ios",
      requestNanoUsd: 0,
      upstreamURL: "https://fixture.example.test/v1"
    })) as unknown;
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [{
        activated_at: "2026-09-01T00:05:00Z",
        created_at: "2026-09-01T00:01:00Z",
        created_by: "adm_01J00000000000000000000000",
        document: iosConfiguration,
        environment_id: "env_01J00000000000000000000000",
        id: "rev_01J00000000000000000000000",
        state: "active",
        validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
        version: 1
      }], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: activeRevision(iosConfiguration) };
      if (path.startsWith("/admin/v1/requests?")) return { data: { items: [], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(await screen.findByRole("heading", { name: "iOS" })).toBeInTheDocument();
    const snippet = container.querySelector("pre");
    expect(snippet).toHaveTextContent("import Foundation");
    expect(snippet).toHaveTextContent("import LatchwayAppAttest");
    expect(snippet).toHaveTextContent("let appAttest = LatchwayAppAttestProvider(");
    expect(snippet).toHaveTextContent('let rootKeychainAccessGroup = "YOUR_FULLY_RESOLVED_PRIVATE_APP_ID_GROUP"');
    expect(snippet).toHaveTextContent("rootKeychainAccessGroup: rootKeychainAccessGroup");
    expect(snippet).toHaveTextContent("attestationProvider: appAttest");
  });

  it("keeps durable verification incomplete when request inspection is not authorized", async () => {
    mocks.capabilities.splice(mocks.capabilities.indexOf("inspect_users"), 1);
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [{
        activated_at: "2026-09-01T00:05:00Z",
        created_at: "2026-09-01T00:01:00Z",
        created_by: "adm_01J00000000000000000000000",
        document: configuration,
        environment_id: "env_01J00000000000000000000000",
        id: "rev_01J00000000000000000000000",
        state: "active",
        version: 1
      }], page: { has_more: false } } };
      if (path === activeConfigurationPath) return { data: activeRevision() };
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{ name: "primary_api_key" }], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(await screen.findByText("Request inspection unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check durable client request" })).toBeDisabled();
    expect(screen.getByText("Verified sample request").closest("li")).not.toHaveClass("wizard-progress__done");
    expect(mocks.adminRequest.mock.calls.some(([path]) => String(path).startsWith("/admin/v1/requests?"))).toBe(false);
  });

  it("reuses an exact application and environment instead of issuing duplicate POSTs", async () => {
    mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.startsWith("/admin/v1/applications?") && !options?.method) return { data: {
        items: [mocks.workspace.application], page: { has_more: false }
      } };
      if (path.endsWith("/environments") && !options?.method) return { data: { items: [mocks.workspace.environment] } };
      throw new Error(`unexpected mutation ${options?.method ?? "GET"} ${path}`);
    });

    const application = await findOrCreateApplication({
      displayName: "Latchway Mobile",
      organizationID: "org_01J00000000000000000000000",
      slug: "latchway-mobile"
    });
    const environment = await findOrCreateEnvironment({
      applicationID: application.id,
      displayName: "Development",
      kind: "development",
      slug: "development"
    });

    expect(application.id).toBe("app_01J00000000000000000000000");
    expect(environment.id).toBe("env_01J00000000000000000000000");
    expect(mocks.adminRequest.mock.calls.some((call) => call[2]?.method === "POST")).toBe(false);
  });

  it("accepts the canonical lifecycle fields returned for newly created resources", async () => {
    mocks.adminRequest.mockImplementation(async (path: string, schema: unknown, options?: { method?: string }) => {
      const parser = schema as { parse(input: unknown): unknown };
      if (path.startsWith("/admin/v1/applications?") && !options?.method) {
        return { data: { items: [], page: { has_more: false } } };
      }
      if (path === "/admin/v1/applications" && options?.method === "POST") {
        return { data: parser.parse({ ...mocks.workspace.application, disabled_at: null }) };
      }
      if (path.endsWith("/environments") && !options?.method) return { data: { items: [] } };
      if (path.endsWith("/environments") && options?.method === "POST") {
        return { data: parser.parse({ ...mocks.workspace.environment, disabled_at: null }) };
      }
      throw new Error(`unexpected request ${options?.method ?? "GET"} ${path}`);
    });

    const application = await findOrCreateApplication({
      displayName: "Latchway Mobile",
      organizationID: "org_01J00000000000000000000000",
      slug: "latchway-mobile"
    });
    const environment = await findOrCreateEnvironment({
      applicationID: application.id,
      displayName: "Development",
      kind: "development",
      slug: "development"
    });

    expect(application.status).toBe("active");
    expect(environment.status).toBe("active");
  });

  it("resumes an identical valid revision through validation and activation without creating a duplicate", async () => {
    const valid = {
      created_at: "2026-09-01T00:01:00Z",
      created_by: "adm_01J00000000000000000000000",
      document: configuration,
      environment_id: "env_01J00000000000000000000000",
      id: "rev_01J00000000000000000000000",
      state: "valid",
      validation: { checked_at: "2026-09-01T00:04:00Z", issues: [], valid: true },
      version: 1
    };
    mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.includes("/config-revisions?page_size=1")) return { data: { items: [valid], page: { has_more: false } } };
      if (path === `/admin/v1/config-revisions/${valid.id}`) return { data: valid, etag: '"revision-1"' };
      if (path.endsWith("/validate")) return { data: valid.validation };
      if (path.endsWith("/plan")) return { data: {
        changes: [], from_revision_id: valid.id, to_revision_id: valid.id, warnings: []
      } };
      if (path.endsWith("/activate")) return { data: { ...valid, activated_at: "2026-09-01T00:05:00Z", state: "active" } };
      throw new Error(`unexpected request ${options?.method ?? "GET"} ${path}`);
    });

    const result = await createValidateActivate({
      activate: true,
      document: JSON.parse(JSON.stringify(configuration)) as unknown,
      environmentID: "env_01J00000000000000000000000"
    });

    expect(result.revision.state).toBe("active");
    expect(mocks.adminRequest.mock.calls.some(([path, , options]) =>
      path === "/admin/v1/environments/env_01J00000000000000000000000/config-revisions" && options?.method === "POST"
    )).toBe(false);
    expect(mocks.adminRequest.mock.calls.some(([path, , options]) =>
      String(path).endsWith("/activate") && options?.etag === '"revision-1"'
    )).toBe(true);
  });
});

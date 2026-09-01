import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { buildNativeTemplate } from "./native-template";

const mocks = vi.hoisted(() => ({
  adminRequest: vi.fn(),
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
    capabilities: ["activate_configuration", "manage_secrets", "run_self_tests"],
    organization_id: "org_01J00000000000000000000000"
  } } })
}));
vi.mock("../app/workspace-context-value", () => ({
  useOptionalWorkspace: () => mocks.workspace
}));

import { SetupWizardPage } from "./configuration-pages";
import {
  createValidateActivate,
  findOrCreateApplication,
  findOrCreateEnvironment
} from "./setup-wizard-api";

const configuration = JSON.parse(buildNativeTemplate({
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
  clientSurface: "react_native",
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

describe("resumable setup wizard", () => {
  beforeEach(() => { mocks.adminRequest.mockReset(); });

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
      if (path.startsWith("/admin/v1/secrets?")) return { data: { items: [{
        algorithm: "AES-256-GCM",
        created_at: "2026-09-01T00:02:00Z",
        environment_id: "env_01J00000000000000000000000",
        id: "sec_01J00000000000000000000000",
        master_key_id: "primary",
        name: "primary_api_key",
        version: 1
      }], page: { has_more: false } } };
      throw new Error(`unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><SetupWizardPage /></QueryClientProvider>);

    expect(await screen.findByText(/Resumed from server-owned revision/)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Credential added" })).toBeDisabled();
    expect(screen.getByText(/Revision/).closest("p")).toHaveTextContent("active");
    expect(screen.getByLabelText("Secret value")).toHaveValue("");

    fireEvent.change(screen.getByLabelText("Full configuration JSON"), { target: { value: "{}" } });
    const beforeUnload = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(beforeUnload)).toBe(false);
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

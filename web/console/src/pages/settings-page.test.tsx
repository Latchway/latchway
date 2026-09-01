import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  evaluateSettingsCompatibility,
  requiredSettingsServerCapabilities
} from "./settings-compatibility";
import { SettingsPage } from "./settings-page";

const mocks = vi.hoisted(() => ({
  activate: vi.fn(),
  adminRequest: vi.fn(),
  dirty: vi.fn(),
  readFile: vi.fn(),
  session: {
    data: {
      mode: "configured",
      session: {
        capabilities: ["activate_configuration", "manage_owners"],
        organization_id: "org_0123456789abcdef"
      }
    }
  },
  stage: vi.fn(),
  workspace: {
    environment: {
      display_name: "Development",
      id: "env_0123456789abcdef",
      kind: "development",
      slug: "development",
      status: "active"
    }
  },
  yaml: vi.fn(() => "apiVersion: latchway.dev/v1alpha1\n")
}));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: mocks.adminRequest
}));
vi.mock("../api/session", () => ({ useConsoleSession: () => mocks.session }));
vi.mock("../app/workspace-context-value", () => ({ useOptionalWorkspace: () => mocks.workspace }));
vi.mock("../app/use-dirty-edit-protection", () => ({ useDirtyEditProtection: mocks.dirty }));
vi.mock("./configuration-transfer", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./configuration-transfer")>()),
  activateConfigurationImport: mocks.activate,
  readConfigurationFile: mocks.readFile,
  redactionSafeConfigurationYAML: mocks.yaml,
  stageConfigurationImport: mocks.stage
}));

const systemStatus = {
  contract_version: "1.0.0",
  database_schema_version: "27",
  protocol_versions: [1, 2],
  ready: true,
  role: "all" as const,
  server_capabilities: [...requiredSettingsServerCapabilities, "admin_event_stream"],
  server_version: "1.0.0"
};

const doctor = {
  facts: {
    retention: {
      admin_session_retention_hours: 168,
      job_history_retention_hours: 720,
      oldest_audit_at: "2026-08-29T00:00:00Z",
      oldest_request_at: "2026-08-30T00:00:00Z",
      oldest_usage_at: "2026-08-31T00:00:00Z",
      policy_mode: "fixed_operational_operator_tenant_data",
      runtime_instance_retention_hours: 24
    },
    runtime: {
      contract_version: "1.0.0",
      protocol_versions: [1, 2]
    }
  },
  generated_at: "2026-09-01T00:00:00Z"
};

const sessions = {
  items: [{
    administrator: { email: "owner@example.test", id: "adm_0123456789abcdef" },
    created_at: "2026-08-29T00:00:00Z",
    current: true,
    expires_at: "2026-09-02T00:00:00Z",
    id: "asn_0123456789abcdef",
    last_seen_at: "2026-09-01T00:00:00Z",
    status: "active"
  }],
  page: { has_more: false }
};

const stagedResult = {
  plan: {
    changes: [{ operation: "replace", path: "/spec/features/0", summary: "Feature routing changed." }],
    from_revision_id: "rev_0123456789abcdef",
    to_revision_id: "rev_1123456789abcdef",
    warnings: []
  },
  report: {
    checked_at: "2026-09-01T00:00:00Z",
    issues: [],
    valid: true
  },
  revision: {
    created_at: "2026-09-01T00:00:00Z",
    created_by: "adm_0123456789abcdef",
    document: { apiVersion: "latchway.dev/v1alpha1" },
    environment_id: "env_0123456789abcdef",
    id: "rev_1123456789abcdef",
    state: "valid",
    version: 2
  }
};

beforeEach(() => {
  mocks.activate.mockReset();
  mocks.adminRequest.mockReset();
  mocks.dirty.mockReset();
  mocks.readFile.mockReset();
  mocks.stage.mockReset();
  mocks.yaml.mockClear();
  mocks.session.data.session.capabilities = ["activate_configuration", "manage_owners"];
  mocks.workspace.environment.status = "active";
  mocks.adminRequest.mockImplementation(async (path: string) => {
    if (path === "/admin/v1/system") return { data: systemStatus };
    if (path === "/admin/v1/system/doctor") return { data: doctor };
    if (path.startsWith("/admin/v1/admin-sessions") && !path.endsWith("/revoke")) return { data: sessions };
    if (path.endsWith("/revoke")) return { data: undefined };
    if (path.endsWith("/config")) return { data: { document: { apiVersion: "latchway.dev/v1alpha1" } } };
    throw new Error(`Unexpected request ${path}`);
  });
  mocks.readFile.mockResolvedValue({ apiVersion: "latchway.dev/v1alpha1" });
  mocks.stage.mockResolvedValue(stagedResult);
  mocks.activate.mockResolvedValue({
    ...stagedResult,
    revision: { ...stagedResult.revision, state: "active" }
  });
});

describe("Settings compatibility", () => {
  it("enters read-only safe mode for protocol, capability, contract, or readiness gaps", () => {
    const result = evaluateSettingsCompatibility({
      ...systemStatus,
      contract_version: "0.9.0",
      protocol_versions: [1],
      ready: false,
      server_capabilities: systemStatus.server_capabilities.filter((item) => item !== "opaque_http")
    });

    expect(result.readOnlySafeMode).toBe(true);
    expect(result.protocolCompatible).toBe(false);
    expect(result.contractCompatible).toBe(false);
    expect(result.missingCapabilities).toEqual(["opaque_http"]);
    expect(result.reasons).toHaveLength(4);
  });
});

describe("SettingsPage", () => {
  it("shows compatibility, negotiated capabilities, doctor privacy facts, and exact CLI commands", async () => {
    render(<SettingsPage />);

    expect(await screen.findByText("Mutation compatibility confirmed")).toBeInTheDocument();
    expect(screen.getByText("Unavailable and off in v1.")).toBeInTheDocument();
    expect(screen.getByText("Deployment-configured.")).toBeInTheDocument();
    expect(screen.getByText("None.")).toBeInTheDocument();
    expect(screen.getByText("168 hours")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Negotiated server capabilities" })).toHaveTextContent("admin_session_management");
    expect(screen.getByText("SSE capability negotiated")).toBeInTheDocument();
    expect(screen.getByText(/latchway config pull --environment env_0123456789abcdef --format yaml/)).toBeInTheDocument();
    expect(screen.getByText(/latchway config apply --environment env_0123456789abcdef --file environment.yaml --dry-run/)).toBeInTheDocument();
    expect(screen.getByText("Current session")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("provider-secret-value");
  });

  it("exports through the canonical active revision and gates activation behind server review", async () => {
    const user = userEvent.setup();
    const createObjectURL = vi.fn(() => "blob:configuration");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<SettingsPage />);
    await screen.findByText("Mutation compatibility confirmed");

    await user.click(screen.getByRole("button", { name: "Download redaction-safe YAML" }));
    expect(mocks.adminRequest).toHaveBeenCalledWith(
      "/admin/v1/environments/env_0123456789abcdef/config",
      expect.anything()
    );
    expect(mocks.yaml).toHaveBeenCalledWith({ apiVersion: "latchway.dev/v1alpha1" });
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:configuration");

    const file = new File(["apiVersion: latchway.dev/v1alpha1\n"], "environment.yaml", { type: "application/yaml" });
    await user.upload(screen.getByLabelText(/YAML or JSON configuration file/), file);
    expect(await screen.findByText("Local file ready")).toBeInTheDocument();
    expect(mocks.dirty).toHaveBeenLastCalledWith(true);

    await user.click(screen.getByRole("button", { name: "Create immutable draft and show plan" }));
    expect(await screen.findByRole("list", { name: "Redacted configuration plan" })).toHaveTextContent("Feature routing changed.");
    const activate = screen.getByRole("button", { name: "Activate reviewed revision" });
    expect(activate).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /reviewed every validation issue/ }));
    await user.type(screen.getByLabelText(/Type ACTIVATE development/), "ACTIVATE development");
    expect(activate).toBeEnabled();
    await user.click(activate);

    await waitFor(() => expect(mocks.activate).toHaveBeenCalledWith({
      document: { apiVersion: "latchway.dev/v1alpha1" },
      environmentID: "env_0123456789abcdef",
      staged: expect.objectContaining({
        revision: expect.objectContaining({ id: "rev_1123456789abcdef", state: "valid" })
      })
    }));
    expect(await screen.findByText(/server accepted its exact strong ETag/)).toBeInTheDocument();
    expect(mocks.dirty).toHaveBeenLastCalledWith(false);
  });

  it("requires the exact typed phrase before immediate session revocation", async () => {
    const user = userEvent.setup();
    render(<SettingsPage />);
    await screen.findByText("Current session");

    await user.click(screen.getByRole("button", { name: "Review revoke session asn_0123456789abcdef" }));
    const confirm = screen.getByRole("button", { name: "Revoke session immediately" });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText("Typed session revocation confirmation"), "REVOKE asn_0123456789abcdef");
    expect(confirm).toBeEnabled();
    await user.click(confirm);

    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledWith(
      "/admin/v1/admin-sessions/asn_0123456789abcdef/revoke",
      expect.anything(),
      { method: "POST" }
    ));
    expect(await screen.findByText(/current administrator session was revoked/)).toBeInTheDocument();
    expect(screen.getByText("revoked")).toBeInTheDocument();
  });

  it("keeps mutations disabled in safe mode and does not request session inventory without permission", async () => {
    mocks.session.data.session.capabilities = ["activate_configuration"];
    mocks.adminRequest.mockImplementation(async (path: string) => {
      if (path === "/admin/v1/system") return { data: { ...systemStatus, protocol_versions: [1] } };
      if (path === "/admin/v1/system/doctor") return { data: { ...doctor, facts: { ...doctor.facts, runtime: { ...doctor.facts.runtime, protocol_versions: [1] } } } };
      throw new Error(`Unexpected request ${path}`);
    });
    render(<SettingsPage />);

    expect(await screen.findByText("Read-only safe mode is active")).toBeInTheDocument();
    expect(screen.getByLabelText(/YAML or JSON configuration file/)).toBeDisabled();
    expect(screen.getByText("Owner access required")).toBeInTheDocument();
    expect(mocks.adminRequest.mock.calls.some(([path]) => String(path).startsWith("/admin/v1/admin-sessions"))).toBe(false);
  });
});

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["revoke_installations"], organization_id: "org_0123456789abcdef" } } })
}));

import { InstallationFamiliesPage } from "./installation-families-page";

const instant = "2026-08-29T00:00:00Z";
const environmentID = "env_0123456789abcdef";
const familyID = "fam_0123456789abcdef";
const rootID = "cmp_0123456789abcdef";
const childID = "cmp_1123456789abcdef";
const usage = { cost_nano_usd: 42, input_tokens: 10, logical_requests: 1, output_tokens: 5, total_tokens: 15 };

const root = {
  component_key_id: "cky_0123456789abcdef", created_at: instant, definition_id: "ios-main",
  dpop_jkt: "A".repeat(43), environment_id: environmentID, granted_features: ["assistant"], id: rootID,
  installation_family_id: familyID, is_root: true, key_storage_claim: "secure_enclave", kind: "main_app",
  last_seen_at: instant, platform: "ios", refresh_reuse_count: 0, request_count: 1, session_expires_at: "2026-08-29T00:05:00Z", session_failure_count: 0,
  session_family_id: "csf_0123456789abcdef", session_status: "active", status: "active",
  trust_expires_at: "2026-08-30T00:00:00Z", trust_source: "direct_attested", trust_verified_at: instant,
  attestation_provider: "app_attest", updated_at: instant, usage, user_id: "usr_0123456789abcdef"
} as const;

const child = {
  component_key_id: "cky_1123456789abcdef", created_at: instant, definition_id: "ios-widget",
  delegation: {
    attestation_expires_at: "2026-08-30T00:00:00Z", attestation_provider: "app_attest",
    configuration_revision_id: "rev_0123456789abcdef", consumed_at: instant, created_at: instant,
    expires_at: "2026-08-30T00:00:00Z", feature_scopes: ["assistant"], id: "dlg_0123456789abcdef",
    identity_expires_at: "2026-08-30T00:00:00Z", parent_component_id: rootID, trust_level: "app_verified"
  },
  dpop_jkt: "B".repeat(43), environment_id: environmentID, granted_features: ["assistant"], id: childID,
  installation_family_id: familyID, is_root: false, key_storage_claim: "keychain", kind: "widget",
  last_seen_at: instant, parent_attestation_event_id: "ate_0123456789abcdef", parent_component_id: rootID,
  platform: "ios", refresh_reuse_count: 2, request_count: 1, session_expires_at: "2026-08-29T00:05:00Z", session_failure_count: 3,
  session_family_id: "csf_1123456789abcdef", session_status: "active", status: "active",
  trust_expires_at: "2026-08-30T00:00:00Z", trust_source: "delegated_from_attested_root", trust_verified_at: instant,
  attestation_provider: "app_attest", updated_at: instant, usage, user_id: "usr_0123456789abcdef"
} as const;

const family = {
  component_count: 2, created_at: instant, environment_id: environmentID, id: familyID, last_seen_at: instant,
  platform: "ios", request_count: 2, root_component_id: rootID, root_trust_expires_at: "2026-08-30T00:00:00Z",
  root_trust_source: "direct_attested", status: "active", updated_at: instant, usage,
  user_id: "usr_0123456789abcdef"
} as const;

beforeEach(() => {
  adminRequestMock.mockReset();
  window.history.replaceState({}, "", "/");
});

describe("Installation Family console", () => {
  it("loads the exact family graph, inspects component provenance, and revokes only the child", async () => {
    const reattestedChild = { ...child, session_status: "revoked", trust_expires_at: "2026-08-29T00:05:00Z", updated_at: "2026-08-29T00:05:00Z" };
    const revokedChild = { ...child, revocation_reason: "console operator revocation", revoked_at: "2026-08-29T00:10:00Z", session_status: "revoked", status: "revoked", updated_at: "2026-08-29T00:10:00Z" };
    const detail = { ...family, components: [root, child] };
    const afterReattestation = { ...family, components: [root, reattestedChild], updated_at: "2026-08-29T00:05:00Z" };
    const after = { ...family, components: [root, revokedChild], updated_at: "2026-08-29T00:10:00Z" };
    let reattestationRequired = false;
    let revokedState = false;
    adminRequestMock.mockImplementation(async (path: string, _schema: unknown, options?: { body?: unknown; method?: string }) => {
      if (path.includes("?")) return { data: { items: [family], page: { has_more: false } } };
      if (path === `/admin/v1/client-components/${childID}/require-reattestation` && options?.method === "POST") { reattestationRequired = true; return { data: reattestedChild }; }
      if (path === `/admin/v1/client-components/${childID}/revoke` && options?.method === "POST") { revokedState = true; return { data: revokedChild }; }
      if (path === `/admin/v1/client-components/${childID}`) return { data: child };
      if (path === `/admin/v1/installation-families/${familyID}`) return { data: revokedState ? after : reattestationRequired ? afterReattestation : detail };
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    render(<InstallationFamiliesPage />);
    expect(screen.getByRole("link", { name: "Open compatibility reference" })).toHaveAttribute("href", "https://docs.latchway.dev/reference/compatibility");
    await user.type(screen.getByLabelText("Environment ID"), environmentID);
    await user.click(screen.getByRole("button", { name: "List families" }));
    await user.click(await screen.findByRole("button", { name: familyID }));

    expect(await screen.findByLabelText("Installation Family trust graph")).toHaveTextContent("delegated from attested root");
    await user.click(screen.getByRole("button", { name: "ios-widget" }));
    expect(await screen.findByRole("heading", { name: "Delegation receipt" })).toBeInTheDocument();
    expect(screen.queryByText("secure_enclave")).not.toBeInTheDocument();
    expect(screen.getByText("keychain")).toBeInTheDocument();
    expect(screen.getByText("Refresh reuse events").parentElement).toHaveTextContent("2");
    expect(screen.getByText("Session failures").parentElement).toHaveTextContent("3");
    await user.click(screen.getByRole("button", { name: "Require re-attestation" }));
    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/client-components/${childID}/require-reattestation`, expect.anything(), { body: { reason: "console operator revocation" }, method: "POST" });
    expect((await screen.findByText("Session status")).parentElement).toHaveTextContent("revoked");
    await user.click(screen.getByRole("button", { name: "Revoke component" }));

    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/client-components/${childID}/revoke`, expect.anything(), { body: { reason: "console operator revocation" }, method: "POST" });
    expect(await screen.findByText("console operator revocation")).toBeInTheDocument();
  });

  it("revokes a complete family and reloads all descendant state", async () => {
    const detail = { ...family, components: [root, child] };
    const renewalComponents = [root, child].map((component) => ({ ...component, session_status: "revoked", trust_expires_at: "2026-08-29T00:05:00Z", updated_at: "2026-08-29T00:05:00Z" }));
    const renewed = { ...family, components: renewalComponents, root_trust_expires_at: "2026-08-29T00:05:00Z", updated_at: "2026-08-29T00:05:00Z" };
    const revokedComponents = [root, child].map((component) => ({ ...component, revocation_reason: "security response", revoked_at: "2026-08-29T00:10:00Z", session_status: "revoked", status: "revoked", updated_at: "2026-08-29T00:10:00Z" }));
    const revoked = { ...family, components: revokedComponents, revocation_reason: "security response", revoked_at: "2026-08-29T00:10:00Z", status: "revoked", updated_at: "2026-08-29T00:10:00Z" };
    let renewalRequired = false;
    let revokedState = false;
    adminRequestMock.mockImplementation(async (path: string, _schema: unknown, options?: { body?: unknown; method?: string }) => {
      if (path.includes("?")) return { data: { items: [family], page: { has_more: false } } };
      if (path === `/admin/v1/installation-families/${familyID}/require-renewal` && options?.method === "POST") { renewalRequired = true; return { data: { ...renewed, components: undefined } }; }
      if (path === `/admin/v1/installation-families/${familyID}/revoke` && options?.method === "POST") { revokedState = true; return { data: { ...revoked, components: undefined } }; }
      if (path === `/admin/v1/installation-families/${familyID}`) return { data: revokedState ? revoked : renewalRequired ? renewed : detail };
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    render(<InstallationFamiliesPage />);
    await user.type(screen.getByLabelText("Environment ID"), environmentID);
    await user.click(screen.getByRole("button", { name: "List families" }));
    await user.click(await screen.findByRole("button", { name: familyID }));
    await user.clear(screen.getByLabelText("Operator reason"));
    await user.type(screen.getByLabelText("Operator reason"), "security response");
    await user.click(screen.getByRole("button", { name: "Require containing-app renewal" }));
    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/installation-families/${familyID}/require-renewal`, expect.anything(), { body: { reason: "security response" }, method: "POST" });
    await user.click(screen.getByRole("button", { name: "Revoke family" }));

    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/installation-families/${familyID}/revoke`, expect.anything(), { body: { reason: "security response" }, method: "POST" });
    expect(await screen.findByText("security response")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke family" })).toBeDisabled();
  });

  it("prefills the environment and pseudonymous-user filters from a user-detail link", async () => {
    const userID = "usr_0123456789abcdef";
    window.history.replaceState({}, "", `/installation-families?environment_id=${environmentID}&user_id=${userID}`);
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: false } } });
    const user = userEvent.setup();
    render(<InstallationFamiliesPage />);

    expect(screen.getByLabelText("Environment ID")).toHaveValue(environmentID);
    expect(screen.getByLabelText("User ID (optional)")).toHaveValue(userID);
    await user.click(screen.getByRole("button", { name: "List families" }));

    expect(adminRequestMock.mock.calls[0]?.[0]).toContain(`environment_id=${environmentID}`);
    expect(adminRequestMock.mock.calls[0]?.[0]).toContain(`user_id=${userID}`);
  });
});

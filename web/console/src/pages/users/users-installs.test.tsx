import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  adminRequest: vi.fn(),
  getUserEffectiveConfiguration: vi.fn(),
  getUserOperationImpact: vi.fn(),
  navigate: vi.fn(),
  requireApplicationUserReauthentication: vi.fn(),
  setApplicationUserBlocked: vi.fn()
}));

vi.mock("../../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/admin")>()),
  adminRequest: mocks.adminRequest,
  getUserEffectiveConfiguration: mocks.getUserEffectiveConfiguration,
  getUserOperationImpact: mocks.getUserOperationImpact,
  requireApplicationUserReauthentication: mocks.requireApplicationUserReauthentication,
  setApplicationUserBlocked: mocks.setApplicationUserBlocked
}));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["revoke_installations"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => ({ mutationAllowed: true }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>,
  useNavigate: () => mocks.navigate
}));

import { AdminRequestError } from "../../api/auth";
import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
import { InstallationFamiliesPage } from "./installations-page";
import { InstallationsPage } from "./older-installs-page";
import { UsersPage } from "./users-page";

const ENV = "env_0123456789abcdef";
const USER = "usr_0123456789abcdef";
const OTHER = "usr_1123456789abcdef";
const instant = "2026-08-29T00:00:00Z";
const usage = { cost_nano_usd: 42, input_tokens: 10, logical_requests: 1, output_tokens: 5, total_tokens: 15 };

const activeUser = { created_at: instant, environment_id: ENV, id: USER, identity_providers: ["firebase"], last_seen_at: instant, normalized_claims: { plan: "subscriber" }, status: "active" };
const otherUser = { ...activeUser, id: OTHER };

function impactFixture(action: string, families = 1) {
  return {
    access_effect: "deny_and_revoke", action, applicable: true,
    counts: { active_client_components: 2, active_component_refresh_tokens: 2, active_component_sessions: 2, active_installation_families: families, active_refresh_tokens: 1, active_session_grants: 1 },
    current_status: "active", immediate: true, impact_token: "A".repeat(43), reversible: true,
    summary: "Blocks access and revokes active credentials application-wide."
  };
}

const FAMILY = "fam_0123456789abcdef";
const ROOT = "cmp_0123456789abcdef";
const CHILD = "cmp_1123456789abcdef";
const root = {
  attestation_provider: "app_attest", component_key_id: "cky_0123456789abcdef", created_at: instant, definition_id: "ios-main",
  dpop_jkt: "A".repeat(43), environment_id: ENV, granted_features: ["assistant"], id: ROOT, installation_family_id: FAMILY,
  is_root: true, key_storage_claim: "secure_enclave", kind: "main_app", last_seen_at: instant, platform: "ios", refresh_reuse_count: 0,
  request_count: 1, session_expires_at: "2026-08-29T00:05:00Z", session_failure_count: 0, session_family_id: "csf_0123456789abcdef",
  session_status: "active", status: "active", trust_expires_at: "2026-08-30T00:00:00Z", trust_source: "direct_attested",
  trust_verified_at: instant, updated_at: instant, usage, user_id: USER
};
const child = {
  ...root, component_key_id: "cky_1123456789abcdef", definition_id: "ios-widget", dpop_jkt: "B".repeat(43), id: CHILD, is_root: false,
  key_storage_claim: "software", kind: "widget", parent_component_id: ROOT, refresh_reuse_count: 2, session_failure_count: 3,
  session_family_id: "csf_1123456789abcdef", trust_source: "delegated_from_attested_root",
  delegation: {
    attestation_expires_at: "2026-08-30T00:00:00Z", attestation_provider: "app_attest", configuration_revision_id: "rev_0123456789abcdef",
    consumed_at: instant, created_at: instant, expires_at: "2026-08-30T00:00:00Z", feature_scopes: ["assistant"], id: "dlg_0123456789abcdef",
    identity_expires_at: "2026-08-30T00:00:00Z", parent_component_id: ROOT, trust_level: "app_verified"
  }
};
const family = {
  component_count: 2, created_at: instant, environment_id: ENV, id: FAMILY, last_seen_at: instant, platform: "ios", request_count: 2,
  root_component_id: ROOT, root_trust_expires_at: "2026-08-30T00:00:00Z", root_trust_source: "direct_attested", status: "active",
  updated_at: instant, usage, user_id: USER
};
const debugFamily = { ...family, id: "fam_1123456789abcdef", root_trust_source: "debug" };

function renderPage(page: ReactNode, initial: WorkspaceSearch = {}) {
  const updates: Array<Partial<WorkspaceSearch>> = [];
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Mobile App", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile-app", status: "active" as const };
  const environment = { application_id: application.id, created_at: instant, display_name: "Production", id: ENV, kind: "production" as const, slug: "production", status: "active" as const };
  function Harness() {
    const [search, setSearch] = useState<WorkspaceSearch>({ application: "mobile-app", environment: "production", organization: "example", ...initial });
    const value: WorkspaceContextValue = {
      application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false,
      isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(),
      updateSearch: (patch) => { updates.push(patch); setSearch((current) => ({ ...current, ...patch })); }
    };
    return <WorkspaceContext.Provider value={value}>{page}</WorkspaceContext.Provider>;
  }
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Harness /></QueryClientProvider>);
  return { updates };
}

function usersApi(users = [activeUser], detail: Record<string, unknown> = activeUser) {
  mocks.adminRequest.mockImplementation(async (path: string) => {
    if (path.startsWith("/admin/v1/users?")) return { data: { items: users, page: { has_more: false } } };
    if (path.startsWith(`/admin/v1/users/${String(detail.id)}?`)) return { data: detail };
    if (path.startsWith("/admin/v1/installation-families?")) return { data: { items: [family], page: { has_more: false } } };
    if (path.startsWith("/admin/v1/requests?")) return { data: { items: [], page: { has_more: false } } };
    throw new Error(`Unexpected request ${path}`);
  });
}

/** The loading drawer shares the record's name, so wait for a loaded section before using it. */
async function loadedDrawer(name: string, section: string): Promise<HTMLElement> {
  await screen.findByRole("heading", { name: section });
  return screen.getByRole("complementary", { name });
}

beforeEach(() => {
  for (const mock of Object.values(mocks)) mock.mockReset();
});
afterEach(cleanup);

describe("Users", () => {
  it("restores a user from the URL, keeps claim values hidden until asked, and closes", async () => {
    usersApi();
    const user = userEvent.setup();
    const { updates } = renderPage(<UsersPage />, { user_id: USER });
    const drawer = await loadedDrawer(USER, "Identity");
    expect(await within(drawer).findByText("plan")).toBeInTheDocument();
    expect(within(drawer).queryByText("subscriber")).not.toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: "Show Values" }));
    expect(within(drawer).getByText("subscriber")).toBeInTheDocument();
    expect(await within(drawer).findByText(/1 active · 1 total/)).toBeInTheDocument();
    expect(within(drawer).getByText(/summed from these installations/)).toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: "Close" }));
    expect(updates.at(-1)).toEqual({ environment_id: undefined, user_id: undefined });
  });

  it("rejects user detail from another environment", async () => {
    usersApi([activeUser], { ...activeUser, environment_id: "env_ffffffffffffffff" });
    renderPage(<UsersPage />, { user_id: USER });
    expect((await screen.findAllByText("User context mismatch")).length).toBeGreaterThan(0);
  });

  it("blocks only after a server preview, and re-asks when the counts changed", async () => {
    usersApi();
    mocks.getUserOperationImpact
      .mockResolvedValueOnce({ data: impactFixture("block", 1) })
      .mockResolvedValueOnce({ data: { ...impactFixture("block", 2), impact_token: "B".repeat(43) } });
    mocks.setApplicationUserBlocked
      .mockRejectedValueOnce(new AdminRequestError({ code: "conflict", detail: "The user state changed after the reviewed impact.", retryable: false, status: 409, title: "Resource conflict" }))
      .mockResolvedValueOnce({ data: { ...activeUser, status: "blocked" } });
    const user = userEvent.setup();
    renderPage(<UsersPage />, { user_id: USER });
    const drawer = await loadedDrawer(USER, "Identity");
    await user.click(within(drawer).getByRole("button", { name: "Actions" }));
    await user.click(screen.getByRole("menuitem", { name: "Block" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Block user?" });
    expect(mocks.getUserOperationImpact).toHaveBeenCalledWith(USER, ENV, "block");
    const confirm = within(dialog).getByRole("button", { name: "Block User" });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText("Reason"), "Confirmed compromised account");
    await user.type(within(dialog).getByLabelText(/to confirm/), USER);
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(confirm);

    expect(await within(dialog).findByText("Counts changed since you opened this")).toBeInTheDocument();
    expect(within(dialog).getByText("1 →")).toBeInTheDocument();
    expect(within(dialog).getByRole("checkbox")).not.toBeChecked();
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(confirm);

    expect(mocks.setApplicationUserBlocked).toHaveBeenLastCalledWith(USER, ENV, true, { acknowledge_immediate_effect: true, impact_token: "B".repeat(43), reason: "Confirmed compromised account" });
    expect(await screen.findByText("Block user completed.")).toBeInTheDocument();
  });

  it("offers only Unblock and an override for a blocked user", async () => {
    usersApi([{ ...activeUser, status: "blocked" }], { ...activeUser, status: "blocked" });
    const user = userEvent.setup();
    renderPage(<UsersPage />, { user_id: USER });
    const drawer = await loadedDrawer(USER, "Identity");
    await user.click(within(drawer).getByRole("button", { name: "What's Going On?" }));
    expect(within(drawer).getByText("Blocked by mistake")).toBeInTheDocument();
    expect(within(drawer).queryByText("Account compromised or abusive")).not.toBeInTheDocument();
    expect(within(drawer).getAllByRole("listitem").filter((item) => item.closest(".lw-intents"))).toHaveLength(2);
  });

  it("explains current access from claim keys without showing claim values", async () => {
    usersApi();
    mocks.getUserEffectiveConfiguration.mockResolvedValue({ data: {
      decision_stages: [], environment_id: ENV, environment_kind: "production", evaluation_mode: "current_user_projection", feature: "assistant",
      inputs: [{ availability: "available", detail: "Only normalized claim keys are shown.", fact: "normalized_claims", keys: ["plan"], source: "current_application_user" }],
      limit_plan: "subscriber", limit_plan_source: "policy_expression",
      limits: [{ algorithm: "per_request", hard: true, index: 0, metric: "input_tokens", per_request_maximum: 4096, scope: ["user", "feature"], source: "limit_plans.subscriber.limits[0]" }],
      policy_outcome: "allowed", protocol: "openai_chat", revision_id: "rev_0123456789abcdef", routes: [],
      subject: { id: USER, kind: "user", user_id: USER }, warnings: []
    } });
    const user = userEvent.setup();
    renderPage(<UsersPage />, { user_id: USER });
    const drawer = await loadedDrawer(USER, "Identity");
    await user.type(within(drawer).getByLabelText("Feature"), "assistant");
    await user.type(within(drawer).getByLabelText("Estimated input tokens"), "2048");
    await user.click(within(drawer).getByRole("button", { name: "Check Access" }));
    expect(mocks.getUserEffectiveConfiguration).toHaveBeenCalledWith(USER, expect.objectContaining({ environmentID: ENV, estimatedInputTokens: 2048, feature: "assistant" }));
    expect(await within(drawer).findByRole("heading", { name: "Current-state projection" })).toBeInTheDocument();
    expect(within(drawer).getByText("keys: plan")).toBeInTheDocument();
  });

  it("requires sign-in for several users as separate reviewed operations and reports each", async () => {
    usersApi([activeUser, otherUser]);
    mocks.getUserOperationImpact.mockImplementation(async (id: string) => ({ data: { ...impactFixture("require_reauthentication"), impact_token: (id === USER ? "C" : "D").repeat(43) } }));
    mocks.requireApplicationUserReauthentication
      .mockResolvedValueOnce({ data: { impact: impactFixture("require_reauthentication"), operation_id: "arq_01J0000000000000000000000A", user: activeUser } })
      .mockRejectedValueOnce(new AdminRequestError({ code: "operation_indeterminate", detail: "The database commit outcome is unknown.", operationId: "arq_01J0000000000000000000000B", retryable: true, status: 503, title: "Operation outcome indeterminate" }));
    const user = userEvent.setup();
    renderPage(<UsersPage />);
    await user.click(await screen.findByRole("checkbox", { name: `Select ${USER}` }));
    await user.click(screen.getByRole("checkbox", { name: `Select ${OTHER}` }));
    await user.click(screen.getByRole("button", { name: "Require Sign-in…" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Require sign-in for 2 users?" });
    await user.type(within(dialog).getByLabelText("Reason"), "Plan migration");
    await user.type(within(dialog).getByLabelText(/to confirm/), "2 users");
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(within(dialog).getByRole("button", { name: "Require Sign-in for 2" }));
    const results = await screen.findByRole("alertdialog", { name: "Require sign-in finished" });
    expect(mocks.requireApplicationUserReauthentication).toHaveBeenNthCalledWith(1, USER, ENV, { acknowledge_immediate_effect: true, impact_token: "C".repeat(43), reason: "Plan migration" });
    expect(within(results).getByText("1 done · 0 skipped · 1 unknown · 0 failed")).toBeInTheDocument();
    expect(within(results).getByText(/Check the audit log before retrying/)).toBeInTheDocument();
  });

  it("goes to IDs instead of searching", async () => {
    usersApi();
    const user = userEvent.setup();
    const { updates } = renderPage(<UsersPage />);
    const go = await screen.findByLabelText("Go to a user, installation, component or request ID");
    await user.type(go, "someone@example.com{Enter}");
    expect(screen.getByText(/never stores emails or sign-in subjects/)).toBeInTheDocument();
    await user.clear(go);
    await user.type(go, `${OTHER}{Enter}`);
    expect(updates.at(-1)).toMatchObject({ user_id: OTHER });
    await user.type(go, `${FAMILY}{Enter}`);
    expect(mocks.navigate).toHaveBeenLastCalledWith(expect.objectContaining({ search: expect.objectContaining({ family_id: FAMILY }), to: "/installation-families" }));
  });
});

function familiesApi(detail: Record<string, unknown> = { ...family, components: [root, child] }) {
  mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { body?: unknown; method?: string }) => {
    if (path.startsWith("/admin/v1/installation-families?")) return { data: { items: [family, debugFamily], page: { has_more: false } } };
    if (path === `/admin/v1/installation-families/${FAMILY}`) return { data: detail };
    if (path === `/admin/v1/client-components/${CHILD}/revoke` && options?.method === "POST") return { data: { ...child, revoked_at: instant, status: "revoked" } };
    if (path === `/admin/v1/installation-families/${FAMILY}/revoke` && options?.method === "POST") return { data: { ...family, revocation_reason: "lost device", revoked_at: instant, status: "revoked" } };
    throw new Error(`Unexpected request ${path}`);
  });
}

describe("Installations", () => {
  it("flags debug trust from the list and narrows to loaded rows with signals", async () => {
    familiesApi();
    const user = userEvent.setup();
    renderPage(<InstallationFamiliesPage />);
    expect(await screen.findByText("Debug trust")).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(3);
    await user.click(screen.getByRole("button", { name: "With signals" }));
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(screen.getByText(/Showing signals in the 2 loaded installations/)).toBeInTheDocument();
  });

  it("opens an installation on a part, shows its signals and revokes only that part", async () => {
    familiesApi();
    const user = userEvent.setup();
    renderPage(<InstallationFamiliesPage />, { component_id: CHILD, environment_id: ENV, family_id: FAMILY });
    const drawer = await loadedDrawer(FAMILY, "Signals");
    expect(within(drawer).getByText("Token reuse ×2")).toBeInTheDocument();
    expect(within(drawer).getByText("Weak key storage")).toBeInTheDocument();
    expect(within(drawer).getByText("Failed sessions ×3")).toBeInTheDocument();
    expect(drawer.querySelector(".lw-part.is-highlighted")?.textContent).toContain("ios-widget");
    const part = drawer.querySelector(".lw-part.is-highlighted") as HTMLElement;
    await user.click(within(part).getByRole("button", { name: "Revoke" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Revoke this part?" });
    expect(within(dialog).getByText("Counts are from this installation as loaded")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Reason"), "widget misbehaving");
    await user.type(within(dialog).getByLabelText(/to confirm/), CHILD);
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(within(dialog).getByRole("button", { name: "Revoke Part" }));
    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledWith(`/admin/v1/client-components/${CHILD}/revoke`, expect.anything(), { body: { reason: "widget misbehaving" }, method: "POST" }));
    expect(await screen.findByText(/Revoke part completed/)).toBeInTheDocument();
    expect(mocks.adminRequest).not.toHaveBeenCalledWith(`/admin/v1/installation-families/${FAMILY}/revoke`, expect.anything(), expect.anything());
  });

  it("treats revoking the root part as revoking the installation", async () => {
    familiesApi();
    const user = userEvent.setup();
    renderPage(<InstallationFamiliesPage />, { environment_id: ENV, family_id: FAMILY });
    const drawer = await loadedDrawer(FAMILY, "Signals");
    const rootPart = drawer.querySelector(".lw-part") as HTMLElement;
    await user.click(within(rootPart).getByRole("button", { name: "Revoke Installation" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Revoke this installation?" });
    await user.type(within(dialog).getByLabelText("Reason"), "lost device");
    await user.type(within(dialog).getByLabelText(/to confirm/), FAMILY);
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(within(dialog).getByRole("button", { name: "Revoke Installation" }));
    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledWith(`/admin/v1/installation-families/${FAMILY}/revoke`, expect.anything(), { body: { reason: "lost device" }, method: "POST" }));
  });

  it("refuses a part that isn't in the opened installation", async () => {
    familiesApi({ ...family, component_count: 1, components: [root] });
    renderPage(<InstallationFamiliesPage />, { component_id: CHILD, environment_id: ENV, family_id: FAMILY });
    expect(await screen.findByText("Component detail mismatch")).toBeInTheDocument();
  });
});

describe("Older installs", () => {
  it("lists legacy installs and revokes one after review", async () => {
    const installation = {
      attestation_provider: "app_attest", created_at: instant, dpop_jkt: "A".repeat(43), environment_id: ENV, id: "ins_0123456789abcdef",
      last_seen_at: instant, platform: "react_native_ios", status: "active", trust_expires_at: "2026-08-30T00:00:00Z", trust_level: "app_verified", user_id: USER
    };
    mocks.adminRequest.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.startsWith("/admin/v1/installations?")) return { data: { items: [installation], page: { has_more: false } } };
      if (path === `/admin/v1/installations/${installation.id}`) return { data: installation };
      if (path === `/admin/v1/installations/${installation.id}/revoke` && options?.method === "POST") return { data: { ...installation, revoked_at: instant, status: "revoked" } };
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    renderPage(<InstallationsPage />, { environment_id: ENV, installation_id: installation.id });
    await screen.findByText("Trust provider");
    const drawer = screen.getByRole("complementary", { name: installation.id });
    expect(screen.getAllByText("Legacy").length).toBeGreaterThan(0);
    await user.click(await within(drawer).findByRole("button", { name: "Revoke Installation" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Revoke this installation?" });
    await user.type(within(dialog).getByLabelText("Reason"), "confirmed compromised device");
    await user.type(within(dialog).getByLabelText(/to confirm/), installation.id);
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(within(dialog).getByRole("button", { name: "Revoke Installation" }));
    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledWith(`/admin/v1/installations/${installation.id}/revoke`, expect.anything(), { body: { reason: "confirmed compromised device" }, method: "POST" }));
    expect(await screen.findByText(`Installation ${installation.id} revoked.`)).toBeInTheDocument();
  });
});

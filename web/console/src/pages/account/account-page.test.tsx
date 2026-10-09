import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility, createPasskeyMock, signInMethods } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true, status: { server_capabilities: ["admin_account_self_service"] } as { server_capabilities: string[] } | undefined },
  createPasskeyMock: vi.fn(),
  signInMethods: { value: ["password", "passkey"] }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/auth")>()),
  adminSignInInfoQueryOptions: { queryFn: () => Promise.resolve({ contract_version: "1.1.0", protocol_versions: [1, 2, 3], setup_open: false, sign_in_methods: signInMethods.value }), queryKey: ["admin-sign-in-info"], retry: false }
}));
vi.mock("../../api/webauthn", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/webauthn")>()), createPasskey: createPasskeyMock, passkeysAvailable: () => true }));
vi.mock("../../api/session", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/session")>()),
  useConsoleSession: () => ({ data: { mode: "configured", session: { administrator: { display_name: "Owner One", email: "owner@example.test", enabled: true, id: "adm_0123456789abcdef" }, capabilities: ["manage_owners"], expires_at: "2026-10-08T20:00:00Z", memberships: [{ organization_id: "org_0123456789abcdef", role: "owner" }], organization_id: "org_0123456789abcdef", password_reset_required: false } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: React.ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { mutationsOf, renderWithWorkspace } from "../../test/workspace-harness";
import { AccountPage } from "./account-page";

type Options = { body?: Record<string, unknown>; method?: string } | undefined;

const session = (id: string, extra: Record<string, unknown>) => ({ created_at: "2026-10-08T08:00:00Z", current: false, expires_at: "2026-10-08T20:00:00Z", id, last_seen_at: "2026-10-08T09:00:00Z", organization_id: "org_0123456789abcdef", status: "active", ...extra });

const RECOVERY_CODES = Array.from({ length: 10 }, (_, index) => `aaaa-bbbb-ccc${String.fromCharCode(97 + index)}`);
type TestPasskey = { created_at: string; id: string; last_used_at?: string; name: string; synced: boolean };
const LAPTOP: TestPasskey = { created_at: "2026-10-02T00:00:00Z", id: "apk_0123456789abcdef", last_used_at: "2026-10-08T07:00:00Z", name: "Laptop", synced: true };

type TwoFactor = { enabled: boolean; passkeys: number; recovery_codes_remaining: number; required_by_organization: boolean; totp_enabled: boolean; totp_enabled_at?: string };

function server(twoFactor: TwoFactor = { enabled: true, passkeys: 0, recovery_codes_remaining: 2, required_by_organization: false, totp_enabled: true, totp_enabled_at: "2026-10-01T00:00:00Z" }, passkeys: TestPasskey[] = []) {
  const state = {
    passkeys,
    twoFactor,
    sessions: [
      session("asn_0123456789abcdef", { current: true, device_summary: "Chrome on macOS" }),
      session("asn_1123456789abcdef", { device_summary: "Safari on iOS" }),
      session("asn_2123456789abcdef", { end_reason: "password_changed", status: "revoked" })
    ]
  };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    if (path === "/admin/v1/auth/sessions") return Promise.resolve({ data: { items: state.sessions } });
    if (path === "/admin/v1/auth/two-factor") return Promise.resolve({ data: state.twoFactor });
    if (path === "/admin/v1/auth/two-factor/disable" && options?.method === "POST") {
      state.twoFactor = { ...state.twoFactor, enabled: state.twoFactor.passkeys > 0, recovery_codes_remaining: state.twoFactor.passkeys > 0 ? state.twoFactor.recovery_codes_remaining : 0, totp_enabled: false, totp_enabled_at: undefined };
      return Promise.resolve({ data: undefined });
    }
    if (path === "/admin/v1/auth/two-factor/recovery-codes" && options?.method === "POST") return Promise.resolve({ data: { recovery_codes: RECOVERY_CODES } });
    if (path === "/admin/v1/auth/passkeys" && options?.method === "POST") {
      const added = { created_at: "2026-10-08T09:30:00Z", id: "apk_1123456789abcdef", name: String(options.body?.name), synced: false };
      state.passkeys = [...state.passkeys, added];
      const first = !state.twoFactor.enabled;
      state.twoFactor = { ...state.twoFactor, enabled: true, passkeys: state.passkeys.length, recovery_codes_remaining: first ? 10 : state.twoFactor.recovery_codes_remaining };
      return Promise.resolve({ data: first ? { passkey: added, recovery_codes: RECOVERY_CODES } : { passkey: added } });
    }
    if (path === "/admin/v1/auth/passkeys") return Promise.resolve({ data: { items: state.passkeys } });
    if (path === "/admin/v1/auth/passkeys/registration-options" && options?.method === "POST") return Promise.resolve({ data: { public_key: { challenge: "test-only-challenge-0123456789" } } });
    if (path.endsWith("/remove") && path.startsWith("/admin/v1/auth/passkeys/") && options?.method === "POST") {
      state.passkeys = state.passkeys.filter((item) => !path.includes(item.id));
      state.twoFactor = { ...state.twoFactor, passkeys: state.passkeys.length };
      return Promise.resolve({ data: undefined });
    }
    if (path.startsWith("/admin/v1/organizations")) return Promise.resolve({ data: { items: [{ created_at: "2026-10-01T00:00:00Z", display_name: "Example Org", id: "org_0123456789abcdef", slug: "example" }], page: { has_more: false } } });
    if (path === "/admin/v1/auth/password" && options?.method === "POST") {
      if (options.body?.current_password !== "test-only-current-pass") return Promise.reject(Object.assign(new Error("wrong"), { problem: undefined }));
      return Promise.resolve({ data: { signed_out_sessions: 1 } });
    }
    if (path === "/admin/v1/auth/sessions/revoke-others" && options?.method === "POST") {
      state.sessions = state.sessions.map((item) => (item.status === "active" && !item.current ? { ...item, end_reason: "signed_out_elsewhere", status: "revoked" } : item));
      return Promise.resolve({ data: { signed_out_sessions: 1 } });
    }
    return Promise.reject(new Error(`unexpected ${options?.method ?? "GET"} ${path}`));
  });
  return state;
}

describe("AccountPage", () => {
  beforeEach(() => {
    adminRequestMock.mockReset();
    compatibility.mutationAllowed = true;
    compatibility.status = { server_capabilities: ["admin_account_self_service", "admin_two_factor", "admin_passkeys"] };
    createPasskeyMock.mockReset();
    signInMethods.value = ["password", "passkey"];
  });

  it("shows the profile and your sessions with devices and end reasons", async () => {
    server();
    renderWithWorkspace(<AccountPage />);
    expect(screen.getByRole("heading", { level: 1, name: "Your account" })).toBeInTheDocument();
    expect(screen.getByText("Owner One")).toBeInTheDocument();
    expect(await screen.findByText("Safari on iOS")).toBeInTheDocument();
    expect(screen.getByText("This session")).toBeInTheDocument();
    expect(screen.getByText("Password changed")).toBeInTheDocument();
  });

  it("changes the password from write-only inputs and reports signed-out sessions", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<AccountPage />);
    await user.type(screen.getByLabelText("Current password"), "test-only-current-pass");
    await user.type(screen.getByLabelText("New password"), "test-only-brand-new-password");
    await user.click(screen.getByRole("button", { name: "Change Password" }));
    expect(await screen.findByText("1 other session was signed out.")).toBeInTheDocument();
    expect(screen.getByLabelText("Current password")).toHaveValue("");
    expect(screen.getByLabelText("New password")).toHaveValue("");
    expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/auth/password"]);
  });

  it("refuses a weak new password before sending anything", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<AccountPage />);
    await user.type(screen.getByLabelText("Current password"), "test-only-current-pass");
    await user.type(screen.getByLabelText("New password"), "aaaaaaaaaaaa");
    await user.click(screen.getByRole("button", { name: "Change Password" }));
    expect(screen.getByText("Choose a stronger password")).toBeInTheDocument();
    expect(mutationsOf(adminRequestMock)).toEqual([]);
  });

  it("signs out your other sessions after confirmation", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<AccountPage />);
    await user.click(await screen.findByRole("button", { name: "Sign Out Other Sessions" }));
    await user.click(within(screen.getByRole("alertdialog", { name: "Sign out your other sessions?" })).getByRole("button", { name: "Sign Out Other Sessions" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/auth/sessions/revoke-others"]));
    expect(await screen.findByText("Signed out from another session")).toBeInTheDocument();
  });

  it("closes the password form when the console is read-only", () => {
    compatibility.mutationAllowed = false;
    server();
    renderWithWorkspace(<AccountPage />);
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
    expect(screen.getByText("Password changes are unavailable.")).toBeInTheDocument();
  });

  it("warns about few recovery codes and removes the authenticator app with the password and a code", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<AccountPage />);
    expect(await screen.findByText("2 of 10")).toBeInTheDocument();
    expect(screen.getByText(/running low on recovery codes/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove Authenticator App" }));
    const dialog = screen.getByRole("alertdialog", { name: "Remove your authenticator app?" });
    await user.type(within(dialog).getByLabelText("Password", { exact: true }), "test-only-current-pass");
    await user.type(within(dialog).getByLabelText("Authentication code"), "123456");
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/auth/two-factor/disable"]));
    const call = adminRequestMock.mock.calls.find(([path]) => path === "/admin/v1/auth/two-factor/disable");
    expect((call?.[2] as Options)?.body).toEqual({ code: "123456", password: "test-only-current-pass" });
    expect(await screen.findByRole("button", { name: "Set Up Authenticator App" })).toBeInTheDocument();
  });

  it("keeps the authenticator app while it's the only second factor the organization requires", async () => {
    server({ enabled: true, passkeys: 0, recovery_codes_remaining: 10, required_by_organization: true, totp_enabled: true, totp_enabled_at: "2026-10-01T00:00:00Z" });
    renderWithWorkspace(<AccountPage />);
    expect(await screen.findByRole("button", { name: "Remove Authenticator App" })).toBeDisabled();
  });

  it("replaces recovery codes with the password when only passkeys are set up", async () => {
    const user = userEvent.setup();
    server({ enabled: true, passkeys: 1, recovery_codes_remaining: 9, required_by_organization: false, totp_enabled: false }, [LAPTOP]);
    renderWithWorkspace(<AccountPage />);
    await user.click(await screen.findByRole("button", { name: "Replace Recovery Codes" }));
    const dialog = screen.getByRole("alertdialog", { name: "Replace your recovery codes?" });
    expect(within(dialog).queryByLabelText("Authentication code")).not.toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Password", { exact: true }), "test-only-current-pass");
    await user.click(within(dialog).getByRole("button", { name: "Replace Codes" }));
    expect(await screen.findByRole("alertdialog", { name: "Save your recovery codes" })).toBeInTheDocument();
    const call = adminRequestMock.mock.calls.find(([path]) => path === "/admin/v1/auth/two-factor/recovery-codes");
    expect((call?.[2] as Options)?.body).toEqual({ password: "test-only-current-pass" });
  });

  it("lists passkeys and adds one with the password, then shows first-time recovery codes once", async () => {
    const user = userEvent.setup();
    server({ enabled: false, passkeys: 0, recovery_codes_remaining: 0, required_by_organization: false, totp_enabled: false });
    createPasskeyMock.mockResolvedValue({ clientExtensionResults: {}, id: "Y3JlZA", rawId: "Y3JlZA", response: { attestationObject: "b2Jq", clientDataJSON: "Y2Rq" }, type: "public-key" });
    renderWithWorkspace(<AccountPage />);
    expect(await screen.findByText("No passkeys yet.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add Passkey" }));
    const dialog = screen.getByRole("alertdialog", { name: "Add a passkey" });
    await user.clear(within(dialog).getByLabelText("Name"));
    await user.type(within(dialog).getByLabelText("Name"), "Work laptop");
    await user.type(within(dialog).getByLabelText("Current password"), "test-only-current-pass");
    await user.click(within(dialog).getByRole("button", { name: "Continue" }));
    const reveal = await screen.findByRole("alertdialog", { name: "Save your recovery codes" });
    expect(within(reveal).getByText("aaaa-bbbb-ccca")).toBeInTheDocument();
    expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/auth/passkeys/registration-options", "POST /admin/v1/auth/passkeys"]);
    const options = adminRequestMock.mock.calls.find(([path]) => path === "/admin/v1/auth/passkeys/registration-options");
    expect((options?.[2] as Options)?.body).toEqual({ password: "test-only-current-pass" });
    const added = adminRequestMock.mock.calls.find(([path, , init]) => path === "/admin/v1/auth/passkeys" && (init as Options)?.method === "POST");
    expect((added?.[2] as Options)?.body).toEqual({ credential: { clientExtensionResults: {}, id: "Y3JlZA", rawId: "Y3JlZA", response: { attestationObject: "b2Jq", clientDataJSON: "Y2Rq" }, type: "public-key" }, name: "Work laptop" });
    await user.click(within(reveal).getByRole("checkbox"));
    await user.click(within(reveal).getByRole("button", { name: "Done" }));
    expect(await screen.findByText("Work laptop")).toBeInTheDocument();
    expect(screen.getByText("This device only")).toBeInTheDocument();
  });

  it("removes a passkey with the password and refuses the last one the organization needs", async () => {
    const user = userEvent.setup();
    server({ enabled: true, passkeys: 1, recovery_codes_remaining: 10, required_by_organization: true, totp_enabled: false }, [LAPTOP]);
    renderWithWorkspace(<AccountPage />);
    expect(await screen.findByText("Laptop")).toBeInTheDocument();
    expect(screen.getByText("Synced")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove" }));
    const refused = screen.getByRole("alertdialog", { name: "Remove this passkey?" });
    expect(within(refused).getByRole("button", { name: "Remove" })).toBeDisabled();
    await user.click(within(refused).getByRole("button", { name: "Cancel" }));
    expect(mutationsOf(adminRequestMock)).toEqual([]);
  });

  it("removes a passkey after checking the password", async () => {
    const user = userEvent.setup();
    server({ enabled: true, passkeys: 1, recovery_codes_remaining: 10, required_by_organization: false, totp_enabled: true, totp_enabled_at: "2026-10-01T00:00:00Z" }, [LAPTOP]);
    renderWithWorkspace(<AccountPage />);
    await user.click(await screen.findByRole("button", { name: "Remove" }));
    const dialog = screen.getByRole("alertdialog", { name: "Remove this passkey?" });
    await user.type(within(dialog).getByLabelText("Password", { exact: true }), "test-only-current-pass");
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual([`POST /admin/v1/auth/passkeys/${LAPTOP.id}/remove`]));
    expect(await screen.findByText("No passkeys yet.")).toBeInTheDocument();
  });

  it("explains when the server can't accept passkeys and offers no Add button", async () => {
    signInMethods.value = ["password"];
    server();
    renderWithWorkspace(<AccountPage />);
    expect(await screen.findByText("This server doesn't accept passkeys here.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add Passkey" })).not.toBeInTheDocument();
  });

  it("hides passkey changes when the console is read-only", async () => {
    compatibility.mutationAllowed = false;
    server(undefined, [LAPTOP]);
    renderWithWorkspace(<AccountPage />);
    expect(await screen.findByText("Laptop")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add Passkey" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
  });
});

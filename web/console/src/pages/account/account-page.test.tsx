import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true, status: { server_capabilities: ["admin_account_self_service"] } as { server_capabilities: string[] } | undefined }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
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

function server() {
  const state = {
    sessions: [
      session("asn_0123456789abcdef", { current: true, device_summary: "Chrome on macOS" }),
      session("asn_1123456789abcdef", { device_summary: "Safari on iOS" }),
      session("asn_2123456789abcdef", { end_reason: "password_changed", status: "revoked" })
    ]
  };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    if (path === "/admin/v1/auth/sessions") return Promise.resolve({ data: { items: state.sessions } });
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
    compatibility.status = { server_capabilities: ["admin_account_self_service"] };
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
});

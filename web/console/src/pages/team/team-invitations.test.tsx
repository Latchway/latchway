import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true, status: { server_capabilities: ["admin_invitations", "admin_application_roles"] } }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { administrator: { email: "owner@example.test", enabled: true, id: "adm_0123456789abcdef" }, capabilities: ["manage_owners"], expires_at: null, memberships: [{ organization_id: "org_0123456789abcdef", role: "owner" }], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));

import { instant, mutationsOf, renderWithWorkspace } from "../../test/workspace-harness";
import { MembersPage } from "./team-pages";

type Options = { body?: Record<string, unknown>; method?: string } | undefined;

const INVITATIONS = "/admin/v1/organizations/org_0123456789abcdef/invitations";
const owner = { created_at: instant, display_name: "Owner One", email: "owner@example.test", id: "adm_0123456789abcdef", membership_id: "amb_0123456789abcdef", organization_id: "org_0123456789abcdef", password_reset_required: false, role: "owner", status: "active", updated_at: instant };
const invitation = (id: string, email: string, status: string, extra: Record<string, unknown> = {}) => ({ created_at: instant, email, email_status: "not_requested", expires_at: "2026-10-15T12:00:00Z", id, invited_by: "Owner One", role: "operator", status, ...extra });
const viewerMember = { ...owner, display_name: "Vee Viewer", email: "vee@example.test", id: "adm_1123456789abcdef", membership_id: "amb_1123456789abcdef", role: "viewer" };
const app = (id: string, name: string) => ({ created_at: instant, display_name: name, id, organization_id: "org_0123456789abcdef", slug: name.toLowerCase(), status: "active" });
let grants: Array<{ admin_user_id: string; application_id: string; created_at: string; granted_by: string; role: string; updated_at: string }> = [];
const LINK = "https://console.example.test/invitation#lwinv_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function server(emailDelivery: boolean) {
  const state = { items: [invitation("ain_0123456789abcdef", "pending@example.test", "pending"), invitation("ain_1123456789abcdef", "done@example.test", "accepted")] };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    const method = options?.method ?? "GET";
    if (path.startsWith("/admin/v1/administrators?")) return Promise.resolve({ data: { items: [owner, viewerMember], page: { has_more: false } } });
    if (path === "/admin/v1/application-roles") return Promise.resolve({ data: { items: grants } });
    if (path.startsWith("/admin/v1/applications?")) return Promise.resolve({ data: { items: [app("app_0123456789abcdef", "Mobile"), app("app_1123456789abcdef", "Web")], page: { has_more: false } } });
    if (path.includes("/application-roles/") && method === "PUT") {
      grants = [...grants.filter((grant) => !path.endsWith(grant.application_id)), { admin_user_id: viewerMember.id, application_id: path.split("/").at(-1) ?? "", created_at: instant, granted_by: "Owner One", role: String(options?.body?.role), updated_at: instant }];
      return Promise.resolve({ data: grants.at(-1) });
    }
    if (path.includes("/application-roles/") && method === "DELETE") {
      grants = grants.filter((grant) => !path.endsWith(grant.application_id));
      return Promise.resolve({ data: undefined });
    }
    if (path.startsWith("/admin/v1/admin-sessions?")) return Promise.resolve({ data: { items: [], page: { has_more: false } } });
    if (path === INVITATIONS && method === "GET") return Promise.resolve({ data: { email_delivery: emailDelivery, items: state.items } });
    if (path === INVITATIONS && method === "POST") {
      const created = invitation("ain_2123456789abcdef", String(options?.body?.email), "pending", { email_status: options?.body?.send_email ? "sent" : "not_requested", role: options?.body?.role });
      state.items = [created, ...state.items];
      return Promise.resolve({ data: { invitation: created, url: LINK } });
    }
    if (path.endsWith("/renew") && method === "POST") return Promise.resolve({ data: { invitation: state.items[0], url: LINK.replace("AAAA", "BBBB") } });
    if (path.endsWith("/revoke") && method === "POST") {
      state.items = state.items.map((item) => (path.includes(item.id) ? { ...item, status: "revoked" } : item));
      return Promise.resolve({ data: state.items.find((item) => path.includes(item.id)) });
    }
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
  return state;
}

describe("Invitations", () => {
  beforeEach(() => {
    adminRequestMock.mockReset();
    compatibility.mutationAllowed = true;
    grants = [];
  });

  it("raises a member's role in one application and lowers it back", async () => {
    const user = userEvent.setup();
    server(false);
    renderWithWorkspace(<MembersPage />);
    await user.click(await screen.findByText("Vee Viewer"));
    const mobile = await screen.findByRole("combobox", { name: "Role in Mobile" });
    expect(within(mobile).getAllByRole("option").map((option) => option.textContent)).toEqual(["Viewer (organization role)", "Operator", "Admin"]);
    await user.selectOptions(mobile, "Admin");
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["PUT /admin/v1/administrators/adm_1123456789abcdef/application-roles/app_0123456789abcdef"]));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Role in Mobile" })).toHaveValue("admin"));
    expect(screen.getByRole("combobox", { name: "Role in Web" })).toHaveValue("");
    await user.selectOptions(screen.getByRole("combobox", { name: "Role in Mobile" }), "Viewer (organization role)");
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toContain("DELETE /admin/v1/administrators/adm_1123456789abcdef/application-roles/app_0123456789abcdef"));
  });

  it("invites by email and shows the link once", async () => {
    const user = userEvent.setup();
    server(true);
    renderWithWorkspace(<MembersPage />);
    await user.click(await screen.findByRole("button", { name: "Invite Member" }));
    await user.type(screen.getByLabelText("Email"), "new@example.test");
    await user.click(screen.getByRole("radio", { name: /Operator/ }));
    expect(screen.getByLabelText("Email the invitation link")).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Create Invitation" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual([`POST ${INVITATIONS}`]));
    const body = (adminRequestMock.mock.calls.find(([path, , init]) => path === INVITATIONS && (init as Options)?.method === "POST")?.[2] as Options)?.body;
    expect(body).toEqual({ email: "new@example.test", role: "operator", send_email: true });
    const reveal = await screen.findByRole("alertdialog", { name: "Invitation for new@example.test" });
    expect(within(reveal).getByText(LINK)).toBeInTheDocument();
    expect(within(reveal).getByText(/also emailed to new@example.test/)).toBeInTheDocument();
    await user.click(within(reveal).getByRole("button", { name: "Done" }));
    expect(screen.queryByText(LINK)).not.toBeInTheDocument();
  });

  it("offers a link to share when the server can't email", async () => {
    const user = userEvent.setup();
    server(false);
    renderWithWorkspace(<MembersPage />);
    await user.click(await screen.findByRole("button", { name: "Invite Member" }));
    expect(screen.queryByLabelText("Email the invitation link")).not.toBeInTheDocument();
    expect(screen.getByText(/doesn't send email; you'll get a link to share/)).toBeInTheDocument();
  });

  it("replaces a link and revokes an open invitation", async () => {
    const user = userEvent.setup();
    server(false);
    renderWithWorkspace(<MembersPage />);
    expect(await screen.findByText("pending@example.test")).toBeInTheDocument();
    expect(screen.getByText("done@example.test")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "New Link" }));
    expect(await screen.findByRole("alertdialog", { name: "Invitation for pending@example.test" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Done" }));
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await user.click(within(screen.getByRole("alertdialog", { name: "Revoke this invitation?" })).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual([`POST ${INVITATIONS}/ain_0123456789abcdef/renew`, `POST ${INVITATIONS}/ain_0123456789abcdef/revoke`]));
    expect(await screen.findByText("Revoked")).toBeInTheDocument();
  });

  it("lists invitations without changes when the console is read-only", async () => {
    compatibility.mutationAllowed = false;
    server(false);
    renderWithWorkspace(<MembersPage />);
    expect(await screen.findByText("pending@example.test")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New Link" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Invite Member" })).toBeDisabled();
  });
});

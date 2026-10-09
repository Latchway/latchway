import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility, session } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true },
  session: { capabilities: ["manage_owners", "activate_configuration", "manage_secrets", "inspect_users", "run_self_tests", "revoke_installations"], role: "owner" }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { administrator: { email: "owner@example.test", enabled: true, id: "adm_0123456789abcdef" }, capabilities: session.capabilities, expires_at: null, memberships: [{ organization_id: "org_0123456789abcdef", role: session.role }], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));

import { instant, mutationsOf, renderWithWorkspace } from "../../test/workspace-harness";
import { MembersPage, SessionsPage, TokensPage } from "./team-pages";

type Options = { body?: Record<string, unknown>; method?: string } | undefined;

const owner = { created_at: instant, display_name: "Owner One", email: "owner@example.test", id: "adm_0123456789abcdef", membership_id: "amb_0123456789abcdef", organization_id: "org_0123456789abcdef", password_reset_required: false, role: "owner", status: "active", updated_at: instant };
const jo = { ...owner, display_name: "Jo Admin", email: "jo@example.test", id: "adm_1123456789abcdef", membership_id: "amb_1123456789abcdef", role: "admin" };
const sessionOf = (id: string, admin: typeof owner, current = false, status = "active") => ({ administrator: { email: admin.email, id: admin.id }, created_at: instant, current, device_summary: "Chrome on macOS", expires_at: "2026-08-29T12:00:00Z", id, last_seen_at: instant, status });
const token = { created_at: instant, expires_at: new Date(Date.now() + 2.5 * 86_400_000).toISOString(), id: "tok_0123456789abcdef", name: "grafana-reader", revoked: false, scopes: ["inspect_users"] };

function server() {
  const state = { members: [owner, jo], sessions: [sessionOf("asn_0123456789abcdef", owner, true), sessionOf("asn_1123456789abcdef", jo), sessionOf("asn_2123456789abcdef", jo), sessionOf("asn_3123456789abcdef", jo, false, "revoked")], tokens: [token] };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    const method = options?.method ?? "GET";
    if (path.startsWith("/admin/v1/administrators?")) return Promise.resolve({ data: { items: state.members, page: { has_more: false } } });
    if (path.startsWith("/admin/v1/admin-sessions?")) return Promise.resolve({ data: { items: state.sessions, page: { has_more: false } } });
    if (path === "/admin/v1/administrators" && method === "POST") return Promise.resolve({ data: { ...jo, display_name: options?.body?.display_name, email: options?.body?.email, id: "adm_2123456789abcdef", password_reset_required: true, role: options?.body?.role } });
    const roleMatch = /^\/admin\/v1\/administrators\/(adm_[A-Za-z0-9]+)\/role$/.exec(path);
    if (roleMatch && method === "PUT") { state.members = state.members.map((member) => (member.id === roleMatch[1] ? { ...member, role: String(options?.body?.role) } : member)); return Promise.resolve({ data: state.members.find((member) => member.id === roleMatch[1]) }); }
    const revoke = /^\/admin\/v1\/admin-sessions\/(asn_[A-Za-z0-9]+)\/revoke$/.exec(path);
    if (revoke && method === "POST") { state.sessions = state.sessions.map((item) => (item.id === revoke[1] ? { ...item, status: "revoked" } : item)); return Promise.resolve({ data: undefined }); }
    if (path === "/admin/v1/api-tokens" && method === "GET") return Promise.resolve({ data: { items: state.tokens } });
    if (path === "/admin/v1/api-tokens?scope=organization" && method === "GET") return Promise.resolve({ data: { items: [...state.tokens.map((item) => ({ ...item, administrator: { email: owner.email, id: owner.id } })), { ...token, administrator: { email: jo.email, id: jo.id }, id: "tok_9123456789abcdef", last_used_at: instant, name: "jo-ci" }] } });
    if (path === "/admin/v1/api-tokens" && method === "POST") {
      const created = { created_at: instant, ...(options?.body?.expires_at ? { expires_at: options.body.expires_at } : {}), id: `tok_${state.tokens.length + 1}123456789abcdef`, name: options?.body?.name, revoked: false, scopes: options?.body?.scopes };
      state.tokens = [...state.tokens, created as typeof token];
      return Promise.resolve({ data: { metadata: created, token: "lwt_live_secret_value_that_is_long_enough_123456" } });
    }
    const deleted = /^\/admin\/v1\/api-tokens\/(tok_[A-Za-z0-9]+)$/.exec(path);
    if (deleted && method === "DELETE") { state.tokens = state.tokens.map((item) => (item.id === deleted[1] ? { ...item, revoked: true } : item)); return Promise.resolve({ data: undefined }); }
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
  return state;
}

beforeEach(() => {
  adminRequestMock.mockReset();
  compatibility.mutationAllowed = true;
  session.capabilities = ["manage_owners", "activate_configuration", "manage_secrets", "inspect_users", "run_self_tests", "revoke_installations"];
  session.role = "owner";
});

describe("Members", () => {
  it("adds a member with a password that never enters state and is cleared before the request settles", async () => {
    const user = userEvent.setup();
    server();
    let fieldDuringRequest: string | undefined;
    const base = adminRequestMock.getMockImplementation();
    adminRequestMock.mockImplementation((path: string, schema: unknown, options: Options) => {
      if (path === "/admin/v1/administrators" && options?.method === "POST") fieldDuringRequest = (document.getElementById("member-password") as HTMLInputElement).value;
      return base?.(path, schema, options);
    });
    renderWithWorkspace(<MembersPage />);
    await user.click(await screen.findByRole("button", { name: "Add Member" }));
    const drawer = screen.getByRole("complementary", { name: "Add member" });
    await user.type(within(drawer).getByLabelText("Name"), "Sam");
    await user.type(within(drawer).getByLabelText("Email"), "JO@example.test");
    expect(within(drawer).getAllByText("Someone on the team already uses this email.").length).toBeGreaterThan(0);
    await user.clear(within(drawer).getByLabelText("Email"));
    await user.type(within(drawer).getByLabelText("Email"), "sam@example.test");
    await user.click(within(drawer).getByRole("radio", { name: /Operator/ }));
    await user.click(within(drawer).getByRole("button", { name: "Generate" }));
    expect((within(drawer).getByLabelText("First password") as HTMLInputElement).value).toHaveLength(20);
    expect(within(drawer).getByRole("button", { name: "Add Member" })).toBeDisabled();
    await user.click(within(drawer).getByRole("checkbox"));
    await user.click(within(drawer).getByRole("button", { name: "Add Member" }));

    expect(await screen.findByText(/Sam was added as Operator/)).toBeInTheDocument();
    const call = adminRequestMock.mock.calls.find(([path, , options]) => path === "/admin/v1/administrators" && (options as Options)?.method === "POST");
    expect((call?.[2] as Options)?.body).toMatchObject({ display_name: "Sam", email: "sam@example.test", role: "operator" });
    expect(String((call?.[2] as Options)?.body?.password)).toHaveLength(20);
    expect(fieldDuringRequest).toBe("");
  });

  it("explains what a role change removes and needs the typed email before saving", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<MembersPage />, { initial: { member: "adm_1123456789abcdef" } });
    const drawer = await screen.findByRole("complementary", { name: "Jo Admin" });
    await user.click(within(drawer).getByRole("radio", { name: /Viewer/ }));
    expect(drawer).toHaveTextContent("Loses: Change and publish configuration");
    expect(drawer).toHaveTextContent("Loses: Run self-tests");
    await user.click(within(drawer).getByRole("button", { name: "Change to Viewer" }));
    const dialog = screen.getByRole("alertdialog", { name: "Change Jo Admin to Viewer?" });
    const confirm = within(dialog).getByRole("button", { name: "Change to Viewer" });
    await user.type(within(dialog).getByLabelText(/to confirm/), "jo@example.test");
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(confirm);
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toContain("PUT /admin/v1/administrators/adm_1123456789abcdef/role"));
    expect(adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/role"))?.[2]).toMatchObject({ body: { role: "viewer" } });
  });

  it("keeps the last active owner an owner and names why", async () => {
    server();
    renderWithWorkspace(<MembersPage />, { initial: { member: "adm_0123456789abcdef" } });
    const drawer = await screen.findByRole("complementary", { name: "Owner One" });
    expect(within(drawer).getByRole("radio", { name: /Admin/ })).toBeDisabled();
    expect(drawer).toHaveTextContent("Add another owner first");
    expect(within(drawer).getByRole("button", { name: "Disable" })).toBeDisabled();
  });

  it("asks a non-owner to find an owner instead of loading the team", async () => {
    session.capabilities = ["inspect_users"];
    session.role = "viewer";
    server();
    renderWithWorkspace(<MembersPage />);
    expect(await screen.findByText("Owner role needed")).toBeInTheDocument();
    expect(adminRequestMock).not.toHaveBeenCalled();
  });
});

describe("Two-factor", () => {
  it("shows who has two-factor on and lets an owner reset it after confirming", async () => {
    const user = userEvent.setup();
    server();
    const base = adminRequestMock.getMockImplementation();
    adminRequestMock.mockImplementation((path: string, schema: unknown, options: Options) => {
      if (path.startsWith("/admin/v1/administrators?")) return Promise.resolve({ data: { items: [owner, { ...jo, two_factor_enabled: true }], page: { has_more: false } } });
      if (path === `/admin/v1/administrators/${jo.id}/reset-two-factor`) return Promise.resolve({ data: { ...jo, two_factor_enabled: false } });
      return base?.(path, schema, options);
    });
    renderWithWorkspace(<MembersPage />);
    const row = (await screen.findByText("Jo Admin")).closest("tr") as HTMLElement;
    expect(within(row).getByText("On")).toBeInTheDocument();
    await user.click(row);
    const drawer = await screen.findByRole("complementary", { name: "Jo Admin" });
    await user.click(within(drawer).getByRole("button", { name: "Reset Two-Factor" }));
    const dialog = screen.getByRole("alertdialog", { name: "Reset Jo Admin's two-factor sign-in?" });
    expect(dialog).toHaveTextContent("confirming who's asking");
    await user.click(within(dialog).getByRole("button", { name: "Reset Two-Factor" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual([`POST /admin/v1/administrators/${jo.id}/reset-two-factor`]));
  });
});

describe("API tokens", () => {
  it("reveals a new token once, unlocks Done only after it's saved, and never re-shows it after a read-only spell", async () => {
    const user = userEvent.setup();
    server();
    const view = renderWithWorkspace(<TokensPage />);
    expect(await screen.findByText("grafana-reader expires in 3 days.", { exact: false })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create Token" }));
    const drawer = screen.getByRole("complementary", { name: "Create token" });
    await user.click(within(drawer).getByRole("button", { name: "CI deploys" }));
    expect(within(drawer).getByLabelText("Name")).toHaveValue("ci-deploy");
    await user.click(within(drawer).getByRole("button", { name: "Create Token" }));
    const reveal = await screen.findByRole("alertdialog", { name: "Save ci-deploy now" });
    expect(within(reveal).getByLabelText("Token")).toHaveValue("lwt_live_secret_value_that_is_long_enough_123456");
    expect(within(reveal).queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
    expect(within(reveal).getByRole("button", { name: "Done" })).toBeDisabled();
    const body = (adminRequestMock.mock.calls.find(([path, , options]) => path === "/admin/v1/api-tokens" && (options as Options)?.method === "POST")?.[2] as Options)?.body;
    expect(body).toMatchObject({ name: "ci-deploy", scopes: ["activate_configuration", "inspect_users"] });
    expect(Math.round((Date.parse(String(body?.expires_at)) - Date.now()) / 86_400_000)).toBe(90);

    compatibility.mutationAllowed = false;
    view.rerenderPage(<TokensPage />);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    compatibility.mutationAllowed = true;
    view.rerenderPage(<TokensPage />);
    expect(screen.queryByText(/lwt_live_secret/)).not.toBeInTheDocument();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("replaces a token with the same name and scopes, then lets the old one live until revoked", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<TokensPage />);
    await user.click(await screen.findByRole("button", { name: "Replace grafana-reader" }));
    const reveal = await screen.findByRole("alertdialog", { name: "Save grafana-reader now" });
    await user.click(within(reveal).getByRole("checkbox"));
    await user.click(within(reveal).getByRole("button", { name: "Done" }));
    const ask = screen.getByRole("alertdialog", { name: "Revoke the old grafana-reader now?" });
    await user.click(within(ask).getByRole("button", { name: "Later" }));
    expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/api-tokens"]);
    expect(adminRequestMock.mock.calls.find(([, , options]) => (options as Options)?.method === "POST")?.[2]).toMatchObject({ body: { name: "grafana-reader", scopes: ["inspect_users"] } });
  });

  it("lets an owner see everyone's tokens with their owner and last use, and replace only their own", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<TokensPage />);
    expect(await screen.findByText("Never")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Everyone" }));
    const row = (await screen.findByText("jo-ci", { selector: ".lw-mono" })).closest("tr") as HTMLElement;
    expect(within(row).getByText(jo.email)).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: /Replace/ })).not.toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    expect(within(row).queryByText("Never")).not.toBeInTheDocument();
  });

  it("hides the everyone view from non-owners", async () => {
    session.capabilities = ["inspect_users"];
    server();
    renderWithWorkspace(<TokensPage />);
    expect(await screen.findByText("grafana-reader", { selector: ".lw-mono" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Everyone" })).not.toBeInTheDocument();
    session.capabilities = ["manage_owners", "activate_configuration", "manage_secrets", "inspect_users", "run_self_tests", "revoke_installations"];
  });

  it("revokes only after the token's name is typed", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<TokensPage />);
    const row = (await screen.findByText("grafana-reader", { selector: ".lw-mono" })).closest("tr") as HTMLElement;
    await user.click(within(row).getByRole("button", { name: "Revoke" }));
    const dialog = screen.getByRole("alertdialog", { name: "Revoke grafana-reader?" });
    expect(dialog).toHaveTextContent("can't be undone");
    expect(within(dialog).getByRole("button", { name: "Revoke" })).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/to confirm/), { target: { value: "grafana-reader" } });
    await user.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["DELETE /admin/v1/api-tokens/tok_0123456789abcdef"]));
    expect(await screen.findByText("Revoked")).toBeInTheDocument();
  });
});

describe("Sessions", () => {
  it("signs out every other active session and keeps yours", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<SessionsPage />);
    expect(await screen.findByText("This session")).toBeInTheDocument();
    expect(screen.getAllByText("Chrome on macOS").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Sign Out Everyone Else" }));
    const dialog = screen.getByRole("alertdialog", { name: "Sign out everyone else?" });
    expect(dialog).toHaveTextContent("2 sessions for 1 person end now");
    expect(dialog).toHaveTextContent("API tokens aren't affected");
    await act(async () => { await user.click(within(dialog).getByRole("button", { name: "Sign Out 2 Sessions" })); });
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/admin-sessions/asn_1123456789abcdef/revoke", "POST /admin/v1/admin-sessions/asn_2123456789abcdef/revoke"]));
    expect(await screen.findByText("Signed out 2 sessions.")).toBeInTheDocument();
  });
});

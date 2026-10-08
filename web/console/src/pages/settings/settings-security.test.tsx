import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true, status: { contract_version: "1.1.0", database_schema_version: "35", mutation_ready: true, protocol_versions: [1, 2, 3], ready: true, role: "all", server_capabilities: ["admin_two_factor"], server_version: "1.2.0" } }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/session")>()),
  useConsoleSession: () => ({ data: { mode: "configured", session: { administrator: { email: "owner@example.test", enabled: true, id: "adm_0123456789abcdef" }, capabilities: ["manage_owners"], expires_at: null, memberships: [{ organization_id: "org_0123456789abcdef", role: "owner" }], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: React.ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { instant, mutationsOf, renderWithWorkspace } from "../../test/workspace-harness";
import { GeneralSettingsPage } from "./settings-pages";

type Options = { body?: Record<string, unknown>; method?: string } | undefined;

const member = (id: string, name: string, twoFactor: boolean) => ({ created_at: instant, display_name: name, email: `${name.toLowerCase()}@example.test`, id, membership_id: id.replace("adm_", "amb_"), organization_id: "org_0123456789abcdef", password_reset_required: false, role: "admin", status: "active", two_factor_enabled: twoFactor, updated_at: instant });

describe("Sign-in security", () => {
  beforeEach(() => {
    adminRequestMock.mockReset();
  });

  it("requires two-factor after showing who doesn't have it yet", async () => {
    const user = userEvent.setup();
    let required = false;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
      if (path === "/admin/v1/auth/two-factor") return Promise.resolve({ data: { enabled: true, passkeys: 0, recovery_codes_remaining: 10, required_by_organization: required, totp_enabled: true } });
      if (path.startsWith("/admin/v1/administrators?")) return Promise.resolve({ data: { items: [member("adm_0123456789abcdef", "Owner", true), member("adm_1123456789abcdef", "Sam", false)], page: { has_more: false } } });
      if (path === "/admin/v1/organizations/org_0123456789abcdef/two-factor-requirement" && options?.method === "PUT") { required = Boolean(options.body?.required); return Promise.resolve({ data: { required } }); }
      if (path === "/admin/v1/system") return Promise.resolve({ data: compatibility.status });
      if (path === "/admin/v1/system/doctor") return Promise.reject(new Error("unavailable"));
      if (path.startsWith("/admin/v1/organizations")) return Promise.resolve({ data: { items: [{ created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" }], page: { has_more: false } } });
      return Promise.reject(new Error(`unexpected ${options?.method ?? "GET"} ${path}`));
    });
    renderWithWorkspace(<GeneralSettingsPage />);
    expect(await screen.findByText("1 active member doesn't have it on yet.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Require Two-Factor" }));
    const dialog = screen.getByRole("alertdialog", { name: "Require two-factor sign-in?" });
    expect(within(dialog).getByText(/Sam · sam@example.test/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Require Two-Factor" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["PUT /admin/v1/organizations/org_0123456789abcdef/two-factor-requirement"]));
    expect(await screen.findByRole("button", { name: "Stop Requiring Two-Factor" })).toBeInTheDocument();
  });
});

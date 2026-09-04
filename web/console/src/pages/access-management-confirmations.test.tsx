import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({
    data: {
      mode: "configured",
      session: {
        capabilities: ["inspect_users", "manage_owners", "run_self_tests"],
        organization_id: "org_0123456789abcdef"
      }
    }
  })
}));
vi.mock("../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => ({ mutationAllowed: true })
}));

import { AdministratorsPage } from "./administrators-page";
import { APITokensPage } from "./api-tokens-page";

const instant = "2026-08-29T00:00:00Z";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => { resolve = promiseResolve; });
  return { promise, resolve };
}

afterEach(cleanup);

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("team and token operational confirmations", () => {
  it("clears an initial administrator password before the create request settles", async () => {
    const created = {
      created_at: instant,
      display_name: "Operator",
      email: "operator@example.test",
      id: "adm_0123456789abcdef",
      membership_id: "amb_0123456789abcdef",
      organization_id: "org_0123456789abcdef",
      password_reset_required: true,
      role: "viewer",
      status: "active",
      updated_at: instant
    };
    const pending = deferred<{ data: typeof created }>();
    adminRequestMock.mockReturnValueOnce(pending.promise);
    const user = userEvent.setup();
    render(<AdministratorsPage />);
    await user.type(screen.getByLabelText("Email"), created.email);
    await user.type(screen.getByLabelText("Display name"), created.display_name);
    const password = screen.getByLabelText(/^Initial password/);
    await user.type(password, "temporary-secret-123");
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    expect(password).toHaveValue("");
    expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/administrators", expect.anything(), {
      body: { display_name: created.display_name, email: created.email, password: "temporary-secret-123", role: "viewer" },
      method: "POST"
    });
    await act(async () => pending.resolve({ data: created }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Create administrator" })).toBeEnabled());
  });

  it("clears a replacement administrator password before the reset request settles", async () => {
    const administrator = {
      created_at: instant,
      display_name: "Operator",
      email: "operator@example.test",
      id: "adm_0123456789abcdef",
      membership_id: "amb_0123456789abcdef",
      organization_id: "org_0123456789abcdef",
      password_reset_required: false,
      role: "operator",
      status: "active",
      updated_at: instant
    };
    const pending = deferred<{ data: typeof administrator }>();
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/administrators?page_size=50")) return Promise.resolve({ data: { items: [administrator], page: { has_more: false } } });
      if (path === `/admin/v1/administrators/${administrator.id}/reset-password`) return pending.promise;
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    render(<AdministratorsPage />);
    await user.click(screen.getByRole("button", { name: "Load administrators" }));
    await user.click(await screen.findByRole("button", { name: "Reset password" }));
    const password = screen.getByLabelText("Replacement password");
    await user.type(password, "replacement-secret-123");
    await user.click(screen.getByRole("button", { name: "Reset and revoke credentials" }));

    expect(password).toHaveValue("");
    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/administrators/${administrator.id}/reset-password`,
      expect.anything(),
      { body: { password: "replacement-secret-123" }, method: "POST" }
    );
    await act(async () => pending.resolve({ data: administrator }));
    await waitFor(() => expect(screen.queryByLabelText("Replacement password")).not.toBeInTheDocument());
  });

  it("explains administrator disable, reversal, and credential non-restoration before mutation", async () => {
    const administrator = {
      created_at: instant,
      display_name: "Operator",
      email: "operator@example.test",
      id: "adm_0123456789abcdef",
      membership_id: "amb_0123456789abcdef",
      organization_id: "org_0123456789abcdef",
      password_reset_required: false,
      role: "operator",
      status: "active",
      updated_at: instant
    };
    adminRequestMock.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.startsWith("/admin/v1/administrators?page_size=50")) return { data: { items: [administrator], page: { has_more: false } } };
      if (path === `/admin/v1/administrators/${administrator.id}/disable` && options?.method === "POST") {
        return { data: { ...administrator, disabled_at: instant, status: "disabled" } };
      }
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    render(<AdministratorsPage />);
    await user.click(screen.getByRole("button", { name: "Load administrators" }));
    await user.click(await screen.findByRole("button", { name: "Review disable" }));

    expect(screen.getByRole("heading", { name: "Disable operator@example.test?" })).toBeInTheDocument();
    expect(screen.getByText(/An owner can enable the organization membership later/)).toBeInTheDocument();
    expect(screen.getByText(/does not restore revoked sessions or API tokens/)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: "Disable and revoke credentials" });
    expect(confirm).toBeDisabled();
    expect(adminRequestMock).not.toHaveBeenCalledWith(expect.stringContaining("/disable"), expect.anything(), expect.anything());
    await user.click(screen.getByLabelText(/immediately removes organization access/i));
    await user.click(confirm);

    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/administrators/${administrator.id}/disable`, expect.anything(), { method: "POST" });
    expect(await screen.findByRole("button", { name: "Enable" })).toBeInTheDocument();
  });

  it("explains terminal API-token revocation before deleting token metadata", async () => {
    const token = {
      created_at: instant,
      id: "tok_0123456789abcdef",
      name: "mobile-ci",
      revoked: false,
      scopes: ["inspect_users", "run_self_tests"]
    };
    adminRequestMock.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string }) => {
      if (path === "/admin/v1/api-tokens" && !options) return { data: { items: [token] } };
      if (path === `/admin/v1/api-tokens/${token.id}` && options?.method === "DELETE") return { data: undefined };
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    render(<APITokensPage />);
    await user.click(screen.getByRole("button", { name: "Load API tokens" }));
    await user.click(await screen.findByRole("button", { name: "Review revoke" }));

    expect(screen.getByRole("heading", { name: "Revoke mobile-ci?" })).toBeInTheDocument();
    expect(screen.getByText(/API-token revocation is terminal/)).toBeInTheDocument();
    expect(screen.getByText(/cannot recover or reactivate this token/)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: "Revoke API token" });
    expect(confirm).toBeDisabled();
    expect(adminRequestMock).not.toHaveBeenCalledWith(expect.stringContaining(token.id), expect.anything(), expect.anything());
    await user.click(screen.getByLabelText(/immediately and permanently revokes this token/i));
    await user.click(confirm);

    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/api-tokens/${token.id}`, expect.anything(), { method: "DELETE" });
    expect(await screen.findByText("Revoked")).toBeInTheDocument();
  });
});

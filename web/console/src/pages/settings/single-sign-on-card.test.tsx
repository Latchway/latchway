import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { mutationAllowed: true }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));

import { instant, mutationsOf, renderWithWorkspace } from "../../test/workspace-harness";
import { SingleSignOnCard } from "./single-sign-on-card";

type Options = { body?: Record<string, unknown>; method?: string } | undefined;

const PATH = "/admin/v1/organizations/org_0123456789abcdef/sso";
const REDIRECT = "https://console.example.test/admin/v1/auth/sso/callback";

const PROVIDER = {
  allowed_email_domains: ["example.com"], authorization_endpoint: "https://login.example.com/authorize", client_id: "latchway",
  created_at: instant, enabled: true, issuer: "https://login.example.com", jwks_uri: "https://login.example.com/jwks",
  provision_role: null, require_sso: false, token_endpoint: "https://login.example.com/token", updated_at: instant
};

function server(initial: typeof PROVIDER | null) {
  const state = { provider: initial };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    if (path === PATH && options?.method === "PUT") {
      const body = options.body ?? {};
      state.provider = { ...PROVIDER, ...body, client_secret: undefined } as unknown as typeof PROVIDER;
      return Promise.resolve({ data: { provider: state.provider, redirect_uri: REDIRECT } });
    }
    if (path === PATH && options?.method === "DELETE") {
      state.provider = null;
      return Promise.resolve({ data: undefined });
    }
    if (path === PATH) return Promise.resolve({ data: { provider: state.provider, redirect_uri: REDIRECT } });
    return Promise.reject(new Error(`unexpected ${options?.method ?? "GET"} ${path}`));
  });
  return state;
}

function bodyOf(method: string): Record<string, unknown> | undefined {
  return (adminRequestMock.mock.calls.find(([path, , init]) => path === PATH && (init as Options)?.method === method)?.[2] as Options)?.body;
}

describe("Single sign-on settings", () => {
  beforeEach(() => {
    adminRequestMock.mockReset();
    compatibility.mutationAllowed = true;
  });

  it("shows the redirect URI and sets up a provider with a write-only secret", async () => {
    const user = userEvent.setup();
    server(null);
    renderWithWorkspace(<SingleSignOnCard organizationID="org_0123456789abcdef" />);
    expect(await screen.findByText(REDIRECT)).toBeInTheDocument();
    expect(screen.getByText("Not set up")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Issuer"), "https://login.example.com");
    await user.type(screen.getByLabelText("Client ID"), "latchway");
    await user.click(screen.getByRole("button", { name: "Set Up Single Sign-On" }));
    expect(screen.getByText("Client secret needed")).toBeInTheDocument();
    expect(mutationsOf(adminRequestMock)).toEqual([]);
    await user.type(screen.getByLabelText("Client secret"), "test-only-client-secret");
    await user.type(screen.getByLabelText("Allowed email domains"), "example.com, Example.org");
    await user.selectOptions(screen.getByLabelText("People without an account"), "Create as Viewer");
    await user.click(screen.getByRole("button", { name: "Set Up Single Sign-On" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual([`PUT ${PATH}`]));
    expect(bodyOf("PUT")).toEqual({
      allowed_email_domains: ["example.com", "Example.org"], client_id: "latchway", client_secret: "test-only-client-secret",
      enabled: true, issuer: "https://login.example.com", provision_role: "viewer", require_sso: false
    });
    expect(screen.getByLabelText("Client secret")).toHaveValue("");
    expect(await screen.findByText("Saved.")).toBeInTheDocument();
    expect(screen.getByText("https://login.example.com/token")).toBeInTheDocument();
  });

  it("keeps the stored secret and confirms before requiring single sign-on", async () => {
    const user = userEvent.setup();
    server(PROVIDER);
    renderWithWorkspace(<SingleSignOnCard organizationID="org_0123456789abcdef" />);
    expect(await screen.findByDisplayValue("https://login.example.com")).toBeInTheDocument();
    await user.click(screen.getByLabelText("Require it for members other than owners"));
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    const dialog = screen.getByRole("alertdialog", { name: "Save single sign-on changes?" });
    expect(within(dialog).getByText(/password and passkey sessions end now/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual([`PUT ${PATH}`]));
    expect(bodyOf("PUT")).not.toHaveProperty("client_secret");
    expect(bodyOf("PUT")?.require_sso).toBe(true);
    expect(await screen.findByText("Required")).toBeInTheDocument();
  });

  it("removes the provider after confirmation", async () => {
    const user = userEvent.setup();
    server(PROVIDER);
    renderWithWorkspace(<SingleSignOnCard organizationID="org_0123456789abcdef" />);
    await user.click(await screen.findByRole("button", { name: "Remove" }));
    await user.click(within(screen.getByRole("alertdialog", { name: "Remove single sign-on?" })).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual([`DELETE ${PATH}`]));
    expect(await screen.findByText("Not set up")).toBeInTheDocument();
  });

  it("closes the form, secret included, when the console is read-only", async () => {
    compatibility.mutationAllowed = false;
    server(PROVIDER);
    renderWithWorkspace(<SingleSignOnCard organizationID="org_0123456789abcdef" />);
    expect(await screen.findByText("Single sign-on changes are unavailable.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Client secret")).not.toBeInTheDocument();
    expect(screen.getByText("https://login.example.com/token")).toBeInTheDocument();
  });
});

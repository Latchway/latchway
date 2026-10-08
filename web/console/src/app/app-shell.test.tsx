import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { forgetConsoleSession, SESSION_ENDED_EVENT } from "../api/session";
import { rememberSignedOutEmail } from "./auth/auth-memory";

import { commands, LEGACY_REDIRECT_PATHS } from "./navigation";
import { createAppRouter } from "./router";

const adminSession = {
  administrator: {
    email: "owner@example.test",
    enabled: true,
    id: "adm_0123456789abcdef"
  },
  capabilities: ["secrets.manage"],
  expires_at: "2026-08-28T10:30:00Z",
  memberships: [
    { organization_id: "org_0123456789abcdef", role: "owner" }
  ],
  organization_id: "org_0123456789abcdef"
};

function requestURL(input: RequestInfo | URL): string {
  if (typeof input === "string") {
    return input;
  }
  return input instanceof URL ? input.toString() : input.url;
}

function signedOutResponse() {
  return new Response(
    JSON.stringify({
      code: "authentication_required",
      detail: "An administrator session is required.",
      request_id: "request_test_1234",
      retryable: false,
      status: 401,
      title: "Authentication required",
      type: "https://docs.latchway.dev/errors/authentication-required",
      documentation_url: "https://docs.latchway.dev/errors/authentication-required"
    }),
    {
      headers: { "Content-Type": "application/problem+json" },
      status: 401
    }
  );
}

function healthResponse(url: string): Response | undefined {
  if (url === "/healthz") {
    return new Response("ok", { status: 200 });
  }
  if (url === "/readyz") {
    return new Response(
      JSON.stringify({
        checks: { database: true, signing_key: true },
        status: "ready"
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 }
    );
  }
  return undefined;
}

function renderConsole(initialEntry = "/") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { gcTime: Number.POSITIVE_INFINITY, retry: false }
    }
  });
  const router = createAppRouter({
    history: createMemoryHistory({ initialEntries: [initialEntry] })
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", ...headers }, status });
}

function problemResponse(status: number, code: string, title: string, detail: string, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({
    code,
    detail,
    documentation_url: `https://docs.latchway.dev/errors/${code.replaceAll("_", "-")}`,
    request_id: "request_test_5678",
    retryable: status === 429,
    status,
    title,
    type: `https://docs.latchway.dev/errors/${code.replaceAll("_", "-")}`
  }), { headers: { "Content-Type": "application/problem+json", ...headers }, status });
}

function installSignedOutFetch() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = requestURL(input);
    if (url === "/admin/v1/auth/session") return signedOutResponse();
    return healthResponse(url) ?? new Response("not found", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function installConfiguredFetch() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = requestURL(input);
    if (url === "/admin/v1/auth/session") {
      return new Response(JSON.stringify(adminSession), {
        headers: { "Content-Type": "application/json" },
        status: 200
      });
    }
    return healthResponse(url) ?? new Response("not found", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("AppShell", () => {
  beforeEach(() => {
    forgetConsoleSession();
    rememberSignedOutEmail(undefined);
  });

  it("shows the sign-in screen, not the console, after a session 401", async () => {
    installSignedOutFetch();
    renderConsole();

    expect(await screen.findByRole("heading", { level: 1, name: "Sign in to Latchway" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Primary navigation" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Email address")).toHaveAttribute("autocomplete", "username");
    expect(screen.getByLabelText("Password")).toHaveAttribute("autocomplete", "current-password");
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "password");
    await userEvent.setup().click(screen.getByRole("button", { name: "Show password" }));
    expect(screen.getByRole("button", { name: "Show password" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "text");
    const facts = screen.getByRole("region", { name: "This server" });
    expect(within(facts).getByText(window.location.host)).toBeInTheDocument();
    expect(await within(facts).findByText("Reachable and ready")).toBeInTheDocument();
  });

  it("signs in, avoids browser storage, and clears the password", async () => {
    const user = userEvent.setup();
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    let authenticated = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return authenticated ? json(adminSession) : signedOutResponse();
      if (url === "/admin/v1/auth/login" && init?.method === "POST") {
        authenticated = true;
        return json(adminSession);
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole();

    await screen.findByRole("heading", { name: "Sign in to Latchway" });
    await user.type(screen.getByLabelText("Email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Password"), "test-only-login-password");
    await user.click(screen.getByRole("button", { name: "Sign In" }));

    expect(await screen.findByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    const loginCall = fetchMock.mock.calls.find(([input]) => requestURL(input) === "/admin/v1/auth/login");
    expect(loginCall?.[1]).toEqual(expect.objectContaining({
      body: JSON.stringify({ email: "owner@example.test", password: "test-only-login-password" }),
      credentials: "same-origin",
      method: "POST",
      redirect: "error"
    }));
    expect(storageSpy).not.toHaveBeenCalled();
    expect(screen.queryByDisplayValue("test-only-login-password")).not.toBeInTheDocument();
  });

  it("validates first-run setup all at once and focuses the first problem", async () => {
    const user = userEvent.setup();
    const fetchMock = installSignedOutFetch();
    renderConsole();

    await user.click(await screen.findByRole("button", { name: "Setting up a new server?" }));
    expect(screen.getByRole("heading", { level: 1, name: "Set up Latchway" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Owner password"), "aaaaaaaaaaaa");
    expect(screen.getByText("Strength: Weak")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create First Owner" }));

    expect(screen.getByText("6 fields need attention.")).toBeInTheDocument();
    expect(screen.getByLabelText("One-time bootstrap token")).toHaveFocus();
    expect(screen.getByLabelText("One-time bootstrap token")).toHaveAttribute("aria-invalid", "true");
    expect(fetchMock.mock.calls.map(([input]) => requestURL(input))).not.toContain("/admin/v1/auth/bootstrap");
  });

  it("creates the first owner, then asks for the bootstrap token to be removed before entering", async () => {
    const user = userEvent.setup();
    let authenticated = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return authenticated ? json(adminSession) : signedOutResponse();
      if (url === "/admin/v1/auth/bootstrap" && init?.method === "POST") {
        authenticated = true;
        return json(adminSession, 201);
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole();

    await user.click(await screen.findByRole("button", { name: "Setting up a new server?" }));
    await user.type(screen.getByLabelText("One-time bootstrap token"), "test-only-bootstrap-token-000000000000");
    await user.type(screen.getByLabelText("Organization name"), "Example Organization");
    expect(screen.getByLabelText("Organization slug")).toHaveValue("example-organization");
    await user.clear(screen.getByLabelText("Organization slug"));
    await user.type(screen.getByLabelText("Organization slug"), "example-org");
    await user.type(screen.getByLabelText("Owner display name"), "Example Owner");
    await user.type(screen.getByLabelText("Owner email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Owner password"), "test-only-owner-password");
    await user.click(screen.getByRole("button", { name: "Create First Owner" }));

    expect(await screen.findByRole("heading", { level: 1, name: "Example Organization is ready" })).toBeInTheDocument();
    const bootstrapCall = fetchMock.mock.calls.find(([input]) => requestURL(input) === "/admin/v1/auth/bootstrap");
    expect(bootstrapCall?.[1]).toEqual(expect.objectContaining({
      body: JSON.stringify({
        bootstrap_token: "test-only-bootstrap-token-000000000000",
        display_name: "Example Owner",
        email: "owner@example.test",
        organization_name: "Example Organization",
        organization_slug: "example-org",
        password: "test-only-owner-password"
      }),
      credentials: "same-origin",
      method: "POST"
    }));
    expect(screen.queryByDisplayValue("test-only-bootstrap-token-000000000000")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Fly.io" }));
    expect(screen.getByText("fly secrets unset LATCHWAY_ADMIN_BOOTSTRAP_TOKEN")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go to the Console" })).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I've removed LATCHWAY_ADMIN_BOOTSTRAP_TOKEN/ }));
    await user.click(screen.getByRole("button", { name: "Go to the Console" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
  });

  it("explains that setup is closed once an owner exists", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return signedOutResponse();
      if (url === "/admin/v1/auth/bootstrap") return problemResponse(409, "bootstrap_disabled", "Bootstrap disabled", "Bootstrap is no longer available.");
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    }));
    renderConsole();

    await user.click(await screen.findByRole("button", { name: "Setting up a new server?" }));
    await user.type(screen.getByLabelText("One-time bootstrap token"), "test-only-bootstrap-token-000000000000");
    await user.type(screen.getByLabelText("Organization name"), "Example");
    await user.type(screen.getByLabelText("Owner display name"), "Owner");
    await user.type(screen.getByLabelText("Owner email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Owner password"), "test-only-owner-password");
    await user.click(screen.getByRole("button", { name: "Create First Owner" }));

    expect(await screen.findByRole("heading", { level: 1, name: "Setup is already done" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Go to Sign In" }));
    expect(screen.getByRole("heading", { level: 1, name: "Sign in to Latchway" })).toBeInTheDocument();
  });

  it("renders validated problem details without exposing extra response fields", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return signedOutResponse();
      if (url === "/admin/v1/auth/login") {
        return new Response(JSON.stringify({
          code: "authentication_required",
          debug: "test-only-login-password",
          detail: "The administrator credentials are invalid.",
          request_id: "request_login_1234",
          retryable: false,
          status: 401,
          title: "Authentication required",
          type: "https://docs.latchway.dev/errors/authentication-required",
          documentation_url: "https://docs.latchway.dev/errors/authentication-required"
        }), { headers: { "Content-Type": "application/problem+json" }, status: 401 });
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    }));
    renderConsole();

    await screen.findByRole("heading", { name: "Sign in to Latchway" });
    await user.type(screen.getByLabelText("Email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Password"), "test-only-login-password");
    await user.click(screen.getByRole("button", { name: "Sign In" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Authentication required");
    expect(alert).toHaveTextContent("The administrator credentials are invalid.");
    expect(alert).toHaveTextContent("Request request_login_1234");
    expect(alert).not.toHaveTextContent("test-only-login-password");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("pauses sign-in for the address the server rate-limited", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return signedOutResponse();
      if (url === "/admin/v1/auth/login") return problemResponse(429, "rate_limited", "Rate limited", "Too many failed login attempts.", { "Retry-After": "300" });
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    }));
    renderConsole();

    await screen.findByRole("heading", { name: "Sign in to Latchway" });
    await user.type(screen.getByLabelText("Email address"), "paused@example.test");
    await user.type(screen.getByLabelText("Password"), "test-only-login-password");
    await user.click(screen.getByRole("button", { name: "Sign In" }));

    expect(await screen.findByText("Sign-in is paused for this email address.")).toBeInTheDocument();
    expect(screen.getByRole("timer")).toHaveTextContent("5:00");
    expect(screen.getByRole("button", { name: "Sign In" })).toBeDisabled();
    await user.clear(screen.getByLabelText("Email address"));
    await user.type(screen.getByLabelText("Email address"), "other@example.test");
    expect(screen.getByRole("button", { name: "Sign In" })).toBeEnabled();
  });

  it("asks which organization to use and signs in to the chosen one", async () => {
    const user = userEvent.setup();
    const second = "org_1123456789abcdef";
    const twoOrgs = { ...adminSession, memberships: [...adminSession.memberships, { organization_id: second, role: "viewer" }] };
    let session: object | undefined;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return session ? json(session) : signedOutResponse();
      if (url === "/admin/v1/auth/login") {
        const body = JSON.parse(String(init?.body)) as { organization_id?: string };
        session = body.organization_id ? { ...twoOrgs, capabilities: [], organization_id: body.organization_id } : twoOrgs;
        return json(session, 200, { "X-CSRF-Token": "test-only-csrf-token-0123456789abcdef" });
      }
      if (url === "/admin/v1/auth/organization") {
        const body = JSON.parse(String(init?.body)) as { organization_id: string };
        session = { ...twoOrgs, capabilities: [], organization_id: body.organization_id };
        return json(session, 200, { "X-CSRF-Token": "test-only-csrf-token-1123456789abcdef" });
      }
      if (url === "/admin/v1/organizations?page_size=200") return json({ items: [
        { created_at: "2026-08-29T00:00:00Z", display_name: "Example Org", id: adminSession.organization_id, slug: "example" },
        { created_at: "2026-08-29T00:00:00Z", display_name: "Second Org", id: second, slug: "second" }
      ], page: { has_more: false } });
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole();

    await screen.findByRole("heading", { name: "Sign in to Latchway" });
    await user.type(screen.getByLabelText("Email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Password"), "test-only-login-password");
    await user.click(screen.getByRole("button", { name: "Sign In" }));

    expect(await screen.findByRole("heading", { level: 1, name: "Choose an organization" })).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: /Second Org/ }));
    expect(await screen.findByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    const calls = fetchMock.mock.calls.map(([input, init]) => [requestURL(input), init?.body]);
    expect(calls.filter(([url]) => url === "/admin/v1/auth/login")).toHaveLength(1);
    expect(calls.filter(([url]) => url === "/admin/v1/auth/organization")).toEqual([["/admin/v1/auth/organization", JSON.stringify({ organization_id: second })]]);
    expect(screen.queryByDisplayValue("test-only-login-password")).not.toBeInTheDocument();
  });

  it("keeps the page and asks to sign in again when the session ends", async () => {
    const user = userEvent.setup();
    let ended = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return ended ? signedOutResponse() : json(adminSession);
      if (url === "/admin/v1/auth/login") {
        ended = false;
        expect(init?.body).toBe(JSON.stringify({ email: "owner@example.test", organization_id: adminSession.organization_id, password: "test-only-login-password" }));
        return json(adminSession);
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole("/applications");

    expect(await screen.findByRole("heading", { level: 1, name: "Applications" })).toBeInTheDocument();
    ended = true;
    window.dispatchEvent(new Event(SESSION_ENDED_EVENT));

    const dialog = await screen.findByRole("dialog", { name: "Your session ended" });
    expect(screen.getByRole("heading", { level: 1, name: "Applications" })).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Email address")).toHaveValue("owner@example.test");
    expect(within(dialog).getByLabelText("Email address")).toHaveAttribute("readonly");
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "Your session ended" })).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Password"), "test-only-login-password");
    await user.click(within(dialog).getByRole("button", { name: "Sign In" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(fetchMock.mock.calls.some(([input]) => requestURL(input) === "/admin/v1/auth/login")).toBe(true);
  });

  it("opens the account page from the account menu", async () => {
    const user = userEvent.setup();
    installConfiguredFetch();
    renderConsole("/requests");

    await user.click(await screen.findByRole("button", { name: "Your account: owner@example.test" }));
    expect(screen.queryByRole("menuitem", { name: "Switch Organization" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("menuitem", { name: "Your Account" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Your account" })).toBeInTheDocument();
    expect(screen.getByText("Owner")).toBeInTheDocument();
    // Without a verified compatible server the password form stays closed.
    expect(screen.getByText("Password changes are unavailable.")).toBeInTheDocument();
  });

  it("requires a new password before showing the console when an owner set it", async () => {
    const user = userEvent.setup();
    let resetRequired = true;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return json({ ...adminSession, password_reset_required: resetRequired });
      if (url === "/admin/v1/auth/password") {
        expect(init?.body).toBe(JSON.stringify({ current_password: "test-only-temporary-pass", new_password: "test-only-chosen-password" }));
        resetRequired = false;
        return json({ signed_out_sessions: 0 });
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    document.cookie = "__Host-latchway_csrf=test-only-csrf-token-0123456789abcdef";
    renderConsole("/applications");

    expect(await screen.findByRole("heading", { level: 1, name: "Choose your password" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Primary navigation" })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Temporary password"), "test-only-temporary-pass");
    await user.type(screen.getByLabelText("New password"), "test-only-chosen-password");
    await user.click(screen.getByRole("button", { name: "Save Password" }));

    expect(await screen.findByRole("heading", { level: 1, name: "Applications" })).toBeInTheDocument();
    expect(screen.queryByDisplayValue("test-only-chosen-password")).not.toBeInTheDocument();
  });

  it("finishes a two-factor sign-in with an authenticator code", async () => {
    const user = userEvent.setup();
    let signedIn = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return signedIn ? json(adminSession) : signedOutResponse();
      if (url === "/admin/v1/auth/login") return json({ challenge: `lwsic_${"a".repeat(43)}`, expires_at: "2026-10-08T10:05:00Z", methods: ["totp", "recovery_code"], status: "two_factor_required" }, 202);
      if (url === "/admin/v1/auth/login/two-factor") {
        expect(JSON.parse(String(init?.body))).toEqual({ challenge: `lwsic_${"a".repeat(43)}`, code: "123456" });
        signedIn = true;
        return json(adminSession, 200, { "X-CSRF-Token": "test-only-csrf-token-0123456789abcdef" });
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole("/applications");

    await screen.findByRole("heading", { name: "Sign in to Latchway" });
    await user.type(screen.getByLabelText("Email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Password", { exact: true }), "test-only-login-password");
    await user.click(screen.getByRole("button", { name: "Sign In" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Verify it's you" })).toBeInTheDocument();
    expect(screen.queryByDisplayValue("test-only-login-password")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Use a recovery code" }));
    expect(screen.getByLabelText("Recovery code")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Use an authentication code" }));
    await user.type(screen.getByLabelText("Authentication code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Applications" })).toBeInTheDocument();
  });

  it("requires setting up two-factor before the console when the organization requires it", async () => {
    const user = userEvent.setup();
    let enrolled = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return json({ ...adminSession, two_factor_enrollment_required: !enrolled });
      if (url === "/admin/v1/auth/two-factor/totp") return json({ secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", uri: "otpauth://totp/Latchway%20%28localhost%29:owner@example.test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Latchway" });
      if (url === "/admin/v1/auth/two-factor/totp/confirm") {
        expect(init?.body).toBe(JSON.stringify({ code: "654321" }));
        enrolled = true;
        return json({ recovery_codes: Array.from({ length: 10 }, (_, index) => `aaaa-bbbb-ccc${String.fromCharCode(97 + index)}`) });
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    document.cookie = "__Host-latchway_csrf=test-only-csrf-token-0123456789abcdef";
    renderConsole("/applications");

    expect(await screen.findByRole("heading", { level: 1, name: "Set up two-factor sign-in" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Set Up Authenticator" }));
    expect(await screen.findByRole("img", { name: "QR code for your authenticator app" })).toBeInTheDocument();
    expect(screen.getByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Authentication code"), "654321");
    await user.click(screen.getByRole("button", { name: "Turn On Two-Factor" }));
    const reveal = await screen.findByRole("alertdialog", { name: "Save your recovery codes" });
    expect(within(reveal).getByText("aaaa-bbbb-ccca")).toBeInTheDocument();
    expect(within(reveal).getByRole("button", { name: "Done" })).toBeDisabled();
    await user.click(within(reveal).getByRole("checkbox"));
    await user.click(within(reveal).getByRole("button", { name: "Done" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Applications" })).toBeInTheDocument();
    expect(screen.queryByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP")).not.toBeInTheDocument();
  });

  it("explains why a session ended on the sign-in screen", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return problemResponse(401, "session_revoked", "Session revoked", "Your password was changed, which signed out your other sessions.");
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    }));
    renderConsole();

    expect(await screen.findByRole("heading", { level: 1, name: "Sign in to Latchway" })).toBeInTheDocument();
    expect(screen.getByText("Your session ended")).toBeInTheDocument();
    expect(screen.getByText("Your password was changed, which signed out your other sessions.")).toBeInTheDocument();
  });

  it("opens first-owner setup when the server reports setup is open", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return signedOutResponse();
      if (url === "/admin/v1/auth/info") return json({ contract_version: "1.1.0", protocol_versions: [1, 2, 3], setup_open: true, sign_in_methods: ["password"] });
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    }));
    renderConsole();

    expect(await screen.findByRole("heading", { level: 1, name: "Set up Latchway" })).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Back to sign in" }));
    expect(screen.getByRole("heading", { level: 1, name: "Sign in to Latchway" })).toBeInTheDocument();
  });

  it("says when the server can't be reached instead of showing sign-in", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return new Response("unavailable", { status: 503 });
      return new Response("unavailable", { status: 503 });
    }));
    renderConsole();

    expect(await screen.findByRole("heading", { level: 1, name: "Can't reach the server" })).toBeInTheDocument();
    expect(screen.getByText("latchway doctor")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try Again" })).toBeInTheDocument();
  });

  it("renders live health details from the canonical endpoints", async () => {
    const fetchMock = installConfiguredFetch();
    renderConsole("/system-health");

    expect(
      await screen.findByRole("heading", { level: 1, name: "System Health" })
    ).toBeInTheDocument();
    await waitFor(() => expect(fetchMock.mock.calls.map(([input]) => requestURL(input))).toContain("/admin/v1/system/doctor"));

    const urls = fetchMock.mock.calls.map(([input]) => requestURL(input));
    expect(urls).toContain("/healthz");
    expect(urls).toContain("/readyz");
    expect(urls).toContain("/admin/v1/auth/session");
  });

  it("reaches every console page from the sidebar or a section tab", async () => {
    installConfiguredFetch();
    renderConsole("/applications");

    expect(await screen.findByRole("heading", { name: "Applications" })).toBeInTheDocument();
    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    const areas = [
      "Overview", "Requests", "Analytics", "Features", "Routing", "AI Connections", "Client Trust", "Setup wizard",
      "Users & Installs", "Policies & Limits", "Changes", "Simulator", "Self-tests", "System Health",
      "Team & Access", "Audit Log", "Settings"
    ];
    for (const label of areas) {
      expect(within(navigation).getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect(within(navigation).getByRole("link", { name: "Settings" })).toHaveAttribute("aria-current", "page");
    const sectionTabs = screen.getByRole("navigation", { name: "Settings pages" });
    expect(within(sectionTabs).getAllByRole("link").map((link) => link.textContent)).toEqual(["General", "Applications"]);
    expect(within(sectionTabs).getByRole("link", { name: "Applications" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByLabelText("Current environment").closest(".lw-crumb-select")).toHaveClass("lw-crumb-btn--dim");

    const destinations = commands.map((command) => command.to);
    expect(new Set(destinations).size).toBe(destinations.length);
    const pages = Object.keys(createAppRouter({ history: createMemoryHistory() }).routesByPath).filter((path) => !LEGACY_REDIRECT_PATHS.includes(path));
    expect([...destinations].sort()).toEqual(pages.sort());
  });

  it.each([
    ["/usage", "Usage"],
    ["/cost", "Cost"],
    ["/latency", "Performance"],
    ["/errors", "Reliability"],
    ["/attestation-failures", "Reliability"]
  ])("redirects the retired %s page to the %s tab of Analytics", async (path, tab) => {
    installConfiguredFetch();
    renderConsole(`${path}?environment_id=env_0123456789abcdef&interval=hour`);
    const sectionTabs = await screen.findByRole("navigation", { name: "Analytics pages" });
    expect(within(sectionTabs).getByRole("link", { name: tab })).toHaveAttribute("aria-current", "page");
  });

  it("opens the command palette with every destination and returns focus when it closes", async () => {
    const user = userEvent.setup();
    installConfiguredFetch();
    renderConsole("/requests");

    const trigger = await screen.findByRole("button", { name: "Search or jump" });
    await user.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "Go to an operator task" });
    expect(within(dialog).getByPlaceholderText("Feature, request, setup, health…")).toHaveFocus();
    expect(within(dialog).getAllByRole("link")).toHaveLength(commands.length);
    await user.type(within(dialog).getByPlaceholderText("Feature, request, setup, health…"), "secrets");
    expect(within(dialog).getAllByRole("link")).toHaveLength(1);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("resolves an explicit application environment and preserves it in task URLs", async () => {
    const user = userEvent.setup();
    const organizationID = "org_0123456789abcdef";
    const applicationID = "app_0123456789abcdef";
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") return new Response(JSON.stringify(adminSession), { headers: { "Content-Type": "application/json" }, status: 200 });
      if (url === "/admin/v1/organizations?page_size=200") return new Response(JSON.stringify({ items: [{ created_at: "2026-08-29T00:00:00Z", display_name: "Example Org", id: organizationID, slug: "example" }], page: { has_more: false } }), { headers: { "Content-Type": "application/json" }, status: 200 });
      if (url === `/admin/v1/applications?organization_id=${organizationID}&page_size=200`) return new Response(JSON.stringify({ items: [{ created_at: "2026-08-29T00:00:00Z", display_name: "Habitify", id: applicationID, organization_id: organizationID, slug: "habitify", status: "active" }], page: { has_more: false } }), { headers: { "Content-Type": "application/json" }, status: 200 });
      if (url === `/admin/v1/applications/${applicationID}/environments`) return new Response(JSON.stringify({ items: [
        { active_revision_id: "rev_0123456789abcdef", application_id: applicationID, created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: "env_0123456789abcdef", kind: "production", slug: "production", status: "active" },
        { active_revision_id: "rev_1123456789abcdef", application_id: applicationID, created_at: "2026-08-29T00:00:00Z", display_name: "Staging", id: "env_1123456789abcdef", kind: "staging", slug: "staging", status: "active" }
      ] }), { headers: { "Content-Type": "application/json" }, status: 200 });
      if (url === "/admin/v1/environments/env_0123456789abcdef/config-revisions?page_size=1") return new Response(JSON.stringify({ items: [{ created_at: "2026-08-29T00:01:00Z", created_by: "adm_0123456789abcdef", document: { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: {}, spec: {} }, environment_id: "env_0123456789abcdef", id: "rev_2123456789abcdef", state: "valid", version: 2 }], page: { has_more: false } }), { headers: { "Content-Type": "application/json" }, status: 200 });
      if (url === "/admin/v1/environments/env_1123456789abcdef/config-revisions?page_size=1") return new Response(JSON.stringify({ items: [], page: { has_more: false } }), { headers: { "Content-Type": "application/json" }, status: 200 });
      const document = { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: {}, spec: {} };
      if (url === "/admin/v1/environments/env_0123456789abcdef/config") return new Response(JSON.stringify({ activated_at: "2026-08-29T00:00:00Z", created_at: "2026-08-29T00:00:00Z", created_by: "adm_0123456789abcdef", document, environment_id: "env_0123456789abcdef", id: "rev_0123456789abcdef", state: "active", version: 1 }), { headers: { "Content-Type": "application/json", ETag: '"active-etag"' }, status: 200 });
      const draftDocument = { ...document, spec: { session: { accessTokenTtl: "15m" } } };
      if (url === "/admin/v1/config-revisions/rev_2123456789abcdef") return new Response(JSON.stringify({ created_at: "2026-08-29T00:01:00Z", created_by: "adm_0123456789abcdef", document: draftDocument, environment_id: "env_0123456789abcdef", id: "rev_2123456789abcdef", state: "valid", version: 2 }), { headers: { "Content-Type": "application/json", ETag: '"draft-etag"' }, status: 200 });
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole("/applications");

    await waitFor(() => expect(screen.getByLabelText("Current application")).toHaveValue("habitify"));
    await waitFor(() => expect(screen.getByLabelText("Current environment")).toHaveValue("production"));
    expect(within(screen.getAllByRole("banner")[0] as HTMLElement).getByText("Production", { selector: ".lw-badge span" })).toBeVisible();
    const statusRail = await screen.findByRole("region", { name: "Console state" });
    // Without a compatibility response the console is in read-only safe mode, which outranks the draft in the rail.
    expect(within(statusRail).getByRole("status")).toHaveTextContent("Read-only safe mode.");
    await user.click(await within(statusRail).findByRole("button", { name: "Draft ready" }));
    expect(within(statusRail).getByText("Unpublished changes.")).toBeVisible();
    expect(within(statusRail).getByText(/1 change in Production/)).toBeVisible();
    expect(within(statusRail).getByRole("link", { name: "Review Changes" })).toHaveAttribute("href", expect.stringContaining("/changes"));
    expect(within(statusRail).getByRole("button", { name: "Publish to Production" })).toBeInTheDocument();
    await waitFor(() => expect(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByText("Features", { exact: true }).closest("a")?.getAttribute("href")).toContain("environment=production"));

    await user.selectOptions(screen.getByLabelText("Current environment"), "staging");
    await waitFor(() => expect(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByText("Features", { exact: true }).closest("a")?.getAttribute("href")).toContain("environment=staging"));
    expect(within(screen.getAllByRole("banner")[0] as HTMLElement).getByText("Staging", { selector: ".lw-badge span" })).toBeVisible();
  });
});

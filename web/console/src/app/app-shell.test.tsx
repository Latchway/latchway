import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

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
  it("offers accessible sign-in and first-owner setup choices after a session 401", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") {
        return signedOutResponse();
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole();

    expect(
      await screen.findByRole("heading", { name: "Sign in to the control plane." })
    ).toBeInTheDocument();
    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(within(navigation).getByRole("link", { name: /Console access/ })).toHaveAttribute(
      "aria-current",
      "page"
    );
    expect(screen.getByRole("radio", { name: "Sign in" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "First-owner setup" })).not.toBeChecked();
    expect(screen.getByLabelText("Email address")).toHaveAttribute(
      "autocomplete",
      "username"
    );
    expect(screen.getByLabelText("Password")).toHaveAttribute(
      "autocomplete",
      "current-password"
    );
  });

  it("signs in, avoids browser storage, and refetches the session", async () => {
    const user = userEvent.setup();
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    let authenticated = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") {
        return authenticated
          ? new Response(JSON.stringify(adminSession), {
              headers: { "Content-Type": "application/json" },
              status: 200
            })
          : signedOutResponse();
      }
      if (url === "/admin/v1/auth/login" && init?.method === "POST") {
        authenticated = true;
        return new Response(JSON.stringify(adminSession), {
          headers: { "Content-Type": "application/json" },
          status: 200
        });
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole();

    await screen.findByRole("heading", { name: "Sign in to the control plane." });
    await user.type(screen.getByLabelText("Email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Password"), "test-only-login-password");
    await user.click(screen.getByRole("button", { name: "Sign in securely" }));

    expect(
      await screen.findByRole("heading", { level: 1, name: "Overview" })
    ).toBeInTheDocument();
    const loginCall = fetchMock.mock.calls.find(
      ([input]) => requestURL(input) === "/admin/v1/auth/login"
    );
    expect(loginCall?.[1]).toEqual(
      expect.objectContaining({
        body: JSON.stringify({
          email: "owner@example.test",
          password: "test-only-login-password"
        }),
        credentials: "same-origin",
        method: "POST",
        redirect: "error"
      })
    );
    await waitFor(() => {
      const sessionCalls = fetchMock.mock.calls.filter(
        ([input]) => requestURL(input) === "/admin/v1/auth/session"
      );
      expect(sessionCalls.length).toBeGreaterThanOrEqual(2);
    });
    expect(storageSpy).not.toHaveBeenCalled();
    expect(screen.queryByDisplayValue("test-only-login-password")).not.toBeInTheDocument();
  });

  it("creates the first owner with the complete bootstrap payload", async () => {
    const user = userEvent.setup();
    let authenticated = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") {
        return authenticated
          ? new Response(JSON.stringify(adminSession), {
              headers: { "Content-Type": "application/json" },
              status: 200
            })
          : signedOutResponse();
      }
      if (url === "/admin/v1/auth/bootstrap" && init?.method === "POST") {
        authenticated = true;
        return new Response(JSON.stringify(adminSession), {
          headers: { "Content-Type": "application/json" },
          status: 201
        });
      }
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole();

    await screen.findByRole("heading", { name: "Sign in to the control plane." });
    await user.click(screen.getByRole("radio", { name: "First-owner setup" }));
    expect(
      screen.getByRole("heading", { name: "Set up the first owner" })
    ).toBeInTheDocument();

    await user.type(
      screen.getByLabelText("One-time bootstrap token"),
      "test-only-bootstrap-token-000000000000"
    );
    await user.type(screen.getByLabelText("Organization name"), "Example Organization");
    await user.type(screen.getByLabelText("Organization slug"), "example-org");
    await user.type(screen.getByLabelText("Owner display name"), "Example Owner");
    await user.type(screen.getByLabelText("Owner email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Owner password"), "test-only-owner-password");
    await user.click(screen.getByRole("button", { name: "Create first owner" }));

    await screen.findByRole("heading", { level: 1, name: "Overview" });
    const bootstrapCall = fetchMock.mock.calls.find(
      ([input]) => requestURL(input) === "/admin/v1/auth/bootstrap"
    );
    expect(bootstrapCall?.[1]).toEqual(
      expect.objectContaining({
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
      })
    );
    expect(
      screen.queryByDisplayValue("test-only-bootstrap-token-000000000000")
    ).not.toBeInTheDocument();
  });

  it("renders validated problem details without exposing extra response fields", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = requestURL(input);
      if (url === "/admin/v1/auth/session") {
        return signedOutResponse();
      }
      if (url === "/admin/v1/auth/login") {
        return new Response(
          JSON.stringify({
            code: "authentication_required",
            debug: "test-only-login-password",
            detail: "The administrator credentials are invalid.",
            request_id: "request_login_1234",
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
      return healthResponse(url) ?? new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderConsole();

    await screen.findByRole("heading", { name: "Sign in to the control plane." });
    await user.type(screen.getByLabelText("Email address"), "owner@example.test");
    await user.type(screen.getByLabelText("Password"), "test-only-login-password");
    await user.click(screen.getByRole("button", { name: "Sign in securely" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Authentication required");
    expect(alert).toHaveTextContent("The administrator credentials are invalid.");
    expect(alert).toHaveTextContent("Code: authentication_required");
    expect(alert).toHaveTextContent("Request: request_login_1234");
    expect(alert).not.toHaveTextContent("test-only-login-password");
    expect(screen.getByLabelText("Password")).toHaveValue("");
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

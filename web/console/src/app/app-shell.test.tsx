import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { createAppRouter } from "./router";

function requestURL(input: RequestInfo | URL): string {
  if (typeof input === "string") {
    return input;
  }
  return input instanceof URL ? input.toString() : input.url;
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

function installFetch(mode: "configured" | "setup-required") {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = requestURL(input);
    if (url === "/admin/v1/auth/session") {
      if (mode === "setup-required") {
        return new Response(
          JSON.stringify({ authenticated: false, setup_required: true }),
          { headers: { "Content-Type": "application/json" }, status: 200 }
        );
      }
      return new Response(
        JSON.stringify({
          authenticated: true,
          setup_required: false,
          user: { display_name: "Gateway owner" }
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 }
      );
    }
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
    return new Response("not found", { status: 404 });
  });

  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("AppShell", () => {
  it("switches to first-run navigation when bootstrap is required", async () => {
    installFetch("setup-required");
    renderConsole();

    expect(
      await screen.findByRole("heading", {
        name: "Create the trust boundary before traffic arrives."
      })
    ).toBeInTheDocument();
    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(within(navigation).getByRole("link", { name: /Initial setup/ })).toHaveAttribute(
      "aria-current",
      "page"
    );
    expect(within(navigation).queryByText("Overview")).not.toBeInTheDocument();
    expect(screen.getByText("Requires the one-time bootstrap token")).toBeVisible();
  });

  it("renders live health details from the canonical endpoints", async () => {
    const fetchMock = installFetch("configured");
    renderConsole("/system-health");

    expect(
      await screen.findByRole("heading", { name: "System health" })
    ).toBeInTheDocument();
    expect(await screen.findByText("Gateway ready")).toBeVisible();
    expect(screen.getByText("database")).toBeVisible();
    expect(screen.getByText("signing key")).toBeVisible();

    const urls = fetchMock.mock.calls.map(([input]) => requestURL(input));
    expect(urls).toContain("/healthz");
    expect(urls).toContain("/readyz");
    expect(urls).toContain("/admin/v1/auth/session");
  });
});

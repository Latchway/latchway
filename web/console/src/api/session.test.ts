import { describe, expect, it, vi } from "vitest";

import { adminSessionEndpoint, fetchConsoleSession } from "./session";

const adminSession = {
  administrator: {
    email: "owner@example.test",
    enabled: true,
    id: "adm_0123456789abcdef"
  },
  capabilities: ["secrets.manage", "configuration.activate"],
  expires_at: null,
  memberships: [
    { organization_id: "org_0123456789abcdef", role: "owner" }
  ],
  organization_id: "org_0123456789abcdef"
};

describe("fetchConsoleSession", () => {
  it("validates the current AdminSession contract", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(
        new Response(JSON.stringify(adminSession), {
          headers: { "Content-Type": "application/json" },
          status: 200
        })
      )
    ) as unknown as typeof fetch;

    await expect(fetchConsoleSession(undefined, fetcher)).resolves.toEqual({
      mode: "configured",
      session: adminSession,
      userLabel: "owner@example.test"
    });
    expect(fetcher).toHaveBeenCalledWith(
      adminSessionEndpoint,
      expect.objectContaining({
        cache: "no-store",
        credentials: "same-origin",
        method: "GET",
        redirect: "error"
      })
    );
  });

  it("treats the canonical unauthenticated 401 as signed out", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            code: "authentication_required",
            detail: "An administrator session is required.",
            request_id: "request_test_1234",
            retryable: false,
            status: 401,
            title: "Authentication required",
            type: "https://latchway.dev/problems/authentication_required"
          }),
          {
            headers: { "Content-Type": "application/problem+json" },
            status: 401
          }
        )
      )
    ) as unknown as typeof fetch;

    await expect(fetchConsoleSession(undefined, fetcher)).resolves.toEqual({
      mode: "signed-out"
    });
  });

  it("uses a safe unknown mode for invalid success data or an unavailable API", async () => {
    const invalidFetcher = vi.fn(async () =>
      Promise.resolve(
        new Response(JSON.stringify({ authenticated: true }), {
          headers: { "Content-Type": "application/json" },
          status: 200
        })
      )
    ) as unknown as typeof fetch;
    const offlineFetcher = vi.fn(async () =>
      Promise.reject(new TypeError("offline with internal address"))
    ) as unknown as typeof fetch;

    await expect(fetchConsoleSession(undefined, invalidFetcher)).resolves.toEqual({
      mode: "unknown"
    });
    await expect(fetchConsoleSession(undefined, offlineFetcher)).resolves.toEqual({
      mode: "unknown"
    });
  });
});

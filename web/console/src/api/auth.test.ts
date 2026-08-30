import { describe, expect, it, vi } from "vitest";

import {
  AdminRequestError,
  adminAuthEndpoints,
  bootstrapFirstOwner,
  loginAdministrator
} from "./auth";

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

function successfulFetcher(status = 200) {
  return vi.fn(async () =>
    Promise.resolve(
      new Response(JSON.stringify(adminSession), {
        headers: { "Content-Type": "application/json" },
        status
      })
    )
  ) as unknown as typeof fetch;
}

describe("administrator credential requests", () => {
  it("posts login credentials only to the canonical same-origin endpoint", async () => {
    const fetcher = successfulFetcher();

    await expect(
      loginAdministrator(
        {
          email: "owner@example.test",
          organization_id: "org_0123456789abcdef",
          password: "test-only-login-password"
        },
        undefined,
        fetcher
      )
    ).resolves.toEqual(adminSession);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(
      adminAuthEndpoints.login,
      expect.objectContaining({
        body: JSON.stringify({
          email: "owner@example.test",
          organization_id: "org_0123456789abcdef",
          password: "test-only-login-password"
        }),
        cache: "no-store",
        credentials: "same-origin",
        method: "POST",
        redirect: "error",
        referrerPolicy: "same-origin"
      })
    );
  });

  it("posts the complete first-owner transaction", async () => {
    const fetcher = successfulFetcher(201);
    const input = {
      bootstrap_token: "test-only-bootstrap-token-000000000000",
      display_name: "Example Owner",
      email: "owner@example.test",
      organization_name: "Example Organization",
      organization_slug: "example-org",
      password: "test-only-owner-password"
    };

    await expect(
      bootstrapFirstOwner(input, undefined, fetcher)
    ).resolves.toEqual(adminSession);
    expect(fetcher).toHaveBeenCalledWith(
      adminAuthEndpoints.bootstrap,
      expect.objectContaining({ body: JSON.stringify(input), method: "POST" })
    );
  });

  it("exposes only validated RFC 9457 fields from a failed response", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            code: "authentication_required",
            debug: "test-only-login-password",
            detail: "The administrator credentials are invalid.",
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

    const error = await loginAdministrator(
      { email: "owner@example.test", password: "test-only-login-password" },
      undefined,
      fetcher
    ).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(AdminRequestError);
    expect(error).toMatchObject({
      problem: {
        code: "authentication_required",
        detail: "The administrator credentials are invalid.",
        requestId: "request_test_1234",
        retryable: false,
        status: 401,
        title: "Authentication required"
      }
    });
    expect(JSON.stringify(error)).not.toContain("test-only-login-password");
  });

  it("does not render an unstructured or mismatched server body as an error", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(
        new Response("database address and test-only-login-password", {
          headers: { "Content-Type": "text/plain" },
          status: 500
        })
      )
    ) as unknown as typeof fetch;

    await expect(
      loginAdministrator(
        { email: "owner@example.test", password: "test-only-login-password" },
        undefined,
        fetcher
      )
    ).rejects.toMatchObject({
      problem: {
        code: "request_failed",
        detail: "The console could not complete this request.",
        status: 500,
        title: "Request failed"
      }
    });
  });

  it("rejects malformed successful sessions without exposing the payload", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(
        new Response(JSON.stringify({ administrator: { email: "owner@example.test" } }), {
          headers: { "Content-Type": "application/json" },
          status: 200
        })
      )
    ) as unknown as typeof fetch;

    await expect(
      loginAdministrator(
        { email: "owner@example.test", password: "test-only-login-password" },
        undefined,
        fetcher
      )
    ).rejects.toMatchObject({
      problem: {
        code: "invalid_response",
        detail: "The gateway returned an invalid administrator session."
      }
    });
  });
});

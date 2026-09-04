import { describe, expect, it, vi } from "vitest";

import {
  AdminRequestError,
  adminAuthEndpoints,
  bootstrapFirstOwner,
  loginAdministrator,
  responseProblem
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
            type: "https://docs.latchway.dev/errors/authentication-required",
            documentation_url: "https://docs.latchway.dev/errors/authentication-required"
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
        documentationURL: "https://docs.latchway.dev/errors/authentication-required",
        requestId: "request_test_1234",
        retryable: false,
        status: 401,
        title: "Authentication required"
      }
    });
    expect(JSON.stringify(error)).not.toContain("test-only-login-password");
  });

  it("rejects a server-supplied documentation URL that does not match the stable code", async () => {
    const response = new Response(JSON.stringify({
      code: "authentication_required",
      detail: "The administrator credentials are invalid.",
      documentation_url: "https://docs.latchway.dev/errors/quota-exceeded",
      request_id: "request_test_1234",
      retryable: false,
      status: 401,
      title: "Authentication required",
      type: "https://docs.latchway.dev/errors/authentication-required"
    }), { headers: { "Content-Type": "application/problem+json" }, status: 401 });

    expect(responseProblem(response, await response.json())).toMatchObject({
      code: "request_failed",
      documentationURL: undefined
    });
  });

  it("preserves only a canonical correlation ID for an indeterminate operation", async () => {
    const response = new Response(JSON.stringify({
      code: "operation_indeterminate",
      detail: "The database commit outcome is unknown.",
      documentation_url: "https://docs.latchway.dev/errors/operation-indeterminate",
      operation_id: "arq_00000000000000000000000000",
      request_id: "request_test_1234",
      retryable: true,
      status: 503,
      title: "Operation outcome unknown",
      type: "https://docs.latchway.dev/errors/operation-indeterminate"
    }), { headers: { "Content-Type": "application/problem+json" }, status: 503 });

    expect(responseProblem(response, await response.json())).toMatchObject({
      code: "operation_indeterminate",
      operationId: "arq_00000000000000000000000000",
      requestId: "request_test_1234",
      retryable: true
    });
  });

  it.each([
    ["missing", undefined, "operation_indeterminate"],
    ["malformed", "arq_not-canonical", "operation_indeterminate"],
    ["attached to a determinate problem", "arq_00000000000000000000000000", "authentication_required"]
  ])("rejects an operation ID that is %s", async (_label, operationID, code) => {
    const documentationCode = code.replaceAll("_", "-");
    const payload = {
      code,
      detail: "A safe error detail.",
      documentation_url: `https://docs.latchway.dev/errors/${documentationCode}`,
      ...(operationID ? { operation_id: operationID } : {}),
      request_id: "request_test_1234",
      retryable: code === "operation_indeterminate",
      status: 503,
      title: "Request failed",
      type: `https://docs.latchway.dev/errors/${documentationCode}`
    };
    const response = new Response(JSON.stringify(payload), { headers: { "Content-Type": "application/problem+json" }, status: 503 });

    expect(responseProblem(response, await response.json())).toMatchObject({
      code: "request_failed",
      documentationURL: undefined,
      retryable: false
    });
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

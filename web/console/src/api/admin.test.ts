import { describe, expect, it, vi } from "vitest";

import { adminRequest, RevisionSchema, UserSchema } from "./admin";
import { loginAdministrator } from "./auth";

const csrf = "csrf_0123456789abcdefghijklmnopqrstuvwxyz";
const session = {
  administrator: { email: "owner@example.test", enabled: true, id: "adm_0123456789abcdef" },
  capabilities: ["activate_configuration", "revoke_installations"],
  expires_at: "2026-08-30T00:00:00Z",
  memberships: [{ organization_id: "org_0123456789abcdef", role: "owner" }],
  organization_id: "org_0123456789abcdef"
};

describe("canonical Admin API browser client", () => {
  it("sends cookie mutations only through the Admin API with recovered CSRF", async () => {
    await loginAdministrator(
      { email: "owner@example.test", password: "test-only-owner-password" },
      undefined,
      vi.fn(async () => new Response(JSON.stringify(session), {
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, status: 200
      })) as unknown as typeof fetch
    );
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      created_at: "2026-08-29T00:00:00Z", environment_id: "env_0123456789abcdef",
      id: "usr_0123456789abcdef", identity_providers: ["firebase"],
      normalized_claims: { plan: "standard" }, status: "blocked"
    }), { headers: { "Content-Type": "application/json" }, status: 200 })) as unknown as typeof fetch;

    await adminRequest(
      "/admin/v1/users/usr_0123456789abcdef/block?environment_id=env_0123456789abcdef",
      UserSchema,
      { method: "POST" },
      fetcher
    );

    expect(fetcher).toHaveBeenCalledWith(
      "/admin/v1/users/usr_0123456789abcdef/block?environment_id=env_0123456789abcdef",
      expect.objectContaining({
        credentials: "same-origin",
        method: "POST",
        redirect: "error",
        headers: expect.objectContaining({ "X-CSRF-Token": csrf })
      })
    );
  });

  it("carries a strong server ETag into activation", async () => {
    const revision = {
      created_at: "2026-08-29T00:00:00Z", created_by: "adm_0123456789abcdef",
      document: {}, environment_id: "env_0123456789abcdef", id: "rev_0123456789abcdef",
      state: "active", version: 1
    };
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("If-Match")).toBe('"revision-etag"');
      return new Response(JSON.stringify(revision), { headers: { "Content-Type": "application/json" }, status: 200 });
    }) as unknown as typeof fetch;
    await adminRequest("/admin/v1/config-revisions/rev_0123456789abcdef/activate", RevisionSchema, {
      etag: '"revision-etag"', method: "POST"
    }, fetcher);
  });

  it("rejects non-conforming success documents", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      id: "usr_0123456789abcdef", raw_identity_token: "must-not-render"
    }), { headers: { "Content-Type": "application/json" }, status: 200 })) as unknown as typeof fetch;
    await expect(adminRequest("/admin/v1/users/usr_0123456789abcdef", UserSchema, {}, fetcher)).rejects.toMatchObject({
      problem: { code: "invalid_response" }
    });
  });
});

describe("console mutation boundary", () => {
  it("contains no direct database client or connection-string access", () => {
    const sources = import.meta.glob("../**/*.{ts,tsx}", {
      eager: true,
      import: "default",
      query: "?raw"
    }) as Record<string, string>;
    const combined = Object.entries(sources)
      .filter(([path]) => !path.endsWith(".test.ts") && !path.endsWith(".test.tsx"))
      .map(([, source]) => source)
      .join("\n");
    expect(combined).not.toMatch(/DATABASE_URL|postgres(?:ql)?:\/\/|from\s+["']pg["']|pgxpool/);
    for (const [path, source] of Object.entries(sources)) {
      if (!path.includes("/pages/") && !path.includes("/components/")) continue;
      expect(source, `${path} bypasses the canonical API client`).not.toMatch(/\bfetch\s*\(|globalThis\.fetch/);
    }
  });
});

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  adminRequest,
  APITokenMetadataSchema,
  CreatedAPITokenSchema,
  AdministratorSchema,
  RequestSchema,
  RevisionSchema,
  SelfTestScheduleSchema,
  UsageSummarySchema,
  UserSchema
} from "./admin";
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

  it("sends a transient bearer without cookies or CSRF and never returns token material", async () => {
    const bearerToken = "transient-scheduled-self-test-token-material-1234567890";
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("Authorization")).toBe(`Bearer ${bearerToken}`);
      expect(headers.get("X-CSRF-Token")).toBeNull();
      expect(headers.get("Cookie")).toBeNull();
      expect(init?.credentials).toBe("omit");
      expect(init?.body).toBe(JSON.stringify({ kind: "upstream" }));
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" }, status: 201 });
    }) as unknown as typeof fetch;
    const result = await adminRequest(
      "/admin/v1/self-test-schedules",
      z.object({ ok: z.boolean() }).strict(),
      { bearerToken, body: { kind: "upstream" }, method: "POST" },
      fetcher
    );
    expect(result).toEqual({ data: { ok: true } });
    expect(JSON.stringify(result)).not.toContain(bearerToken);

    let rejected: unknown;
    try {
      await adminRequest(
        "/admin/v1/self-test-schedules",
        z.object({ ok: z.boolean() }).strict(),
        { bearerToken, body: { kind: "upstream" }, method: "POST" },
        vi.fn(async () => new Response(JSON.stringify({
          code: "permission_denied", detail: "The durable credential is not authorized.", retryable: false,
          status: 403, title: "Permission denied", type: "https://latchway.dev/problems/permission_denied"
        }), { headers: { "Content-Type": "application/problem+json" }, status: 403 })) as unknown as typeof fetch
      );
    } catch (error) {
      rejected = error;
    }
    expect(rejected).toBeDefined();
    expect(JSON.stringify(rejected)).not.toContain(bearerToken);
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

  it("accepts only redaction-safe administrator metadata", () => {
    const administrator = {
      created_at: "2026-08-29T00:00:00Z", display_name: "Owner",
      email: "owner@example.test", id: "adm_0123456789abcdef",
      membership_id: "amb_0123456789abcdef", organization_id: "org_0123456789abcdef",
      password_reset_required: false, role: "owner", status: "active",
      updated_at: "2026-08-29T00:00:00Z"
    };
    expect(AdministratorSchema.parse(administrator)).toEqual(administrator);
    expect(() => AdministratorSchema.parse({ ...administrator, password: "must-not-render" })).toThrow();
  });

  it("keeps one-time API-token plaintext separate from list metadata", () => {
    const metadata = {
      created_at: "2026-08-29T00:00:00Z",
      id: "tok_0123456789abcdef",
      name: "mobile-ci",
      revoked: false,
      scopes: ["inspect_users"]
    };
    expect(APITokenMetadataSchema.parse(metadata)).toEqual(metadata);
    expect(() => APITokenMetadataSchema.parse({ ...metadata, token: "must-not-appear-in-list-metadata" })).toThrow();
    expect(CreatedAPITokenSchema.parse({
      metadata,
      token: "one-time-printable-token-material-1234567890"
    })).toEqual({ metadata, token: "one-time-printable-token-material-1234567890" });
  });

  it("accepts only redaction-safe, lifecycle-consistent self-test schedule metadata", () => {
    const schedule = {
      application_id: "app_0123456789abcdef", authorization_credential_id: "tok_0123456789abcdef",
      config_revision_id: "rev_0123456789abcdef", created_at: "2026-08-29T00:00:00Z",
      daily_cost_limit_nano_usd: 240_000_000, environment_id: "env_0123456789abcdef",
      id: "sts_0123456789abcdef", interval_seconds: 3600, kind: "upstream",
      max_cost_nano_usd: 10_000_000, model: "canary", next_run_at: "2026-08-29T01:00:00Z",
      status: "active", updated_at: "2026-08-29T00:00:00Z", upstream: "primary"
    };
    expect(SelfTestScheduleSchema.parse(schedule)).toEqual(schedule);
    expect(() => SelfTestScheduleSchema.parse({ ...schedule, provider_secret: "must-not-render" })).toThrow();
    expect(() => SelfTestScheduleSchema.parse({ ...schedule, next_run_at: undefined })).toThrow();
    expect(() => SelfTestScheduleSchema.parse({ ...schedule, daily_cost_limit_nano_usd: 1 })).toThrow();
  });

  it("keeps provider cost provenance and its fixed report source distinct", () => {
	const attempt = {
	  attempt_number: 1, completed_at: "2026-08-29T00:00:02Z",
	  cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost", http_status: 200,
	  id: "atm_0123456789abcdef", model: "openai/gpt", started_at: "2026-08-29T00:00:00Z",
	  route: "primary", status: "succeeded", upstream: "openrouter", usage_provenance: "unknown"
	};
	expect(RequestSchema.parse({
	  attempts: [attempt], environment_id: "env_0123456789abcdef", feature: "assistant",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  completed_at: "2026-08-29T00:00:03Z", protocol: "openai_chat",
	  started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  user_id: "usr_0123456789abcdef"
	}).attempts[0]).toEqual(attempt);
	expect(() => RequestSchema.parse({
	  attempts: [{ ...attempt, cost_source: "secret source\n" }],
	  environment_id: "env_0123456789abcdef", feature: "assistant",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  completed_at: "2026-08-29T00:00:03Z", protocol: "openai_chat",
	  started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  user_id: "usr_0123456789abcdef"
	})).toThrow();
	const request = {
	  attempts: [attempt], completed_at: "2026-08-29T00:00:03Z",
	  environment_id: "env_0123456789abcdef", feature: "assistant",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  user_id: "usr_0123456789abcdef"
	};
	expect(() => RequestSchema.parse({ ...request, attempts: [{ ...attempt, attempt_number: 2 }] })).toThrow();
	expect(() => RequestSchema.parse({
	  ...request, attempts: [{ ...attempt, first_byte_at: "2026-08-29T00:00:03Z" }]
	})).toThrow();
	expect(() => RequestSchema.parse({
	  ...request, attempts: [{ ...attempt, failure_code: "upstream_timeout" }]
	})).toThrow();
	expect(() => RequestSchema.parse({
	  ...request, attempts: [{ ...attempt, failure_code: "timeout", status: "failed" }]
	})).not.toThrow();
	const values = { cost_nano_usd: 0, input_tokens: 0, logical_requests: 0, output_tokens: 0, total_tokens: 0 };
	const analytics = {
	  active_users: 0, attestation_failure_rate: { denominator: 0, numerator: 0, parts_per_million: 0 },
	  by_feature: { items: [], limit: 50, truncated: false }, by_model: { items: [], limit: 50, truncated: false },
	  by_selected_plan: { items: [], limit: 50, truncated: false }, cost_per_active_user_nano_usd: { denominator: 0, numerator: 0 },
	  failure_rate: { denominator: 0, numerator: 0, parts_per_million: 0 }, fallback_rate: { denominator: 0, numerator: 0, parts_per_million: 0 },
	  quota_denial_rate: { denominator: 0, numerator: 0, parts_per_million: 0 }, request_count: 0,
	  request_latency: { p50_ms: 0, p95_ms: 0, p99_ms: 0, samples: 0 }, requests_per_active_user: { denominator: 0, numerator: 0 },
	  time_to_first_token: { p50_ms: 0, p95_ms: 0, p99_ms: 0, samples: 0 },
	  usage_by_provenance: [
		{ cost_source: "openrouter_usage_cost", provenance: "upstream_reported", values },
		{ provenance: "calculated", values }, { provenance: "estimated", values }, { provenance: "unknown", values }
	  ]
	};
	expect(UsageSummarySchema.parse({
	  analytics, end: "2026-08-29T01:00:00Z", provenance: [], start: "2026-08-29T00:00:00Z", values
	}).analytics.usage_by_provenance.at(0)?.cost_source).toBe("openrouter_usage_cost");
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

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  adminRequest,
  AuditEventSchema,
  APITokenMetadataSchema,
  CreatedAPITokenSchema,
  AdministratorSchema,
  ClientComponentSchema,
  DoctorReportSchema,
  EffectiveConfigurationSchema,
  getRequestEffectiveConfiguration,
  getUserEffectiveConfiguration,
  getUserOperationImpact,
  InstallationFamilySchema,
  RequestSchema,
  RevisionSchema,
  runDevelopmentSample,
  SelfTestScheduleSchema,
  SupportBundleSchema,
  UsageSummarySchema,
  setApplicationUserBlocked,
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
  it("runs only the bounded loopback development helper without administrator credentials", async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    fetcher.mockResolvedValue(new Response(JSON.stringify({
      feature: "habit-assistant",
      model: "fixture-model",
      protocol: "openai_responses",
      request_id: "req_0123456789abcdef",
      status: "succeeded"
    }), { headers: { "Content-Type": "application/json" }, status: 201 }));

    await expect(runDevelopmentSample(fetcher)).resolves.toEqual({
      data: {
        feature: "habit-assistant",
        model: "fixture-model",
        protocol: "openai_responses",
        request_id: "req_0123456789abcdef",
        status: "succeeded"
      }
    });
    expect(fetcher).toHaveBeenCalledWith(
      "/development/v1/sample-request",
      expect.objectContaining({
        body: "{}",
        credentials: "same-origin",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        method: "POST",
        redirect: "error"
      })
    );
    const options = fetcher.mock.calls[0]?.[1] as RequestInit;
    expect(options.headers).not.toHaveProperty("Authorization");
    expect(options.headers).not.toHaveProperty("X-CSRF-Token");
  });

  it("rejects nonconforming development sample metadata", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      credential: "must-not-cross",
      feature: "habit-assistant",
      model: "fixture-model",
      protocol: "openai_responses",
      request_id: "req_0123456789abcdef",
      status: "succeeded"
    }), { headers: { "Content-Type": "application/json" }, status: 201 })) as unknown as typeof fetch;

    await expect(runDevelopmentSample(fetcher)).rejects.toThrow("Invalid development response");
  });

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

    await setApplicationUserBlocked(
      "usr_0123456789abcdef",
      "env_0123456789abcdef",
      true,
      { acknowledge_immediate_effect: true, impact_token: "A".repeat(43), reason: "security response" },
      fetcher
    );

    expect(fetcher).toHaveBeenCalledWith(
      "/admin/v1/users/usr_0123456789abcdef/block?environment_id=env_0123456789abcdef",
      expect.objectContaining({
        credentials: "same-origin",
        method: "POST",
        redirect: "error",
        headers: expect.objectContaining({
          "X-CSRF-Token": csrf,
          "X-Latchway-Admin-Source": "console",
          "X-Latchway-Audit-Reason": "operator_reason_provided"
        }),
        body: JSON.stringify({ acknowledge_immediate_effect: true, impact_token: "A".repeat(43), reason: "security response" })
      })
    );
  });

  it("rejects unsafe audit attribution before sending a mutation", async () => {
    const fetcher = vi.fn() as unknown as typeof fetch;
    await expect(adminRequest(
      "/admin/v1/users/usr_0123456789abcdef/block?environment_id=env_0123456789abcdef",
      UserSchema,
      { method: "POST", reason: "provider_token_rotation" },
      fetcher
    )).rejects.toThrow("Invalid redaction-safe audit reason code.");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("accepts only value-free audit changes and structurally allowlisted support bundles", () => {
    const change = { classification: "sensitive", field: "credential", operation: "rotate", redacted: true };
    const audit = {
      action: "admin.secret_rotate", actor: "admin_user:adm_00000000000000000000000000",
      actor_id: "adm_00000000000000000000000000", actor_kind: "admin_user", changes: [change],
      environment_id: "env_0123456789abcdef", id: "aud_00000000000000000000000000",
      reason: "planned_rotation", request_id: "arq_00000000000000000000000000",
      resource_id: "sec_00000000000000000000000000", resource_type: "secret", result: "succeeded",
      source: "console", summary: { changes: [change] }, target: "secret:sec_00000000000000000000000000",
      timestamp: "2026-08-29T00:00:00Z"
    };
    expect(AuditEventSchema.parse(audit).changes[0]?.redacted).toBe(true);
    expect(() => AuditEventSchema.parse({ ...audit, before: { credential: "plaintext" } })).toThrow();
    expect(() => AuditEventSchema.parse({
      ...audit,
      actor: "admin_api_token:tok_00000000000000000000000000",
      actor_id: "tok_00000000000000000000000000",
      actor_kind: "admin_api_token",
      source: "console"
    })).toThrow();

    const report = {
      checks: [{ id: "database_connectivity", state: "passed", summary: "PostgreSQL accepted a bounded probe." }],
      database: "reachable",
      facts: {
        configuration: {
          active_configurations: 1, active_environments: 1,
          cache: { available: true, entries: 1, estimated_bytes: 16384, fresh_entries: 1, maximum_entries: 1024, maximum_estimated_bytes: 25165824, newest_loaded_at: "2026-08-29T00:00:00Z", reconciliation_interval_seconds: 30, refreshes_in_flight: 0, stale_entries: 0 },
          draft_revisions: 0, highest_revision_number: 1, invalid_revisions: 0,
          missing_active_configuration: 0, revisions: 1
        },
        database: { latency_ms: 1, pool_acquired: 1, pool_idle: 1, pool_maximum: 4, pool_total: 2, pool_utilization_ppm: 250000, reachable: true, schema_available: 27, schema_current: 27, size_bytes: 1024 },
        expired_quota_reservations: 0,
        jobs: { by_status: [], expired_locks: 0, failed_self_tests: 0, recent_self_tests: 0, usage_settlement_backlog: 0 },
        replicas: { fresh_apis: 1, fresh_by_role: [{ count: 1, role: "all" }], fresh_workers: 1, stale_replicas: 0 },
        retention: { admin_session_retention_hours: 168, job_history_retention_hours: 720, policy_mode: "fixed_operational_operator_tenant_data", runtime_instance_retention_hours: 24 },
        runtime: { build_date: "2026-08-29", clock_offset_ms: 0, commit: "abc123", compatibility_source: "embedded_self", contract_version: "1.0.0", latest_compatible_version: "1.0.0", protocol_versions: [1, 2], role: "all", server_version: "1.0.0" },
        security: {
          active_secret_records: 1, active_signing_keys: 1,
          apple_verification: { configured_selections: 1, credential_backed_selections: 0, external_network_selections: 0, registered_active_keys: 1, required_selections: 1, resolved_credential_records: 0 },
          configured_external_jwks_providers: 1,
          google_verification: { configured_selections: 1, credential_backed_selections: 0, external_network_selections: 1, registered_active_keys: 0, required_selections: 1, resolved_credential_records: 0 },
          identity_provider_errors: 0, identity_providers: 1, pending_signing_keys: 0,
          retiring_signing_keys: 0, stale_identity_provider_jwks: 0
        }
      },
      generated_at: "2026-08-29T00:00:00Z", overall_state: "healthy", report_schema: 1,
      role: "all", schema_version: 27, status: "ok"
    };
    expect(DoctorReportSchema.parse(report).facts.database.schema_current).toBe(27);
    const bundle = {
      bundle_schema: 1, generated_at: report.generated_at,
      redaction: { excluded: ["access_tokens", "admin_sessions", "api_tokens", "authorization_headers", "cookies", "dpop_proofs", "identity_tokens", "master_key", "provider_credentials", "raw_attestation_evidence", "request_content", "response_content", "secret_values"], mode: "structural_allowlist" },
      report, source: "admin_api"
    };
    expect(SupportBundleSchema.parse(bundle).redaction.mode).toBe("structural_allowlist");
    expect(() => SupportBundleSchema.parse({ ...bundle, provider_credentials: "plaintext" })).toThrow();
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
          status: 403, title: "Permission denied", type: "https://docs.latchway.dev/errors/permission-denied",
          documentation_url: "https://docs.latchway.dev/errors/permission-denied"
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

  it("uses canonical redaction-safe effective-configuration and impact endpoints", async () => {
    const route = {
      configured_priority: 0, configured_weight: 100, fallback_on: ["timeout"], match_expression: "true",
      model: "gpt_mobile", observed: false, order: 1, physical_model: "gpt-5-mini",
      retry_maximum_attempts: 2, retry_on: ["timeout"], route: "primary", source: "feature.routes[0]",
      sticky_by: "user", upstream: "openai"
    };
    const effective = {
      decision_stages: [], environment_id: "env_0123456789abcdef", environment_kind: "production",
      evaluation_mode: "current_user_projection", feature: "assistant",
      inputs: [{ availability: "available", detail: "Claim values are omitted.", fact: "normalized_claims", keys: ["plan"], source: "current_application_user" }],
      limit_plan: "subscriber", limit_plan_source: "policy_expression",
      limits: [{ algorithm: "per_request", hard: true, index: 0, metric: "input_tokens", per_request_maximum: 4096, scope: ["user", "feature"], source: "limit_plans.subscriber.limits[0]" }],
      policy_outcome: "allowed", protocol: "openai_responses", revision_id: "rev_0123456789abcdef",
      routes: [route], selected_route: route,
      subject: { id: "usr_0123456789abcdef", kind: "user", user_id: "usr_0123456789abcdef" }, warnings: []
    };
    const requestEffective = {
      ...effective, evaluation_mode: "recorded_request", request_status: "succeeded",
      subject: { id: "req_0123456789abcdef", kind: "request", user_id: "usr_0123456789abcdef" }
    };
    const impact = {
      access_effect: "deny_and_revoke", action: "block", applicable: true,
      counts: { active_client_components: 1, active_component_refresh_tokens: 1, active_component_sessions: 1, active_installation_families: 1, active_refresh_tokens: 1, active_session_grants: 1 },
      current_status: "active", immediate: true, impact_token: "A".repeat(43), reversible: true,
      summary: "Blocks future access and revokes active credentials application-wide."
    };
    const fetcherMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      const body = path.includes("operation-impact") ? impact : path.includes("/requests/") ? requestEffective : effective;
      return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" }, status: 200 });
    });
    const fetcher = fetcherMock as unknown as typeof fetch;

    await getUserEffectiveConfiguration("usr_0123456789abcdef", {
      environmentID: "env_0123456789abcdef", estimatedInputTokens: 0, feature: "assistant",
      maximumOutputTokens: 0, streaming: false
    }, fetcher);
    await getRequestEffectiveConfiguration("req_0123456789abcdef", fetcher);
    await getUserOperationImpact("usr_0123456789abcdef", "env_0123456789abcdef", "block", fetcher);

    expect(fetcherMock.mock.calls.map(([path]) => String(path))).toEqual([
      "/admin/v1/users/usr_0123456789abcdef/effective-configuration?environment_id=env_0123456789abcdef&estimated_input_tokens=0&feature=assistant&maximum_output_tokens=0&streaming=false",
      "/admin/v1/requests/req_0123456789abcdef/effective-configuration",
      "/admin/v1/users/usr_0123456789abcdef/operation-impact?action=block&environment_id=env_0123456789abcdef"
    ]);
    expect(EffectiveConfigurationSchema.parse(effective).inputs[0]?.keys).toEqual(["plan"]);
    expect(() => EffectiveConfigurationSchema.parse({ ...effective, provider_secret: "must-not-render" })).toThrow();
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

  it("validates complete family/component trust provenance without credential material", () => {
    const usage = { cost_nano_usd: 42, input_tokens: 10, logical_requests: 1, output_tokens: 5, total_tokens: 15 };
    const root = {
      attestation_provider: "app_attest", component_key_id: "cky_0123456789abcdef", created_at: "2026-08-29T00:00:00Z",
      definition_id: "ios-main", dpop_jkt: "A".repeat(43), environment_id: "env_0123456789abcdef",
      granted_features: ["assistant"], id: "cmp_0123456789abcdef", installation_family_id: "fam_0123456789abcdef",
      is_root: true, key_storage_claim: "secure_enclave", kind: "main_app", last_seen_at: "2026-08-29T00:00:00Z",
      platform: "ios", refresh_reuse_count: 0, request_count: 1, session_failure_count: 0, session_family_id: "csf_0123456789abcdef",
      session_status: "active", status: "active", trust_source: "direct_attested", updated_at: "2026-08-29T00:00:00Z",
      usage, user_id: "usr_0123456789abcdef"
    };
    const child = {
      ...root, component_key_id: "cky_1123456789abcdef", definition_id: "ios-widget", dpop_jkt: "B".repeat(43),
      id: "cmp_1123456789abcdef", is_root: false, key_storage_claim: "keychain", kind: "widget", session_failure_count: 2,
      parent_component_id: root.id, trust_source: "delegated_direct_attested",
      delegation: {
        attestation_expires_at: "2026-08-30T00:00:00Z", attestation_provider: "app_attest",
        configuration_revision_id: "rev_0123456789abcdef", created_at: "2026-08-29T00:00:00Z",
        expires_at: "2026-08-30T00:00:00Z", feature_scopes: ["assistant"], id: "dlg_0123456789abcdef",
        identity_expires_at: "2026-08-30T00:00:00Z", parent_component_id: root.id, trust_level: "app_verified"
      }
    };
    const family = {
      component_count: 2, components: [root, child], created_at: "2026-08-29T00:00:00Z",
      environment_id: "env_0123456789abcdef", id: "fam_0123456789abcdef", last_seen_at: "2026-08-29T00:00:00Z",
      platform: "ios", request_count: 2, root_component_id: root.id, root_trust_source: "direct_attested",
      status: "active", updated_at: "2026-08-29T00:00:00Z", usage, user_id: "usr_0123456789abcdef"
    };

    expect(ClientComponentSchema.parse(child).delegation?.parent_component_id).toBe(root.id);
    expect(ClientComponentSchema.parse(child).trust_source).toBe("delegated_direct_attested");
    expect(ClientComponentSchema.parse(child).session_failure_count).toBe(2);
    expect(InstallationFamilySchema.parse(family).components).toHaveLength(2);
    expect(() => ClientComponentSchema.parse({ ...child, refresh_grant: "must-not-render" })).toThrow();
    expect(() => InstallationFamilySchema.parse({ ...family, components: [{ ...root, parent_component_id: child.id, is_root: false, delegation: child.delegation }, child] })).toThrow();
  });

  it("keeps provider cost provenance and its fixed report source distinct", () => {
	const requestProvenance = {
	  config_revision_id: "rev_0123456789abcdef", decision_stages: [], selected_limit_plan: "subscriber"
	};
	const attempt = {
	  attempt_number: 1, completed_at: "2026-08-29T00:00:02Z",
	  cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost", http_status: 200,
	  first_byte_at: "2026-08-29T00:00:00.500Z", first_token_at: "2026-08-29T00:00:01Z",
	  id: "atm_0123456789abcdef", model: "openai/gpt", started_at: "2026-08-29T00:00:00Z",
	  route: "primary", status: "succeeded", upstream: "openrouter", usage_provenance: "unknown"
	};
	expect(RequestSchema.parse({
	  ...requestProvenance, attempts: [attempt], environment_id: "env_0123456789abcdef", feature: "assistant",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  completed_at: "2026-08-29T00:00:03Z", protocol: "openai_chat",
	  started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  user_id: "usr_0123456789abcdef"
	}).attempts[0]).toEqual(attempt);
	expect(RequestSchema.parse({
	  ...requestProvenance, attempts: [attempt], client_component_id: "cmp_0123456789abcdef",
	  completed_at: "2026-08-29T00:00:03Z", component_definition_id: "ios-main", component_kind: "main_app",
	  environment_id: "env_0123456789abcdef", feature: "assistant", framework: "swift-openai",
	  framework_version: "4.6.0", id: "req_0123456789abcdef", installation_family_id: "fam_0123456789abcdef",
	  installation_id: "ins_0123456789abcdef", protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z",
	  status: "succeeded", trust_source: "direct_attested", user_id: "usr_0123456789abcdef"
	}).framework).toBe("swift-openai");
	expect(() => RequestSchema.parse({
	  ...requestProvenance, attempts: [attempt], client_component_id: "cmp_0123456789abcdef", completed_at: "2026-08-29T00:00:03Z",
	  environment_id: "env_0123456789abcdef", feature: "assistant", id: "req_0123456789abcdef",
	  installation_id: "ins_0123456789abcdef", protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z",
	  status: "succeeded", user_id: "usr_0123456789abcdef"
	})).toThrow();
	expect(() => RequestSchema.parse({
	  ...requestProvenance, attempts: [{ ...attempt, cost_source: "secret source\n" }],
	  environment_id: "env_0123456789abcdef", feature: "assistant",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  completed_at: "2026-08-29T00:00:03Z", protocol: "openai_chat",
	  started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  user_id: "usr_0123456789abcdef"
	})).toThrow();
	const request = {
	  ...requestProvenance, attempts: [attempt], completed_at: "2026-08-29T00:00:03Z",
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
	  ...request, attempts: [{ ...attempt, first_byte_at: undefined }]
	})).toThrow();
	expect(() => RequestSchema.parse({
	  ...request, attempts: [{ ...attempt, first_token_at: "2026-08-29T00:00:02.500Z" }]
	})).toThrow();
	expect(() => RequestSchema.parse({
	  ...request, attempts: [{ ...attempt, failure_code: "upstream_timeout" }]
	})).toThrow();
	expect(() => RequestSchema.parse({
	  ...request, attempts: [{ ...attempt, failure_code: "timeout", status: "failed" }]
	})).not.toThrow();
	const recovered = {
	  ...request, attempts: [], failure_code: "internal_error", status: "failed",
	  decision_stages: [{
	    completed_at: "2026-08-29T00:00:01Z", config_revision_id: requestProvenance.config_revision_id,
	    duration_ms: 1000, limit_plan_key: "subscriber", number: 1, outcome: "succeeded",
	    stage: "policy_evaluated", started_at: "2026-08-29T00:00:00Z"
	  }, {
	    completed_at: "2026-08-29T00:00:03Z", config_revision_id: requestProvenance.config_revision_id,
	    duration_ms: 1000, failure_code: "internal_error", number: 2, outcome: "failed",
	    stage: "lifecycle_recovered", started_at: "2026-08-29T00:00:02Z"
	  }]
	};
	expect(RequestSchema.parse(recovered).decision_stages.at(-1)?.stage).toBe("lifecycle_recovered");
	expect(() => RequestSchema.parse({ ...recovered, decision_stages: recovered.decision_stages.map((stage, index) => index === 1 ? { ...stage, stage: "unregistered_stage" } : stage) })).toThrow();
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

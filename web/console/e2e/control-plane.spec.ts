import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";

const ids = {
  admin: "adm_0123456789abcdef",
  administrator: "adm_1123456789abcdef",
  apiToken: "tok_0123456789abcdef",
  application: "app_01J00000000000000000000000",
  environment: "env_0123456789abcdef",
  organization: "org_0123456789abcdef",
  override: "uov_0123456789abcdef",
  revision: "rev_0123456789abcdef",
  activeRevision: "rev_1123456789abcdef",
  draftRevision: "rev_2123456789abcdef",
  audit: "aud_01J00000000000000000000000",
  auditAdmin: "adm_01J00000000000000000000000",
  auditRequest: "arq_01J00000000000000000000000",
  auditUser: "usr_01J00000000000000000000000",
  request: "req_0123456789abcdef",
  attempt: "atm_0123456789abcdef",
  secret: "sec_0123456789abcdef",
  rotatedSecret: "sec_1123456789abcdef",
  unusedSecret: "sec_2123456789abcdef",
  selfTest: "tst_0123456789abcdef",
  selfTestSchedule: "sts_0123456789abcdef",
  user: "usr_0123456789abcdef"
};
const csrf = "csrf_0123456789abcdefghijklmnopqrstuvwxyz";
const instant = "2026-08-29T00:00:00Z";
const oneTimeAPIToken = "one-time-browser-token-material-1234567890";

type ObservedMutation = { path: string; csrf: string | null };

function nonAdminMutations(mutations: ObservedMutation[]): ObservedMutation[] {
  return mutations.filter(({ path }) => !path.startsWith("/admin/v1/"));
}

function expectOnlyAdminMutations(mutations: ObservedMutation[]): void {
  expect(
    nonAdminMutations(mutations),
    "the console sent a same-origin mutation outside the canonical Admin API"
  ).toEqual([]);
}

function json(route: Route, status: number, body: unknown, headers: Record<string, string> = {}) {
  return route.fulfill({
    body: JSON.stringify(body),
    contentType: status === 200 || status === 201 || status === 202 ? "application/json" : "application/problem+json",
    headers,
    status
  });
}

function problem(route: Route, code: string, status: number, detail: string) {
  return json(route, status, {
    code, detail, request_id: "request_e2e_123456", retryable: false, status,
    title: "Request failed",
    type: `https://docs.latchway.dev/errors/${code.replaceAll("_", "-")}`,
    documentation_url: `https://docs.latchway.dev/errors/${code.replaceAll("_", "-")}`
  });
}

async function installAdminFixture(
  page: Page,
  options: { includePrimarySecret?: boolean } = {}
) {
  let authenticated = false;
  const mutations: ObservedMutation[] = [];
  const administratorBodies: Array<Record<string, unknown>> = [];
  const apiTokenBodies: Array<Record<string, unknown>> = [];
  const applicationBodies: Array<Record<string, unknown>> = [];
  const environmentBodies: Array<Record<string, unknown>> = [];
  const overrideBodies: Array<Record<string, unknown>> = [];
  const revisionBodies: unknown[] = [];
  const configurationPatchBodies: unknown[] = [];
  const configurationETags: Array<{ etag: string | null; path: string }> = [];
  const rollbackBodies: Array<Record<string, unknown>> = [];
  const secretBodies: Array<Record<string, unknown>> = [];
  const selfTestBodies: Array<Record<string, unknown>> = [];
  const selfTestScheduleBodies: Array<Record<string, unknown>> = [];
  const selfTestScheduleAuthorizations: Array<{ authorization?: string; cookie?: string; csrf?: string }> = [];
  let apiTokens: Array<Record<string, unknown>> = [];
  let selfTestRun: Record<string, unknown> | undefined;
  let selfTestSchedules: Array<Record<string, unknown>> = [];
  let secretItems: Array<Record<string, unknown>> = options.includePrimarySecret === false ? [] : [{
    algorithm: "xchacha20poly1305", created_at: instant, environment_id: ids.environment,
    id: ids.secret, master_key_id: "master-key", name: "primary_api_key", version: 1
  }];
  let userOverride: Record<string, unknown> | undefined;
  const configurationDocument = {
    apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig",
    metadata: { application: "mobile-app", environment: "production", labels: { retained: "yes" }, organization: "example" },
    spec: {
      attestationPolicies: [{ id: "native", platforms: { react_native_ios: { appAttest: { allowedBundleVersions: ["1"], allowedValidationCategories: [4], appIdPrefix: "TEAMID", bundleId: "com.example.app", environment: "production" }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" } } }],
      features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "assistant", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "assistant_default", priority: 10, when: "true" }] }],
      identityProviders: [{ id: "firebase", projectId: "example-mobile", type: "firebase" }],
      inputAccountingProfiles: [{ id: "assistant_input", maximumContextTokens: 128000, maximumFramingTokensPerMessage: 4, maximumFramingTokensPerRequest: 8, method: "utf8_byte_bpe_declared_framing_v1", physicalModel: "gpt-5-mini", protocol: "openai_responses" }],
      limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], timezone: "UTC", window: "1d" }] }],
      models: [{ capabilities: ["openai_responses"], id: "assistant_default", inputAccountingRef: "assistant_input", pricingRef: "operator_pricing", upstream: "openai", upstreamModel: "gpt-5-mini" }],
      pricingCatalogs: [{ currency: "USD", entries: [{ inputNanoUsdPerMillion: 250000, model: "assistant_default", outputNanoUsdPerMillion: 2000000, requestNanoUsd: 0 }], id: "operator_pricing" }],
      upstreams: [{ authentication: { type: "none" }, baseUrl: "https://api.openai.com/v1", id: "openai", type: "openai_compatible" }]
    }
  };
  let createdRevisionDocument: unknown = configurationDocument;
  let activeConfigurationDocument: unknown = configurationDocument;
  let activeConfigurationRevisionID = ids.activeRevision;
  let activeConfigurationVersion = 2;
  let userStatus: "active" | "blocked" = "active";
  const session = {
    administrator: { email: "owner@example.test", enabled: true, id: ids.admin },
    capabilities: ["activate_configuration", "inspect_users", "manage_owners", "manage_secrets", "revoke_installations", "run_self_tests"],
    expires_at: null,
    memberships: [{ organization_id: ids.organization, role: "owner" }],
    organization_id: ids.organization
  };
  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const pageURL = page.url();
    const isSameOrigin = pageURL !== "about:blank" && new URL(pageURL).origin === url.origin;
    if (isSameOrigin && request.method() !== "GET") {
      mutations.push({ path: url.pathname, csrf: request.headers()["x-csrf-token"] ?? null });
      if (!url.pathname.startsWith("/admin/v1/")) {
        return problem(route, "method_not_allowed", 405, "Console mutations must use the Admin API.");
      }
    }
    if (url.pathname === "/healthz") return route.fulfill({ body: "ok", status: 200 });
    if (url.pathname === "/readyz") return json(route, 200, { checks: { database: true }, status: "ready" });
    if (!url.pathname.startsWith("/admin/v1/")) return route.continue();
    if (url.pathname === "/admin/v1/auth/session") return authenticated ? json(route, 200, session) : problem(route, "authentication_required", 401, "Sign in.");
    if (url.pathname === "/admin/v1/auth/login") { authenticated = true; return json(route, 200, session, { "X-CSRF-Token": csrf }); }
    if (url.pathname === "/admin/v1/auth/logout") { authenticated = false; return route.fulfill({ status: 204 }); }
    if (url.pathname === "/admin/v1/administrators" && request.method() === "GET") return json(route, 200, { items: [{ created_at: instant, display_name: "Owner", email: "owner@example.test", id: ids.admin, membership_id: "amb_0123456789abcdef", organization_id: ids.organization, password_reset_required: false, role: "owner", status: "active", updated_at: instant }], page: { has_more: false } });
    if (url.pathname === "/admin/v1/administrators" && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; administratorBodies.push(body);
      return json(route, 201, { created_at: instant, display_name: body.display_name, email: body.email, id: ids.administrator, membership_id: "amb_1123456789abcdef", organization_id: ids.organization, password_reset_required: false, role: body.role, status: "active", updated_at: instant });
    }
    if (url.pathname.startsWith(`/admin/v1/administrators/${ids.administrator}/`)) {
      const action = url.pathname.split("/").at(-1); const body = JSON.parse(request.postData() || "{}") as Record<string, unknown>; administratorBodies.push({ action, ...body });
      return json(route, 200, { created_at: instant, display_name: "Second Owner", email: "second-owner@example.test", id: ids.administrator, membership_id: "amb_1123456789abcdef", organization_id: ids.organization, password_reset_required: false, role: action === "role" ? body.role : "operator", status: action === "disable" ? "disabled" : "active", updated_at: instant, ...(action === "disable" ? { disabled_at: instant } : {}) });
    }
    if (url.pathname === "/admin/v1/api-tokens" && request.method() === "GET") return json(route, 200, { items: apiTokens });
    if (url.pathname === "/admin/v1/api-tokens" && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
      apiTokenBodies.push(body);
      const metadata = { created_at: instant, id: ids.apiToken, name: body.name, revoked: false, scopes: body.scopes };
      apiTokens = [...apiTokens, metadata];
      return json(route, 201, { metadata, token: oneTimeAPIToken });
    }
    if (url.pathname === `/admin/v1/api-tokens/${ids.apiToken}` && request.method() === "DELETE") {
      apiTokenBodies.push({ action: "revoke", token_id: ids.apiToken });
      apiTokens = apiTokens.map((token) => token.id === ids.apiToken ? { ...token, revoked: true } : token);
      return route.fulfill({ status: 204 });
    }
    if (url.pathname === "/admin/v1/applications" && request.method() === "GET") return json(route, 200, { items: [{ created_at: instant, display_name: "Mobile App", id: ids.application, organization_id: ids.organization, slug: "mobile-app", status: "active" }], page: { has_more: false } });
    if (url.pathname === "/admin/v1/applications" && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; applicationBodies.push(body);
      return json(route, 201, { created_at: instant, display_name: body.display_name, id: ids.application, organization_id: ids.organization, slug: body.slug, status: "active" });
    }
    if (url.pathname === `/admin/v1/applications/${ids.application}/environments` && request.method() === "GET") return json(route, 200, { items: [{ application_id: ids.application, created_at: instant, display_name: "Production", id: ids.environment, kind: "production", slug: "production", status: "active" }] });
    if (url.pathname === `/admin/v1/applications/${ids.application}/environments` && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; environmentBodies.push(body);
      return json(route, 201, { application_id: ids.application, created_at: instant, display_name: body.display_name, id: ids.environment, kind: body.kind, slug: body.slug, status: "active" });
    }
    if (url.pathname === "/admin/v1/secrets" && request.method() === "GET") return json(route, 200, { items: secretItems, page: { has_more: false } });
    if (url.pathname === "/admin/v1/secrets" && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; secretBodies.push(body);
      const created = { algorithm: "xchacha20poly1305", created_at: instant, environment_id: ids.environment, id: body.name === "primary_api_key" ? ids.secret : ids.unusedSecret, master_key_id: "master-key", name: body.name, version: 1 };
      secretItems = [created, ...secretItems.filter((item) => item.name !== body.name)];
      return json(route, 201, created);
    }
    if (url.pathname.startsWith("/admin/v1/secrets/") && url.pathname.endsWith("/rotate") && request.method() === "POST") {
      const currentID = url.pathname.split("/").at(-2) ?? "";
      const current = secretItems.find((item) => item.id === currentID);
      if (!current) return problem(route, "resource_conflict", 409, "The secret version is stale.");
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; secretBodies.push({ action: "rotate", secret_id: currentID, ...body });
      const rotated = { ...current, id: ids.rotatedSecret, rotated_at: instant, version: Number(current.version) + 1 };
      secretItems = secretItems.map((item) => item.id === currentID ? rotated : item);
      return json(route, 201, rotated);
    }
    if (url.pathname.startsWith("/admin/v1/secrets/") && request.method() === "DELETE") {
      const currentID = url.pathname.split("/").at(-1) ?? "";
      if (!secretItems.some((item) => item.id === currentID)) return problem(route, "resource_conflict", 409, "The secret version is stale.");
      secretBodies.push({ action: "delete", secret_id: currentID });
      secretItems = secretItems.filter((item) => item.id !== currentID);
      return route.fulfill({ status: 204 });
    }
    if (url.pathname === `/admin/v1/environments/${ids.environment}/config-revisions` && request.method() === "GET") return json(route, 200, { items: [{ activated_at: instant, created_at: instant, created_by: ids.admin, document: configurationDocument, environment_id: ids.environment, id: ids.revision, state: "superseded", version: 1 }], page: { has_more: false } });
    if (url.pathname === `/admin/v1/environments/${ids.environment}/config-revisions` && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
      if (body.base_revision_id === activeConfigurationRevisionID) {
        revisionBodies.push(body);
        return json(route, 201, { created_at: instant, created_by: ids.admin, document: activeConfigurationDocument, environment_id: ids.environment, id: ids.draftRevision, state: "draft", version: 3 }, { ETag: '"draft-etag-1"' });
      }
      const document = body.document as unknown;
      createdRevisionDocument = document;
      revisionBodies.push(document);
      return json(route, 201, { created_at: instant, created_by: ids.admin, document, environment_id: ids.environment, id: ids.revision, state: "draft", version: 1 }, { ETag: '"revision-etag"' });
    }
    if (url.pathname === `/admin/v1/environments/${ids.environment}/config` && request.method() === "GET") return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: activeConfigurationDocument, environment_id: ids.environment, id: activeConfigurationRevisionID, state: "active", version: activeConfigurationVersion }, { ETag: '"active-revision-etag"' });
    if (url.pathname === `/admin/v1/environments/${ids.environment}/rollback` && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; rollbackBodies.push({ audit_reason: request.headers()["x-latchway-audit-reason"], etag: request.headers()["if-match"], ...body });
      return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: configurationDocument, environment_id: ids.environment, id: ids.revision, state: "active", version: 3 }, { ETag: '"restored-revision-etag"' });
    }
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/validate`) return json(route, 200, { checked_at: instant, issues: [], valid: true });
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/plan`) return problem(route, "resource_not_found", 404, "No active configuration exists.");
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}` && request.method() === "GET") return json(route, 200, { created_at: instant, created_by: ids.admin, document: createdRevisionDocument, environment_id: ids.environment, id: ids.revision, state: "valid", version: 1 }, { ETag: '"revision-etag"' });
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/activate`) return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: createdRevisionDocument, environment_id: ids.environment, id: ids.revision, state: "active", version: 1 });
    if (url.pathname === `/admin/v1/config-revisions/${ids.draftRevision}` && request.method() === "PATCH") {
      activeConfigurationDocument = JSON.parse(request.postData() ?? "{}");
      configurationPatchBodies.push(activeConfigurationDocument);
      configurationETags.push({ etag: request.headers()["if-match"] ?? null, path: url.pathname });
      return json(route, 200, { created_at: instant, created_by: ids.admin, document: activeConfigurationDocument, environment_id: ids.environment, id: ids.draftRevision, state: "draft", version: 3 }, { ETag: '"draft-etag-2"' });
    }
    if (url.pathname === `/admin/v1/config-revisions/${ids.draftRevision}/validate`) return json(route, 200, { checked_at: instant, issues: [], valid: true });
    if (url.pathname === `/admin/v1/config-revisions/${ids.draftRevision}/plan`) return json(route, 200, { changes: [{ operation: "replace", path: "/spec/upstreams/0/baseUrl" }], from_revision_id: ids.activeRevision, to_revision_id: ids.draftRevision, warnings: [] });
    if (url.pathname === `/admin/v1/config-revisions/${ids.draftRevision}/activate`) {
      configurationETags.push({ etag: request.headers()["if-match"] ?? null, path: url.pathname });
      activeConfigurationRevisionID = ids.draftRevision;
      activeConfigurationVersion = 3;
      return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: activeConfigurationDocument, environment_id: ids.environment, id: ids.draftRevision, state: "active", version: 3 }, { ETag: '"targeted-active-etag"' });
    }
    if (url.pathname === "/admin/v1/usage/summary") return json(route, 200, {
      analytics: {
        active_users: 2, attestation_failure_rate: { denominator: 4, numerator: 1, parts_per_million: 250000 },
        by_feature: { items: [{ active_users: 2, key: "assistant", request_count: 3, values: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 3, output_tokens: 20, total_tokens: 30 } }], limit: 50, truncated: false },
        by_model: { items: [{ active_users: 2, key: "assistant_default", request_count: 3, values: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 3, output_tokens: 20, total_tokens: 30 } }], limit: 50, truncated: false },
        by_selected_plan: { items: [{ active_users: 2, key: "free", request_count: 3, values: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 3, output_tokens: 20, total_tokens: 30 } }], limit: 50, truncated: false },
        cost_per_active_user_nano_usd: { denominator: 2, numerator: 900 }, failure_rate: { denominator: 3, numerator: 1, parts_per_million: 333333 }, fallback_rate: { denominator: 3, numerator: 1, parts_per_million: 333333 }, quota_denial_rate: { denominator: 3, numerator: 0, parts_per_million: 0 }, request_count: 3,
        request_latency: { p50_ms: 100, p95_ms: 300, p99_ms: 500, samples: 3 }, requests_per_active_user: { denominator: 2, numerator: 3 }, time_to_first_token: { p50_ms: 20, p95_ms: 40, p99_ms: 60, samples: 3 },
        usage_by_provenance: [
          { cost_source: "openrouter_usage_cost", provenance: "upstream_reported", values: { cost_nano_usd: 700, input_tokens: 10, logical_requests: 2, output_tokens: 20, total_tokens: 30 } },
          { cost_source: "operator_pricing", provenance: "calculated", values: { cost_nano_usd: 200, input_tokens: 0, logical_requests: 1, output_tokens: 0, total_tokens: 0 } },
          { provenance: "estimated", values: { cost_nano_usd: 0, input_tokens: 0, logical_requests: 0, output_tokens: 0, total_tokens: 0 } },
          { provenance: "unknown", values: { cost_nano_usd: 0, input_tokens: 0, logical_requests: 0, output_tokens: 0, total_tokens: 0 } }
        ]
      }, end: "2026-08-29T01:00:00Z", provenance: ["upstream_reported", "calculated"], start: instant,
      values: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 3, output_tokens: 20, total_tokens: 30 }
    });
    if (url.pathname === "/admin/v1/usage/timeseries") return json(route, 200, { interval: url.searchParams.get("interval") ?? "hour", points: [{ timestamp: instant, values: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 3, output_tokens: 20, total_tokens: 30 } }] });
    const requestDetail = {
      attempts: [{ attempt_number: 1, completed_at: "2026-08-29T00:00:02.500Z", cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost", first_byte_at: "2026-08-29T00:00:00.500Z", first_token_at: "2026-08-29T00:00:00.750Z", http_status: 200, id: ids.attempt, model: "openai/gpt", route: "primary", started_at: instant, status: "succeeded", upstream: "openrouter", usage: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 0, output_tokens: 20, total_tokens: 30 }, usage_provenance: "upstream_reported" }],
      completed_at: "2026-08-29T00:00:03Z",
      config_revision_id: ids.activeRevision,
      decision_stages: [{
        completed_at: "2026-08-29T00:00:00.010Z",
        config_revision_id: ids.activeRevision,
        duration_ms: 10,
        number: 1,
        outcome: "succeeded",
        stage: "identity_verified",
        started_at: instant
      }, {
        completed_at: "2026-08-29T00:00:00.020Z",
        config_revision_id: ids.activeRevision,
        duration_ms: 10,
        number: 2,
        outcome: "succeeded",
        stage: "client_trust_verified",
        started_at: "2026-08-29T00:00:00.010Z"
      }, {
        completed_at: "2026-08-29T00:00:00.030Z",
        config_revision_id: ids.activeRevision,
        duration_ms: 10,
        number: 3,
        outcome: "succeeded",
        stage: "configuration_loaded",
        started_at: "2026-08-29T00:00:00.020Z"
      }, {
        completed_at: "2026-08-29T00:00:00.040Z",
        config_revision_id: ids.activeRevision,
        duration_ms: 10,
        model: "assistant_default",
        number: 4,
        outcome: "succeeded",
        physical_model: "gpt-5-mini",
        route: "primary",
        stage: "route_selected",
        started_at: "2026-08-29T00:00:00.030Z",
        upstream: "openrouter"
      }, {
        completed_at: "2026-08-29T00:00:00.050Z",
        config_revision_id: ids.activeRevision,
        duration_ms: 10,
        limit_algorithm: "calendar",
        limit_maximum: 100,
        limit_metric: "logical_requests",
        limit_plan_key: "free",
        limit_rule_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        number: 5,
        outcome: "succeeded",
        stage: "quota_rule_evaluated",
        started_at: "2026-08-29T00:00:00.040Z"
      }],
      environment_id: ids.environment,
      feature: "assistant",
      id: ids.request,
      installation_id: "ins_0123456789abcdef",
      protocol: "openai_chat",
      selected_limit_plan: "free",
      selected_model: "assistant_default",
      selected_physical_model: "gpt-5-mini",
      selected_route: "primary",
      selected_upstream: "openrouter",
      started_at: instant,
      status: "succeeded",
      usage: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 1, output_tokens: 20, total_tokens: 30 },
      user_id: ids.user
    };
    if (url.pathname === "/admin/v1/requests") return json(route, 200, { items: [requestDetail], page: { has_more: false } });
    if (url.pathname === `/admin/v1/requests/${ids.request}`) return json(route, 200, requestDetail);
    const auditChange = { classification: "public", field: "status", operation: "set", redacted: false };
    const auditEvent = {
      action: "admin.user_block",
      actor: `admin_user:${ids.auditAdmin}`,
      actor_id: ids.auditAdmin,
      actor_kind: "admin_user",
      changes: [auditChange],
      environment_id: ids.environment,
      id: ids.audit,
      reason: "security_response",
      request_id: ids.auditRequest,
      resource_id: ids.auditUser,
      resource_type: "application_user",
      result: "succeeded",
      source: "console",
      summary: { changes: [auditChange] },
      target: `application_user:${ids.auditUser}`,
      timestamp: instant
    };
    if (url.pathname === "/admin/v1/audit-events") return json(route, 200, { items: [auditEvent], page: { has_more: false } });
    if (url.pathname === `/admin/v1/audit-events/${ids.audit}`) return json(route, 200, auditEvent);
    if (url.pathname === `/admin/v1/config-revisions/${activeConfigurationRevisionID}/simulate`) return json(route, 200, {
      allowed: true, application_id: ids.application, environment_id: ids.environment, environment_kind: "production", explanation: ["production policy allowed"],
      facts: { application_id: ids.application, authenticated: true, environment_id: ids.environment, environment_kind: "production", feature: "assistant", framing_unit_count: 1, image_units: 0, normalized_claims: {}, platform: "react_native_ios", requested_input_tokens: 0, requested_output_max: 0, revision_id: activeConfigurationRevisionID, rewritten_request_bytes: 1024, streaming: false, tool_calls: 0, trust_level: "app_verified" },
      fact_usage: [], feature: "assistant", limit_plan: "free", limits: [], model: "assistant_default", physical_model: "gpt-5-mini", pricing_confidence: "configured", protocol: "openai_responses", revision_id: activeConfigurationRevisionID, route: "primary", upstream: "openai", warnings: []
    });
    if (url.pathname === "/admin/v1/self-test-schedules" && request.method() === "GET") return json(route, 200, { items: selfTestSchedules, page: { has_more: false } });
    if (url.pathname === "/admin/v1/self-test-schedules" && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
      selfTestScheduleBodies.push(body);
      selfTestScheduleAuthorizations.push({ authorization: request.headers().authorization, cookie: request.headers().cookie, csrf: request.headers()["x-csrf-token"] });
      const schedule = {
        application_id: ids.application, authorization_credential_id: ids.apiToken,
        config_revision_id: activeConfigurationRevisionID, created_at: instant,
        daily_cost_limit_nano_usd: body.daily_cost_limit_nano_usd, environment_id: body.environment_id,
        id: ids.selfTestSchedule, interval_seconds: body.interval_seconds, kind: body.kind,
        max_cost_nano_usd: body.max_cost_nano_usd, model: body.model,
        next_run_at: "2026-08-29T01:00:00Z", status: "active", updated_at: instant, upstream: body.upstream
      };
      selfTestSchedules = [schedule];
      return json(route, 201, schedule);
    }
    if (url.pathname === `/admin/v1/self-test-schedules/${ids.selfTestSchedule}` && request.method() === "GET") return json(route, 200, selfTestSchedules[0]);
    if (url.pathname === `/admin/v1/self-test-schedules/${ids.selfTestSchedule}` && request.method() === "DELETE") {
      const disabled = { ...selfTestSchedules[0], disabled_at: "2026-08-29T00:10:00Z", disabled_reason_code: "operator_disabled", next_run_at: undefined, status: "disabled", updated_at: "2026-08-29T00:10:00Z" };
      selfTestSchedules = [disabled];
      return json(route, 200, disabled);
    }
    if (url.pathname === `/admin/v1/self-tests/${ids.selfTest}` && request.method() === "GET" && selfTestRun) return json(route, 200, selfTestRun);
    if (url.pathname === "/admin/v1/self-tests") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
      selfTestBodies.push(body);
      const kind = typeof body.kind === "string" ? body.kind : "local";
      selfTestRun = { checks: [{ name: kind === "local" ? "database" : "usage", safe_detail: kind === "local" ? "PostgreSQL transaction completed." : "Bounded provider usage passed.", state: "passed" }], completed_at: instant, created_at: instant, id: ids.selfTest, kind, state: "passed" };
      return json(route, 202, selfTestRun);
    }
    if (url.pathname === `/admin/v1/users/${ids.user}` && request.method() === "GET") return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: userStatus, ...(userOverride ? { limit_plan_override: userOverride } : {}) });
    if (url.pathname === `/admin/v1/users/${ids.user}/limit-override` && request.method() === "PUT") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; overrideBodies.push(body);
      userOverride = { created_at: instant, id: ids.override, limit_plan: body.limit_plan, reason: body.reason, ...(body.expires_at ? { expires_at: body.expires_at } : {}) };
      return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], limit_plan_override: userOverride, normalized_claims: { plan: "standard" }, status: "active" });
    }
    if (url.pathname === `/admin/v1/users/${ids.user}/limit-override` && request.method() === "DELETE") { overrideBodies.push({ action: "clear", user_id: ids.user }); userOverride = undefined; return route.fulfill({ status: 204 }); }
    if (url.pathname === "/admin/v1/users" && request.method() === "GET") return json(route, 200, { items: [{ created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: userStatus }], page: { has_more: false } });
    if (url.pathname === `/admin/v1/users/${ids.user}/operation-impact` && request.method() === "GET") return json(route, 200, {
      access_effect: "deny_and_revoke", action: "block", applicable: userStatus === "active",
      counts: { active_client_components: 2, active_component_refresh_tokens: 2, active_component_sessions: 2, active_installation_families: 1, active_refresh_tokens: 1, active_session_grants: 1 },
      current_status: userStatus, immediate: true, impact_token: "A".repeat(43), reversible: true,
      summary: "Blocks access and revokes active credentials application-wide."
    });
    if (url.pathname === `/admin/v1/users/${ids.user}/block` && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
      if (body.impact_token !== "A".repeat(43) || body.acknowledge_immediate_effect !== true) return problem(route, "conflict", 409, "The reviewed impact is stale.");
      userStatus = "blocked";
      return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: userStatus });
    }
    return problem(route, "resource_not_found", 404, "Fixture endpoint not found.");
  });
  return { administratorBodies, apiTokenBodies, applicationBodies, configurationETags, configurationPatchBodies, environmentBodies, mutations, overrideBodies, revisionBodies, rollbackBodies, secretBodies, selfTestBodies, selfTestScheduleAuthorizations, selfTestScheduleBodies };
}

test("mutation proof records and rejects a same-origin non-Admin write", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");

  const status = await page.evaluate(async () => {
    const response = await fetch("/v1/responses", { method: "POST" });
    return response.status;
  });

  expect(status).toBe(405);
  expect(fixture.mutations).toEqual([{ csrf: null, path: "/v1/responses" }]);
  expect(nonAdminMutations(fixture.mutations)).toEqual(fixture.mutations);
});

test("authenticated console has no automated WCAG A or AA violations", async ({ page }) => {
  await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("heading", { name: "The gateway is ready for control-plane work." })).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("keyboard navigation reaches content, traps the command dialog, and restores focus", async ({ browserName, page }) => {
  await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("heading", { name: "The gateway is ready for control-plane work." })).toBeVisible();

  await page.reload();
  await expect(page.getByRole("heading", { name: "The gateway is ready for control-plane work." })).toBeVisible();
  const skipLink = page.getByRole("link", { name: "Skip to main content" });
  if (browserName === "webkit") {
    // WebKit follows the host Safari preference that can omit links from sequential Tab order.
    await skipLink.focus();
  } else {
    await page.keyboard.press("Tab");
  }
  await expect(skipLink).toBeFocused();
  await skipLink.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  const commandTrigger = page.getByRole("button", { name: "Search or jump" });
  await commandTrigger.focus();
  await commandTrigger.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Go to an operator task" });
  await expect(dialog).toBeVisible();
  await expect(page.getByPlaceholder("Feature, request, setup, health…")).toBeFocused();
  const closeButton = dialog.getByRole("button", { name: "Close command palette" });
  await closeButton.focus();
  await page.keyboard.press("Shift+Tab");
  await expect(dialog.getByRole("link").last()).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(closeButton).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(commandTrigger).toBeFocused();
});

test("@mobile authenticated incident navigation fits a phone viewport", async ({ page }) => {
  await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("heading", { name: "The gateway is ready for control-plane work." })).toBeVisible();

  const primaryNavigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(primaryNavigation).toBeVisible();
  await primaryNavigation.getByRole("link", { name: /^Requests/ }).click();
  await expect(page.getByRole("heading", { name: "Understand what happened." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Refresh requests" })).toBeVisible();
  const viewport = await page.evaluate(() => ({ documentWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth }));
  expect(viewport.documentWidth).toBeLessThanOrEqual(viewport.viewportWidth + 1);
});

test("first run, Admin-only mutation path, user block, and logout", async ({ page }) => {
  const fixture = await installAdminFixture(page, { includePrimarySecret: false });
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("heading", { name: "The gateway is ready for control-plane work." })).toBeVisible();
  await page.getByRole("link", { name: /Setup wizard/ }).click();
  await page.getByLabel("Organization slug").fill("example");
  await page.getByLabel("Application name").fill("Mobile App");
  await page.getByLabel("Application slug").fill("mobile-app");
  await page.getByLabel("Firebase project ID").fill("example-mobile");
  await page.getByLabel("Environment kind").selectOption("production");
  await page.getByLabel("App ID prefix").fill("TEAM1234");
  await page.getByLabel("Bundle ID", { exact: true }).fill("com.example.mobile");
  await page.getByLabel("Signing or distribution").selectOption("app_store");
  await page.getByLabel("Allowed CFBundleVersion (build number)").fill("234");
  await page.getByLabel("Package name").fill("com.example.mobile.android");
  await page.getByLabel("Cloud project number").fill("123456789");
  await page.getByLabel("Certificate SHA-256 digest (base64url)").fill(
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
  );
  await page.getByLabel("Input price (nano-USD per million tokens)").fill("250000");
  await page.getByLabel("Output price (nano-USD per million tokens)").fill("2000000");
  await page.getByRole("button", { name: "Create application and environment" }).click();
  await expect(page.getByRole("heading", { name: "Write-only upstream credential" })).toBeVisible();
  const generated = JSON.parse(await page.getByLabel("Full configuration JSON").inputValue()) as {
    spec: {
      attestationPolicies: Array<{ platforms: Record<string, unknown> }>;
      inputAccountingProfiles: Array<Record<string, unknown>>;
      models: Array<Record<string, unknown>>;
      pricingCatalogs: Array<Record<string, unknown>>;
      upstreams: Array<Record<string, unknown>>;
      limitPlans: Array<{ limits: Array<Record<string, unknown>> }>;
    };
  };
  expect(Object.keys(generated.spec.attestationPolicies[0]?.platforms ?? {}).sort()).toEqual([
    "react_native_android", "react_native_ios"
  ]);
  expect(generated.spec.attestationPolicies[0]?.platforms).toMatchObject({
    react_native_ios: { minimumTrustLevel: "app_verified", appAttest: { environment: "production", allowedValidationCategories: [4], allowedBundleVersions: ["234"] } },
    react_native_android: { minimumTrustLevel: "device_verified" }
  });
  expect(generated.spec.inputAccountingProfiles[0]).toMatchObject({
    protocol: "openai_responses", physicalModel: "gpt-5-mini",
    maximumFramingTokensPerRequest: 8, maximumFramingTokensPerMessage: 4,
    maximumContextTokens: 128000
  });
  expect(generated.spec.models[0]).toMatchObject({
    upstreamModel: "gpt-5-mini", capabilities: ["openai_responses"],
    inputAccountingRef: "assistant_default_responses_accounting", pricingRef: "operator_pricing"
  });
  expect(generated.spec.upstreams[0]).toMatchObject({ authentication: { type: "bearer", secretRef: "secret/primary_api_key" } });
  expect(generated.spec.pricingCatalogs[0]).toMatchObject({ entries: [{ model: "assistant_default", inputNanoUsdPerMillion: 250000, outputNanoUsdPerMillion: 2000000 }] });
  expect(generated.spec.limitPlans[0]?.limits).toEqual(expect.arrayContaining([
    expect.objectContaining({ metric: "input_tokens", algorithm: "calendar", hard: true }),
    expect.objectContaining({ metric: "total_tokens", algorithm: "calendar", hard: true }),
    expect.objectContaining({ metric: "input_tokens", algorithm: "per_request", hard: true })
  ]));
  const snippets = await page.locator("pre").allTextContents();
  expect(snippets).toHaveLength(1);
  expect(snippets.every((snippet) => snippet.includes(ids.application))).toBe(true);
  expect(snippets[0]).toContain("baseURL: gatewayURL");
  expect(snippets[0]).toContain('identityProvider: "firebase"');
  expect(snippets[0]).toContain('playIntegrityCloudProjectNumber: "123456789"');
  expect(snippets[0]).toContain('latchway.fetch("/v1/responses"');
  expect(snippets[0]).toContain('latchwayFeature: "assistant"');
  expect(snippets.join("\n")).not.toContain("applicationID: \"mobile-app\"");
  expect(snippets.join("\n")).not.toContain("window.location.origin");
  await page.getByLabel("Secret value").fill("test-only-upstream-key");
  await page.getByRole("button", { name: "Add credential" }).click();
  await expect(page.getByRole("button", { name: "Credential added" })).toBeVisible();
  await expect(page.getByLabel("Secret value")).toHaveValue("");
  await page.getByRole("button", { name: "Validate and activate with ETag" }).click();
  await expect(page.getByText(/is active/)).toBeVisible();
  await page.getByRole("button", { name: "Run bounded upstream self-test" }).click();
  await expect(page.getByText(/Self-test .*passed/)).toBeVisible();
  expect(fixture.selfTestBodies).toEqual([{
    environment_id: ids.environment,
    kind: "upstream",
    max_cost_nano_usd: 10_000_000,
    model: "assistant_default",
    upstream: "primary"
  }]);
  expect(fixture.revisionBodies).toHaveLength(1);
  expect(fixture.revisionBodies[0]).toEqual(expect.objectContaining({
    spec: expect.objectContaining({ models: expect.arrayContaining([
      expect.objectContaining({ inputAccountingRef: "assistant_default_responses_accounting" })
    ]) })
  }));

  await page.getByRole("link", { name: /^Users/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "List users" }).click();
  await page.getByRole("button", { name: ids.user }).click();
  await page.getByRole("button", { name: "Review block" }).click();
  await expect(page.getByRole("heading", { name: "Block user impact" })).toBeVisible();
  await page.getByLabel("Operator reason").fill("Confirmed compromised account");
  await page.getByLabel("Type the exact user ID to confirm").fill(ids.user);
  await page.getByLabel(/acknowledge the immediate application-wide effect/i).check();
  await page.getByRole("button", { name: "Confirm Block user" }).click();
  await expect(page.getByRole("status")).toContainText("Block user completed");
  await expect(page.getByRole("button", { name: "Review unblock" })).toBeVisible();

  expect(fixture.mutations.length).toBeGreaterThanOrEqual(8);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in before opening this control-plane view." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toHaveCount(0);
  expectOnlyAdminMutations(fixture.mutations);
  expect(fixture.mutations.every(({ path, csrf: token }) => path === "/admin/v1/auth/login" || token === csrf)).toBe(true);
});

test("owner completes resource, secret, override, and exact-ETag rollback workflows", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();

  await page.getByRole("link", { name: /^Applications/ }).click();
  await page.getByRole("button", { name: "Load applications" }).click();
  await expect(page.getByText(ids.application)).toBeVisible();
  await page.getByLabel("Display name").fill("Resource App");
  await page.getByLabel("Slug").fill("resource-app");
  await page.getByRole("button", { name: "Create application" }).click();
  expect(fixture.applicationBodies.at(-1)).toEqual({ display_name: "Resource App", organization_id: ids.organization, slug: "resource-app" });

  await page.getByRole("link", { name: /^Environments/ }).click();
  await page.getByLabel("Application ID").fill(ids.application);
  await page.getByRole("button", { name: "Load environments" }).click();
  await expect(page.getByText(ids.environment)).toBeVisible();
  await page.getByLabel("Display name").fill("Staging");
  await page.getByLabel("Slug").fill("staging");
  await page.getByLabel("Kind").selectOption("staging");
  await page.getByRole("button", { name: "Create environment" }).click();
  expect(fixture.environmentBodies.at(-1)).toEqual({ display_name: "Staging", kind: "staging", slug: "staging" });

  await page.getByRole("link", { name: /^Secrets/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load secret metadata" }).click();
  await expect(page.getByText(ids.secret)).toBeVisible();
  await page.getByLabel("Secret name").fill("unused_provider_key");
  await page.getByLabel("Secret value").fill("transient-create-secret");
  await page.getByRole("button", { name: "Create secret" }).click();
  await expect(page.getByLabel("Secret value")).toHaveValue("");
  await expect(page.getByText(ids.unusedSecret)).toBeVisible();
  expect(await page.locator("body").innerText()).not.toContain("transient-create-secret");

  const primaryRow = page.getByRole("row", { name: /primary_api_key/ });
  await primaryRow.getByRole("button", { name: "Rotate" }).click();
  await page.getByLabel("Replacement secret value").fill("transient-rotation-secret");
  await page.getByRole("button", { name: "Rotate secret" }).click();
  await expect(page.getByText(ids.rotatedSecret)).toBeVisible();
  expect(await page.locator("body").innerText()).not.toContain("transient-rotation-secret");

  const unusedRow = page.getByRole("row", { name: /unused_provider_key/ });
  await unusedRow.getByRole("button", { name: "Delete unreferenced" }).click();
  await expect(page.getByText(ids.unusedSecret, { exact: true }).last()).toBeVisible();
  await page.getByRole("button", { name: "Cancel deletion" }).click();
  expect(fixture.secretBodies.some((body) => body.action === "delete")).toBe(false);
  await unusedRow.getByRole("button", { name: "Delete unreferenced" }).click();
  await page.getByLabel("Type unused_provider_key to confirm").fill("unused_provider_key");
  await page.getByRole("button", { name: "Permanently delete secret" }).click();
  await expect(page.getByText(ids.unusedSecret)).toHaveCount(0);
  expect(fixture.secretBodies.at(-1)).toEqual({ action: "delete", secret_id: ids.unusedSecret });
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });

  await page.getByRole("link", { name: /^User overrides/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByLabel("User ID").fill(ids.user);
  await page.getByRole("button", { name: "Inspect override" }).click();
  await expect(page.getByText("No override")).toBeVisible();
  await page.getByLabel("Limit plan").fill("subscriber");
  await page.getByLabel("Reason").fill("support-approved");
  await page.getByRole("button", { name: "Set override" }).click();
  await expect(page.getByText("Reason: support-approved")).toBeVisible();
  await page.getByRole("button", { name: "Clear override" }).click();
  await expect(page.getByText("No override")).toBeVisible();
  expect(fixture.overrideBodies).toEqual([
    { limit_plan: "subscriber", reason: "support-approved" },
    { action: "clear", user_id: ids.user }
  ]);

  await page.getByRole("link", { name: /^Configuration revisions/ }).click();
  await expect(page.locator(".resource-result")).toContainText(`Active revision: ${ids.activeRevision}`);
  await page.getByRole("button", { name: "Review rollback" }).click();
  await page.getByLabel("Operator reason").fill("restore known-good revision");
  await page.getByRole("button", { name: "Confirm rollback to revision 1" }).click();
  await expect(page.locator(".resource-result")).toContainText(`Active revision: ${ids.revision}`);
  expect(fixture.rollbackBodies).toEqual([{ audit_reason: "operator_reason_provided", etag: '"active-revision-etag"', reason: "restore known-good revision", revision_id: ids.revision }]);

  expectOnlyAdminMutations(fixture.mutations);
  expect(fixture.mutations.every(({ path, csrf: token }) => path === "/admin/v1/auth/login" || token === csrf)).toBe(true);
});

test("owner activates a targeted configuration merge and uses focused observability context", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();

  await page.getByRole("link", { name: /^Upstreams/ }).click();
  await expect(page.getByRole("heading", { name: "Connect a provider without exposing its credential." })).toBeVisible();
  await page.getByLabel("Connection ID").fill("gateway");
  await page.getByLabel("Base URL").fill("https://gateway.example.test/v1");
  await page.getByLabel("Secret name").fill("gateway_api_key");
  await page.getByLabel("Provider credential").fill("test-only-gateway-secret");
  await page.getByLabel("Logical model ID").fill("gateway_assistant");
  await page.getByLabel("Physical provider model").fill("gateway-model-v1");
  await page.getByRole("button", { name: "Review connection change" }).click();
  await expect(page.getByRole("heading", { name: "Publish gateway to Production?" })).toBeVisible();
  await expect(page.getByLabel("Provider credential")).toHaveValue("");
  expect(fixture.secretBodies.at(-1)).toEqual({ environment_id: ids.environment, name: "gateway_api_key", value: "test-only-gateway-secret" });
  await page.getByRole("button", { name: "Publish to Production" }).click();
  await expect(page.getByRole("heading", { name: "Test the published connection" })).toBeVisible();

  const patched = fixture.configurationPatchBodies[0] as { metadata: unknown; spec: { identityProviders: unknown; models: Array<Record<string, unknown>>; upstreams: Array<Record<string, unknown>> } };
  expect(patched.spec.upstreams).toContainEqual(expect.objectContaining({ baseUrl: "https://gateway.example.test/v1", id: "gateway", type: "openai_compatible" }));
  expect(patched.spec.models).toContainEqual(expect.objectContaining({ id: "gateway_assistant", upstream: "gateway", upstreamModel: "gateway-model-v1" }));
  expect(patched.metadata).toEqual({ application: "mobile-app", environment: "production", labels: { retained: "yes" }, organization: "example" });
  expect(patched.spec.identityProviders).toEqual([{ id: "firebase", projectId: "example-mobile", type: "firebase" }]);
  expect(fixture.configurationETags).toEqual([
    { etag: '"draft-etag-1"', path: `/admin/v1/config-revisions/${ids.draftRevision}` },
    { etag: '"draft-etag-2"', path: `/admin/v1/config-revisions/${ids.draftRevision}/activate` }
  ]);

  await page.getByRole("link", { name: /^Cost/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load cost" }).click();
  await expect(page.getByRole("heading", { name: "Cost provenance" })).toBeVisible();
  await expect(page.getByText("openrouter_usage_cost")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Latency distributions" })).toHaveCount(0);

  await page.getByRole("link", { name: /^Attestation failures/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load attestation failures" }).click();
  await expect(page.getByRole("heading", { name: "Attestation rejection aggregate" })).toBeVisible();
  await expect(page.getByText(/contains no raw App Attest assertion/)).toBeVisible();

  await page.getByRole("link", { name: /^Route simulator/ }).click();
  await page.getByLabel("Environment context ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load active route context" }).click();
  await expect(page.getByText(/Selected active revision/)).toContainText("1 feature");
  await expect(page.getByLabel("Revision ID")).toHaveValue(ids.draftRevision);
  await expect(page.getByLabel("Feature")).toHaveValue("assistant");
  await page.getByRole("button", { name: "Simulate route" }).click();
  await expect(page.getByRole("heading", { name: "Allowed" })).toBeVisible();

  await page.getByRole("link", { name: /^Requests/ }).click();
  await expect(page.locator(".production-context code")).toHaveText(ids.environment);
  const filteredRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/admin/v1/requests" &&
      url.searchParams.get("status") === "succeeded" &&
      url.searchParams.get("feature") === "assistant" &&
      url.searchParams.get("platform") === "react_native_ios" &&
      url.searchParams.get("tokens_min") === "1" &&
      url.searchParams.get("sort") === "started_at_asc";
  });
  await page.getByLabel("Status").selectOption("succeeded");
  await page.getByLabel("Feature").fill("assistant");
  await page.getByLabel("Platform").selectOption("react_native_ios");
  await page.getByLabel("Token minimum").fill("1");
  await page.getByLabel("Sort").selectOption("started_at_asc");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await filteredRequest;
  await expect(page).toHaveURL(/feature=assistant/);
  await expect(page).toHaveURL(/platform=react_native_ios/);
  const restoredRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/admin/v1/requests" && url.searchParams.get("tokens_min") === "1";
  });
  await page.reload();
  await restoredRequest;
  await expect(page.getByLabel("Status")).toHaveValue("succeeded");
  await expect(page.getByLabel("Feature")).toHaveValue("assistant");
  await expect(page.getByLabel("Platform")).toHaveValue("react_native_ios");
  await expect(page.getByLabel("Token minimum")).toHaveValue("1");
  await expect(page.getByLabel("Sort")).toHaveValue("started_at_asc");
  await page.getByRole("button", { name: ids.request }).click();
  await expect(page.getByRole("heading", { name: "Durable execution timeline" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Aggregate usage" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Ordered upstream attempts" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "2.5 s" })).toBeVisible();
  await expect(page.getByRole("cell", { exact: true, name: "primary" })).toBeVisible();
  await expect(page.getByText("750 ms")).toBeVisible();
  await expect(page.getByText(/closed, sanitized vocabulary/)).toBeVisible();

  expectOnlyAdminMutations(fixture.mutations);
  expect(fixture.mutations.every(({ path, csrf: token }) => path === "/admin/v1/auth/login" || token === csrf)).toBe(true);
});

test("audit filters and inspected detail survive a fresh browser reload", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await page.getByRole("link", { name: /^Audit log/ }).click();

  const filteredAudit = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/admin/v1/audit-events" &&
      url.searchParams.get("action") === "admin.user_block" &&
      url.searchParams.get("source") === "console" &&
      url.searchParams.get("reason") === "security_response" &&
      url.searchParams.get("result") === "succeeded";
  });
  await page.getByLabel("Action").fill("admin.user_block");
  await page.getByLabel("Descriptive source").selectOption("console");
  await page.getByLabel("Reason code").fill("security_response");
  await page.getByLabel("Result").selectOption("succeeded");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await filteredAudit;
  await expect(page).toHaveURL(/reason=security_response/);
  await expect(page).toHaveURL(/source=console/);
  const restoredAudit = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/admin/v1/audit-events" && url.searchParams.get("reason") === "security_response";
  });
  await page.reload();
  await restoredAudit;
  await expect(page.getByLabel("Action")).toHaveValue("admin.user_block");
  await expect(page.getByLabel("Descriptive source")).toHaveValue("console");
  await expect(page.getByLabel("Reason code")).toHaveValue("security_response");
  await expect(page.getByLabel("Result")).toHaveValue("succeeded");
  await page.getByRole("button", { name: `application_user:${ids.auditUser}` }).click();
  await expect(page.getByRole("heading", { name: "Field-level diff" })).toBeVisible();

  expectOnlyAdminMutations(fixture.mutations);
  expect(fixture.mutations.every(({ path, csrf: token }) => path === "/admin/v1/auth/login" || token === csrf)).toBe(true);
});

test("credential-aware self-test sends configured identifiers and a numeric cost ceiling", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await page.getByRole("link", { name: /^Self-tests/ }).click();
  const immediateSelfTest = page.locator("form.control-form").filter({
    has: page.getByRole("button", { name: "Run self-test" }),
  });
  await immediateSelfTest.locator('input[name="environment"]').fill(ids.environment);
  await immediateSelfTest.locator('select[name="kind"]').selectOption("openrouter");
  await immediateSelfTest.locator('input[name="upstream"]').fill("openrouter");
  await immediateSelfTest.locator('input[name="model"]').fill("canary");
  await expect(immediateSelfTest.locator('input[name="max_cost_nano_usd"]')).toHaveValue("10000000");
  await page.getByRole("button", { name: "Run self-test" }).click();
  await expect(page.getByRole("heading", { name: "openrouter self-test" })).toBeVisible();
  await expect(page.getByText("Bounded provider usage passed.")).toBeVisible();
  expect(fixture.selfTestBodies).toEqual([{
    environment_id: ids.environment,
    kind: "openrouter",
    max_cost_nano_usd: 10_000_000,
    model: "canary",
    upstream: "openrouter"
  }]);
  expect(JSON.stringify(fixture.selfTestBodies)).not.toContain("api_key");
  expectOnlyAdminMutations(fixture.mutations);
});

test("self-test schedules bind durable token metadata and support list, detail, and disable", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await page.getByRole("link", { name: /^API tokens/ }).click();
  await page.getByLabel("Token name").fill("self-test-scheduler");
  await page.getByLabel("Run self-tests").check();
  await page.getByRole("button", { name: "Create API token" }).click();
  await page.getByRole("button", { name: "Dismiss token" }).click();

  await page.getByRole("link", { name: /^Self-tests/ }).click();
  await page.getByLabel("Scheduled environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load schedules" }).click();
  await page.getByLabel("Durable Admin API token").fill(oneTimeAPIToken);
  await page.getByLabel("Scheduled upstream ID").fill("primary");
  await page.getByLabel("Scheduled model ID").fill("canary");
  await page.getByRole("button", { name: "Create schedule" }).click();
  await expect(page.getByLabel("Durable Admin API token")).toHaveValue("");
  await expect(page.getByText(ids.activeRevision)).toBeVisible();
  await expect(page.getByText(ids.apiToken, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: ids.selfTestSchedule }).click();
  await page.getByRole("button", { name: "Disable schedule" }).click();
  await expect(page.getByText(`${ids.selfTestSchedule} · disabled`)).toBeVisible();

  expect(fixture.selfTestScheduleBodies).toEqual([{
    daily_cost_limit_nano_usd: 240_000_000, environment_id: ids.environment,
    interval_seconds: 3600, kind: "upstream",
    max_cost_nano_usd: 10_000_000, model: "canary", upstream: "primary"
  }]);
  expect(fixture.selfTestScheduleAuthorizations).toEqual([{ authorization: `Bearer ${oneTimeAPIToken}`, cookie: undefined, csrf: undefined }]);
  expect(JSON.stringify(fixture.selfTestScheduleBodies)).not.toContain(oneTimeAPIToken);
  expectOnlyAdminMutations(fixture.mutations);
});

test("owner manages administrators without persisting password material", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await page.getByRole("link", { name: /^Administrators/ }).click();
  await page.getByLabel("Email", { exact: true }).fill("second-owner@example.test");
  await page.getByLabel("Display name").fill("Second Owner");
  await page.locator('select[name="role"]').selectOption("viewer");
  await page.getByLabel("Initial password").fill("temporary administrator password");
  await page.getByRole("button", { name: "Create administrator" }).click();
  await expect(page.getByText("second-owner@example.test")).toBeVisible();
  await page.getByLabel("Role for second-owner@example.test").selectOption("operator");
  await page.getByRole("button", { name: "Reset password" }).last().click();
  await page.getByLabel("Replacement password").fill("replacement administrator password");
  await page.getByRole("button", { name: "Reset and revoke credentials" }).click();
  await page.getByRole("button", { name: "Review disable" }).last().click();
  await expect(page.getByRole("heading", { name: "Disable second-owner@example.test?" })).toBeVisible();
  await expect(page.getByText(/does not restore revoked sessions or API tokens/i)).toBeVisible();
  await page.getByLabel(/immediately removes organization access/i).check();
  await page.getByRole("button", { name: "Disable and revoke credentials" }).click();
  await expect(page.getByRole("button", { name: "Enable" })).toBeVisible();
  expect(fixture.administratorBodies).toEqual([
    { display_name: "Second Owner", email: "second-owner@example.test", password: "temporary administrator password", role: "viewer" },
    { action: "role", role: "operator" },
    { action: "reset-password", password: "replacement administrator password" },
    { action: "disable" }
  ]);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  expectOnlyAdminMutations(fixture.mutations);
});

test("owner stores a one-time API token explicitly and can revoke its metadata", async ({ browserName, page }) => {
  if (browserName === "chromium") {
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"], {
      origin: "http://127.0.0.1:4174"
    });
  }
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await page.getByRole("link", { name: /^API tokens/ }).click();
  await page.getByRole("button", { name: "Load API tokens" }).click();
  await expect(page.getByText("No scoped automation credentials have been created for this administrator.")).toBeVisible();
  await page.getByLabel("Token name").fill("mobile-ci");
  await page.getByLabel("Inspect users and usage").check();
  await page.getByLabel("Run self-tests").check();
  await page.getByRole("button", { name: "Create API token" }).click();
  await expect(page.getByText("This is the only time Latchway will show this credential.")).toBeVisible();
  await expect(page.getByLabel("One-time API token")).toHaveValue(oneTimeAPIToken);
  await page.getByRole("button", { name: "Copy token — clipboard may retain it" }).click();
  await expect(page.getByText(/Copied\. The operating system clipboard may retain this credential\.|Clipboard access was unavailable\./)).toBeVisible();
  if (browserName === "chromium") expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(oneTimeAPIToken);
  await page.getByRole("button", { name: "Dismiss token" }).click();
  await expect(page.getByLabel("One-time API token")).toHaveCount(0);
  const tokenRow = page.getByRole("row", { name: /mobile-ci/ });
  await tokenRow.getByRole("button", { name: "Review revoke" }).click();
  await expect(page.getByRole("heading", { name: "Revoke mobile-ci?" })).toBeVisible();
  await expect(page.getByText(/cannot recover or reactivate this token/i)).toBeVisible();
  await page.getByLabel(/immediately and permanently revokes this token/i).check();
  await page.getByRole("button", { name: "Revoke API token" }).click();
  await expect(tokenRow.getByText("Revoked")).toBeVisible();
  expect(fixture.apiTokenBodies).toEqual([
    { name: "mobile-ci", scopes: ["inspect_users", "run_self_tests"] },
    { action: "revoke", token_id: ids.apiToken }
  ]);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  expectOnlyAdminMutations(fixture.mutations);
});

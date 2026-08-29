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
  request: "req_0123456789abcdef",
  attempt: "atm_0123456789abcdef",
  secret: "sec_0123456789abcdef",
  rotatedSecret: "sec_1123456789abcdef",
  unusedSecret: "sec_2123456789abcdef",
  selfTest: "tst_0123456789abcdef",
  user: "usr_0123456789abcdef"
};
const csrf = "csrf_0123456789abcdefghijklmnopqrstuvwxyz";
const instant = "2026-08-29T00:00:00Z";
const oneTimeAPIToken = "one-time-browser-token-material-1234567890";

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
    title: "Request failed", type: `https://latchway.dev/problems/${code}`
  });
}

async function installAdminFixture(page: Page) {
  let authenticated = false;
  const mutations: Array<{ path: string; csrf: string | null }> = [];
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
  let apiTokens: Array<Record<string, unknown>> = [];
  let secretItems: Array<Record<string, unknown>> = [{
    algorithm: "xchacha20poly1305", created_at: instant, environment_id: ids.environment,
    id: ids.secret, master_key_id: "master-key", name: "primary_api_key", version: 1
  }];
  let userOverride: Record<string, unknown> | undefined;
  const configurationDocument = {
    apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig",
    metadata: { application: "mobile-app", environment: "production", labels: { retained: "yes" }, organization: "example" },
    spec: {
      attestationPolicies: [{ id: "native", platforms: { react_native_ios: { appAttest: { allowedBundleVersions: ["1.0.0"], allowedValidationCategories: [1], appIdPrefix: "TEAMID", bundleId: "com.example.app", environment: "production" }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" } } }],
      features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "assistant", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "assistant_default", priority: 10, when: "true" }] }],
      identityProviders: [{ id: "firebase", projectId: "example-mobile", type: "firebase" }],
      inputAccountingProfiles: [{ id: "assistant_input", maximumContextTokens: 128000, maximumFramingTokensPerMessage: 4, maximumFramingTokensPerRequest: 8, method: "utf8_byte_bpe_declared_framing_v1", physicalModel: "gpt-5-mini", protocol: "openai_responses" }],
      limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], timezone: "UTC", window: "1d" }] }],
      models: [{ capabilities: ["openai_responses"], id: "assistant_default", inputAccountingRef: "assistant_input", pricingRef: "operator_pricing", upstream: "openai", upstreamModel: "gpt-5-mini" }],
      pricingCatalogs: [{ currency: "USD", entries: [{ inputNanoUsdPerMillion: 250000, model: "assistant_default", outputNanoUsdPerMillion: 2000000, requestNanoUsd: 0 }], id: "operator_pricing" }],
      upstreams: [{ authentication: { type: "none" }, baseUrl: "https://api.openai.com/v1", id: "openai", type: "openai_compatible" }]
    }
  };
  let activeConfigurationDocument: unknown = configurationDocument;
  let activeConfigurationRevisionID = ids.activeRevision;
  let activeConfigurationVersion = 2;
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
    if (url.pathname === "/healthz") return route.fulfill({ body: "ok", status: 200 });
    if (url.pathname === "/readyz") return json(route, 200, { checks: { database: true }, status: "ready" });
    if (!url.pathname.startsWith("/admin/v1/")) return route.continue();
    if (request.method() !== "GET") mutations.push({ path: url.pathname, csrf: request.headers()["x-csrf-token"] ?? null });
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
    if (url.pathname === "/admin/v1/applications" && request.method() === "GET") return json(route, 200, { items: [{ created_at: instant, display_name: "Mobile App", id: ids.application, organization_id: ids.organization, slug: "mobile-app" }], page: { has_more: false } });
    if (url.pathname === "/admin/v1/applications" && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; applicationBodies.push(body);
      return json(route, 201, { created_at: instant, display_name: body.display_name, id: ids.application, organization_id: ids.organization, slug: body.slug });
    }
    if (url.pathname === `/admin/v1/applications/${ids.application}/environments` && request.method() === "GET") return json(route, 200, { items: [{ application_id: ids.application, created_at: instant, display_name: "Production", id: ids.environment, kind: "production", slug: "production" }] });
    if (url.pathname === `/admin/v1/applications/${ids.application}/environments` && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; environmentBodies.push(body);
      return json(route, 201, { application_id: ids.application, created_at: instant, display_name: body.display_name, id: ids.environment, kind: body.kind, slug: body.slug });
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
      revisionBodies.push(document);
      return json(route, 201, { created_at: instant, created_by: ids.admin, document, environment_id: ids.environment, id: ids.revision, state: "draft", version: 1 }, { ETag: '"revision-etag"' });
    }
    if (url.pathname === `/admin/v1/environments/${ids.environment}/config` && request.method() === "GET") return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: activeConfigurationDocument, environment_id: ids.environment, id: activeConfigurationRevisionID, state: "active", version: activeConfigurationVersion }, { ETag: '"active-revision-etag"' });
    if (url.pathname === `/admin/v1/environments/${ids.environment}/rollback` && request.method() === "POST") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; rollbackBodies.push({ etag: request.headers()["if-match"], ...body });
      return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: configurationDocument, environment_id: ids.environment, id: ids.revision, state: "active", version: 3 }, { ETag: '"restored-revision-etag"' });
    }
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/validate`) return json(route, 200, { checked_at: instant, issues: [], valid: true });
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/plan`) return problem(route, "resource_not_found", 404, "No active configuration exists.");
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/activate`) return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: {}, environment_id: ids.environment, id: ids.revision, state: "active", version: 1 });
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
      attempts: [{ completed_at: "2026-08-29T00:00:02.500Z", cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost", id: ids.attempt, model: "openai/gpt", started_at: instant, status: "succeeded", upstream: "openrouter", usage: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 0, output_tokens: 20, total_tokens: 30 }, usage_provenance: "upstream_reported" }],
      completed_at: "2026-08-29T00:00:03Z", environment_id: ids.environment, feature: "assistant", id: ids.request, installation_id: "ins_0123456789abcdef", protocol: "openai_chat", started_at: instant, status: "succeeded", usage: { cost_nano_usd: 900, input_tokens: 10, logical_requests: 1, output_tokens: 20, total_tokens: 30 }, user_id: ids.user
    };
    if (url.pathname === "/admin/v1/requests") return json(route, 200, { items: [requestDetail], page: { has_more: false } });
    if (url.pathname === `/admin/v1/requests/${ids.request}`) return json(route, 200, requestDetail);
    if (url.pathname === `/admin/v1/config-revisions/${activeConfigurationRevisionID}/simulate`) return json(route, 200, {
      allowed: true, application_id: ids.application, environment_id: ids.environment, environment_kind: "production", explanation: ["production policy allowed"],
      facts: { application_id: ids.application, authenticated: true, environment_id: ids.environment, environment_kind: "production", feature: "assistant", framing_unit_count: 1, normalized_claims: {}, platform: "react_native_ios", requested_input_tokens: 0, requested_output_max: 0, revision_id: activeConfigurationRevisionID, rewritten_request_bytes: 1024, streaming: false, trust_level: "app_verified" },
      fact_usage: [], feature: "assistant", limit_plan: "free", limits: [], model: "assistant_default", physical_model: "gpt-5-mini", pricing_confidence: "configured", protocol: "openai_responses", revision_id: activeConfigurationRevisionID, route: "primary", upstream: "openai", warnings: []
    });
    if (url.pathname === "/admin/v1/self-tests") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
      selfTestBodies.push(body);
      const kind = typeof body.kind === "string" ? body.kind : "local";
      return json(route, 202, { checks: [{ name: kind === "local" ? "database" : "usage", safe_detail: kind === "local" ? "PostgreSQL transaction completed." : "Bounded provider usage passed.", state: "passed" }], completed_at: instant, created_at: instant, id: ids.selfTest, kind, state: "passed" });
    }
    if (url.pathname === `/admin/v1/users/${ids.user}` && request.method() === "GET") return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: "active", ...(userOverride ? { limit_plan_override: userOverride } : {}) });
    if (url.pathname === `/admin/v1/users/${ids.user}/limit-override` && request.method() === "PUT") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>; overrideBodies.push(body);
      userOverride = { created_at: instant, id: ids.override, limit_plan: body.limit_plan, reason: body.reason, ...(body.expires_at ? { expires_at: body.expires_at } : {}) };
      return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], limit_plan_override: userOverride, normalized_claims: { plan: "standard" }, status: "active" });
    }
    if (url.pathname === `/admin/v1/users/${ids.user}/limit-override` && request.method() === "DELETE") { overrideBodies.push({ action: "clear", user_id: ids.user }); userOverride = undefined; return route.fulfill({ status: 204 }); }
    if (url.pathname === "/admin/v1/users" && request.method() === "GET") return json(route, 200, { items: [{ created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: "active" }], page: { has_more: false } });
    if (url.pathname === `/admin/v1/users/${ids.user}/block`) return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: "blocked" });
    return problem(route, "resource_not_found", 404, "Fixture endpoint not found.");
  });
  return { administratorBodies, apiTokenBodies, applicationBodies, configurationETags, configurationPatchBodies, environmentBodies, mutations, overrideBodies, revisionBodies, rollbackBodies, secretBodies, selfTestBodies };
}

test("first run, Admin-only mutation path, user block, and logout", async ({ page }) => {
  const fixture = await installAdminFixture(page);
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
  await page.getByLabel("App ID prefix").fill("TEAM1234");
  await page.getByLabel("Bundle ID").fill("com.example.mobile");
  await page.getByLabel("Allowed bundle version").fill("2.3.4");
  await page.getByLabel("Package name").fill("com.example.mobile");
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
    "android", "ios", "react_native_android", "react_native_ios"
  ]);
  expect(generated.spec.attestationPolicies[0]?.platforms).toMatchObject({
    ios: { minimumTrustLevel: "app_verified", appAttest: { allowedBundleVersions: ["2.3.4"] } },
    android: { minimumTrustLevel: "device_verified" },
    react_native_ios: { minimumTrustLevel: "app_verified", appAttest: { allowedBundleVersions: ["2.3.4"] } },
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
  expect(snippets).toHaveLength(3);
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
  await page.getByRole("button", { name: "Block" }).click();
  await expect(page.getByRole("button", { name: "Unblock" })).toBeVisible();

  expect(fixture.mutations.length).toBeGreaterThanOrEqual(9);
  expect(fixture.mutations.every(({ path, csrf: token }) => path.startsWith("/admin/v1/") && (path === "/admin/v1/auth/login" || token === csrf))).toBe(true);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in before opening this control-plane view." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toHaveCount(0);
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
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load newest revision" }).click();
  await expect(page.locator(".resource-result")).toContainText(`Active revision: ${ids.activeRevision}`);
  await page.getByRole("button", { name: "Rollback to this revision" }).click();
  await expect(page.locator(".resource-result")).toContainText(`Active revision: ${ids.revision}`);
  expect(fixture.rollbackBodies).toEqual([{ etag: '"active-revision-etag"', revision_id: ids.revision }]);

  expect(fixture.mutations.every(({ path, csrf: token }) => path === "/admin/v1/auth/login" || token === csrf)).toBe(true);
});

test("owner activates a targeted configuration merge and uses focused observability context", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();

  await page.getByRole("link", { name: /^Upstreams/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load active configuration" }).click();
  await page.getByRole("button", { name: "Delete openai" }).click();
  await expect(page.getByRole("heading", { name: "Stage deletion of openai" })).toBeVisible();
  await page.getByRole("button", { name: "Cancel deletion" }).click();
  expect(fixture.configurationPatchBodies).toHaveLength(0);

  await page.getByRole("button", { name: "Edit openai" }).click();
  const upstream = JSON.parse(await page.getByLabel("Resource JSON").inputValue()) as Record<string, unknown>;
  upstream.baseUrl = "https://gateway.example.test/v1";
  await page.getByLabel("Resource JSON").fill(JSON.stringify(upstream, null, 2));
  await page.getByRole("button", { name: "Stage resource" }).click();
  await expect(page.getByText("Staged changes", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Validate and activate" }).click();
  await expect(page.locator(".resource-result")).toContainText(`Revision ${ids.draftRevision} is active`);

  const patched = fixture.configurationPatchBodies[0] as { metadata: unknown; spec: { identityProviders: unknown; upstreams: Array<Record<string, unknown>> } };
  expect(patched.spec.upstreams[0]).toEqual(expect.objectContaining({ baseUrl: "https://gateway.example.test/v1", id: "openai", type: "openai_compatible" }));
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

  await page.getByRole("link", { name: /^Requests/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByRole("button", { name: "List requests" }).click();
  await page.getByRole("button", { name: ids.request }).click();
  await expect(page.getByRole("heading", { name: "Aggregate usage" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Ordered upstream attempts" })).toBeVisible();
  await expect(page.getByText("2.5 s")).toBeVisible();
  await expect(page.getByText(/does not expose route IDs, upstream HTTP status/)).toBeVisible();

  await page.getByRole("link", { name: /^Route simulator/ }).click();
  await page.getByLabel("Environment context ID").fill(ids.environment);
  await page.getByRole("button", { name: "Load active route context" }).click();
  await expect(page.getByText(/Selected active revision/)).toContainText("1 feature");
  await expect(page.getByLabel("Revision ID")).toHaveValue(ids.draftRevision);
  await expect(page.getByLabel("Feature")).toHaveValue("assistant");
  await page.getByRole("button", { name: "Simulate route" }).click();
  await expect(page.getByRole("heading", { name: "Allowed" })).toBeVisible();

  expect(fixture.mutations.every(({ path, csrf: token }) => path === "/admin/v1/auth/login" || token === csrf)).toBe(true);
});

test("credential-aware self-test sends configured identifiers and a numeric cost ceiling", async ({ page }) => {
  const fixture = await installAdminFixture(page);
  await page.goto("/");
  await page.getByLabel("Email address").fill("owner@example.test");
  await page.getByLabel("Password").fill("test-only-owner-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await page.getByRole("link", { name: /^Self-tests/ }).click();
  await page.getByLabel("Environment ID").fill(ids.environment);
  await page.getByLabel("Test kind").selectOption("openrouter");
  await page.getByLabel("Upstream ID").fill("openrouter");
  await page.getByLabel("Model ID").fill("canary");
  await expect(page.getByLabel("Maximum total cost (nano-USD)")).toHaveValue("10000000");
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
  await page.getByRole("button", { name: "Disable" }).last().click();
  await expect(page.getByRole("button", { name: "Enable" })).toBeVisible();
  expect(fixture.administratorBodies).toEqual([
    { display_name: "Second Owner", email: "second-owner@example.test", password: "temporary administrator password", role: "viewer" },
    { action: "role", role: "operator" },
    { action: "reset-password", password: "replacement administrator password" },
    { action: "disable" }
  ]);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test("owner stores a one-time API token explicitly and can revoke its metadata", async ({ page }) => {
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: "http://127.0.0.1:4174"
  });
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
  await expect(page.getByText("Copied. The operating system clipboard may retain this credential.")).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(oneTimeAPIToken);
  await page.getByRole("button", { name: "Dismiss token" }).click();
  await expect(page.getByLabel("One-time API token")).toHaveCount(0);
  const tokenRow = page.getByRole("row", { name: /mobile-ci/ });
  await tokenRow.getByRole("button", { name: "Revoke" }).click();
  await expect(tokenRow.getByText("Revoked")).toBeVisible();
  expect(fixture.apiTokenBodies).toEqual([
    { name: "mobile-ci", scopes: ["inspect_users", "run_self_tests"] },
    { action: "revoke", token_id: ids.apiToken }
  ]);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

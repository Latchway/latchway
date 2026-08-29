import { expect, test, type Page, type Route } from "@playwright/test";

const ids = {
  admin: "adm_0123456789abcdef",
  application: "app_01J00000000000000000000000",
  environment: "env_0123456789abcdef",
  organization: "org_0123456789abcdef",
  revision: "rev_0123456789abcdef",
  secret: "sec_0123456789abcdef",
  selfTest: "tst_0123456789abcdef",
  user: "usr_0123456789abcdef"
};
const csrf = "csrf_0123456789abcdefghijklmnopqrstuvwxyz";
const instant = "2026-08-29T00:00:00Z";

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
  const revisionBodies: unknown[] = [];
  const selfTestBodies: Array<Record<string, unknown>> = [];
  const session = {
    administrator: { email: "owner@example.test", enabled: true, id: ids.admin },
    capabilities: ["activate_configuration", "inspect_users", "manage_secrets", "revoke_installations", "run_self_tests"],
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
    if (url.pathname === "/admin/v1/applications") return json(route, 201, { created_at: instant, display_name: "Mobile App", id: ids.application, organization_id: ids.organization, slug: "mobile-app" });
    if (url.pathname === `/admin/v1/applications/${ids.application}/environments`) return json(route, 201, { application_id: ids.application, created_at: instant, display_name: "Production", id: ids.environment, kind: "production", slug: "production" });
    if (url.pathname === "/admin/v1/secrets") return json(route, 201, { algorithm: "xchacha20poly1305", created_at: instant, environment_id: ids.environment, id: ids.secret, master_key_id: "master-key", name: "primary_api_key", version: 1 });
    if (url.pathname === `/admin/v1/environments/${ids.environment}/config-revisions`) {
      const document = JSON.parse(request.postData() ?? "{}").document as unknown;
      revisionBodies.push(document);
      return json(route, 201, { created_at: instant, created_by: ids.admin, document, environment_id: ids.environment, id: ids.revision, state: "draft", version: 1 }, { ETag: '"revision-etag"' });
    }
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/validate`) return json(route, 200, { checked_at: instant, issues: [], valid: true });
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/plan`) return problem(route, "resource_not_found", 404, "No active configuration exists.");
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/activate`) return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: {}, environment_id: ids.environment, id: ids.revision, state: "active", version: 1 });
    if (url.pathname === "/admin/v1/self-tests") {
      const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
      selfTestBodies.push(body);
      const kind = typeof body.kind === "string" ? body.kind : "local";
      return json(route, 202, { checks: [{ name: kind === "local" ? "database" : "usage", safe_detail: kind === "local" ? "PostgreSQL transaction completed." : "Bounded provider usage passed.", state: "passed" }], completed_at: instant, created_at: instant, id: ids.selfTest, kind, state: "passed" });
    }
    if (url.pathname === "/admin/v1/users" && request.method() === "GET") return json(route, 200, { items: [{ created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: "active" }], page: { has_more: false } });
    if (url.pathname === `/admin/v1/users/${ids.user}/block`) return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: "blocked" });
    return problem(route, "resource_not_found", 404, "Fixture endpoint not found.");
  });
  return { mutations, revisionBodies, selfTestBodies };
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
  await page.getByRole("button", { name: "Create application and environment" }).click();
  await expect(page.getByRole("heading", { name: "Write-only upstream credential" })).toBeVisible();
  const generated = JSON.parse(await page.getByLabel("Full configuration JSON").inputValue()) as {
    spec: {
      attestationPolicies: Array<{ platforms: Record<string, unknown> }>;
      inputAccountingProfiles: Array<Record<string, unknown>>;
      models: Array<Record<string, unknown>>;
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
    inputAccountingRef: "assistant_default_responses_accounting"
  });
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
  await page.getByRole("button", { name: "Run local self-test" }).click();
  await expect(page.getByText(/Self-test .*passed/)).toBeVisible();
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

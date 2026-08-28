import { expect, test, type Page, type Route } from "@playwright/test";

const ids = {
  admin: "adm_0123456789abcdef",
  application: "app_0123456789abcdef",
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
    if (url.pathname === `/admin/v1/environments/${ids.environment}/config-revisions`) return json(route, 201, { created_at: instant, created_by: ids.admin, document: JSON.parse(request.postData() ?? "{}").document, environment_id: ids.environment, id: ids.revision, state: "draft", version: 1 }, { ETag: '"revision-etag"' });
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/validate`) return json(route, 200, { checked_at: instant, issues: [], valid: true });
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/plan`) return problem(route, "resource_not_found", 404, "No active configuration exists.");
    if (url.pathname === `/admin/v1/config-revisions/${ids.revision}/activate`) return json(route, 200, { activated_at: instant, created_at: instant, created_by: ids.admin, document: {}, environment_id: ids.environment, id: ids.revision, state: "active", version: 1 });
    if (url.pathname === "/admin/v1/self-tests") return json(route, 202, { checks: [{ name: "database", safe_detail: "PostgreSQL transaction completed.", state: "passed" }], completed_at: instant, created_at: instant, id: ids.selfTest, kind: "local", state: "passed" });
    if (url.pathname === "/admin/v1/users" && request.method() === "GET") return json(route, 200, { items: [{ created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: "active" }], page: { has_more: false } });
    if (url.pathname === `/admin/v1/users/${ids.user}/block`) return json(route, 200, { created_at: instant, environment_id: ids.environment, id: ids.user, identity_providers: ["firebase"], normalized_claims: { plan: "standard" }, status: "blocked" });
    return problem(route, "resource_not_found", 404, "Fixture endpoint not found.");
  });
  return { mutations };
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
  await page.getByLabel("Package name").fill("com.example.mobile");
  await page.getByLabel("Cloud project number").fill("123456789");
  await page.getByLabel("Certificate SHA-256 digest (base64url)").fill("A".repeat(43));
  await page.getByRole("button", { name: "Create application and environment" }).click();
  await expect(page.getByRole("heading", { name: "Write-only upstream credential" })).toBeVisible();
  await page.getByLabel("Secret value").fill("test-only-upstream-key");
  await page.getByRole("button", { name: "Add credential" }).click();
  await expect(page.getByRole("button", { name: "Credential added" })).toBeVisible();
  await expect(page.getByLabel("Secret value")).toHaveValue("");
  await page.getByRole("button", { name: "Validate and activate with ETag" }).click();
  await expect(page.getByText(/is active/)).toBeVisible();
  await page.getByRole("button", { name: "Run local self-test" }).click();
  await expect(page.getByText(/Self-test .*passed/)).toBeVisible();

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

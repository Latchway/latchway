import { expect, test } from "@playwright/test";

const liveStackBaseURL = process.env.LATCHWAY_CONSOLE_LIVE_E2E_BASE_URL;
const bootstrapToken = process.env.LATCHWAY_CONSOLE_LIVE_E2E_BOOTSTRAP_TOKEN;
const ownerPassword = process.env.LATCHWAY_CONSOLE_LIVE_E2E_OWNER_PASSWORD;
const providerCredential = process.env.LATCHWAY_CONSOLE_LIVE_E2E_PROVIDER_CREDENTIAL;

// Failed-test artifacts must not capture even the short-lived bootstrap,
// owner, or provider credentials entered by this proof.
test.use({ screenshot: "off", trace: "off", video: "off" });

test.describe("real first-run control plane", () => {
  // This proof mutates an isolated gateway through the one-time owner bootstrap.
  // A retry would reuse that already-configured gateway and hide the original failure.
  test.describe.configure({ retries: 0 });

  test.skip(
    !liveStackBaseURL || !bootstrapToken || !ownerPassword || !providerCredential,
    "The live-stack harness supplies an isolated PostgreSQL gateway and ephemeral credentials."
  );

  test("bootstraps, activates a native-mobile configuration, and signs back in", async ({ page }) => {
    await page.goto("/");
    // A fresh server with an unused bootstrap token opens on setup.
    await expect(page.getByRole("heading", { level: 1, name: "Set up Latchway" })).toBeVisible();
    await page.getByLabel("One-time bootstrap token").fill(bootstrapToken ?? "");
    await page.getByLabel("Organization name").fill("Latchway Live E2E");
    await page.getByLabel("Organization slug").fill("latchway-live");
    await page.getByLabel("Owner display name").fill("Live E2E Owner");
    await page.getByLabel("Owner email address").fill("owner@live-e2e.invalid");
    await page.getByLabel("Owner password").fill(ownerPassword ?? "");
    await page.getByRole("button", { name: "Create First Owner" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Latchway Live E2E is ready" })).toBeVisible();
    await page.getByRole("checkbox", { name: /I've removed LATCHWAY_ADMIN_BOOTSTRAP_TOKEN/ }).check();
    await page.getByRole("button", { name: "Go to the Console" }).click();

    await expect(
      page.getByRole("heading", { level: 1, name: "Overview" })
    ).toBeVisible();
    await page.getByRole("navigation", { name: "Primary navigation" }).getByRole("link", { name: "Setup wizard" }).click();
    await expect(
      page.getByRole("heading", { level: 1, name: "Set up an application" })
    ).toBeVisible();

    await page.getByLabel("Organization slug").fill("latchway-live");
    await page.getByLabel("Application name").fill("Native Mobile");
    await page.getByLabel("Application slug").fill("native-mobile");
    await page.getByLabel("Environment kind").selectOption("production");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Firebase project ID").fill("latchway-live-e2e");
    await page.getByLabel("App ID prefix").fill("TEAM1234");
    await page.getByLabel("Bundle ID", { exact: true }).fill("dev.latchway.livee2e");
    await page.getByLabel("Allowed CFBundleVersion (build number)").fill("1");
    await page.getByLabel("Package name").fill("dev.latchway.livee2e.android");
    await page.getByLabel("Cloud project number").fill("123456789");
    await page.getByLabel("Certificate SHA-256 digest (base64url)").fill(
      "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
    );
    await page.getByLabel("Exact version code").fill("1");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Input price (nano-USD per million tokens)").fill("250000");
    await page.getByLabel("Output price (nano-USD per million tokens)").fill("2000000");
    await page.getByRole("button", { name: "Continue" }).click();
    const createWorkspace = page.getByRole("button", { name: "Create application and environment" });
    await expect(createWorkspace).toBeEnabled();
    expect(await createWorkspace.evaluate((button) => button.closest("form")?.checkValidity() ?? false)).toBe(true);
    await createWorkspace.click();

    await expect(page.getByRole("heading", { name: "Write-only upstream credential" })).toBeVisible();
    await page.getByLabel("Secret value").fill(providerCredential ?? "");
    await page.getByRole("button", { name: "Add credential" }).click();
    await expect(page.getByRole("button", { name: "Credential added" })).toBeVisible();
    await expect(page.getByLabel("Secret value")).toHaveValue("");

    await page.getByRole("button", { name: "Validate and activate with ETag" }).click();
    await expect(page.getByText(/is active/)).toBeVisible();

    await page.getByRole("button", { name: /^Your account/ }).click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "You're signed out" })).toBeVisible();

    await page.getByRole("button", { name: "Sign In Again" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Sign in to Latchway" })).toBeVisible();
    await expect(page.getByLabel("Email address")).toHaveValue("owner@live-e2e.invalid");
    await page.getByLabel("Password", { exact: true }).fill(ownerPassword ?? "");
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
    // Signing back in returns to the page that was open, with the server-owned setup resumed.
    await expect(page.getByRole("heading", { level: 1, name: "Set up an application" })).toBeVisible();
    await expect(page.getByText(/is active/)).toBeVisible();

    // An owner-set password must be replaced at first sign-in, against the real server.
    await page.getByRole("navigation", { name: "Primary navigation" }).getByRole("link", { name: "Team & Access" }).click();
    await page.getByRole("button", { name: "Add Member" }).click();
    const drawer = page.getByRole("complementary", { name: "Add member" });
    await drawer.getByLabel("Name", { exact: true }).fill("Live Operator");
    await drawer.getByLabel("Email", { exact: true }).fill("operator@live-e2e.invalid");
    await drawer.locator("label.lw-role-card").filter({ hasText: "Operator" }).click();
    await drawer.getByLabel("First password").fill("temporary-operator-passphrase");
    await drawer.getByRole("checkbox").check();
    await drawer.getByRole("button", { name: "Add Member" }).click();
    await expect(page.getByText(/Live Operator was added as Operator/)).toBeVisible();

    await page.getByRole("button", { name: /^Your account/ }).click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();
    await page.getByRole("button", { name: "Sign In Again" }).click();
    await page.getByLabel("Email address").fill("operator@live-e2e.invalid");
    await page.getByLabel("Password", { exact: true }).fill("temporary-operator-passphrase");
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Choose your password" })).toBeVisible();
    await page.getByLabel("Temporary password").fill("temporary-operator-passphrase");
    await page.getByLabel("New password").fill("operator chosen live passphrase 2026");
    await page.getByRole("button", { name: "Save Password" }).click();
    await expect(page.getByRole("button", { name: /^Your account/ })).toBeVisible();

    await page.getByRole("button", { name: /^Your account/ }).click();
    await page.getByRole("menuitem", { name: "Your Account" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Your account" })).toBeVisible();
    await expect(page.getByText("This session", { exact: true })).toBeVisible();
    await expect(page.getByText(/on (macOS|Linux|Windows)|^(Chrome|Firefox|Safari)/).first()).toBeVisible();
  });
});

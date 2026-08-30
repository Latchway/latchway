import { expect, test } from "@playwright/test";

const liveStackBaseURL = process.env.LATCHWAY_CONSOLE_LIVE_E2E_BASE_URL;
const bootstrapToken = process.env.LATCHWAY_CONSOLE_LIVE_E2E_BOOTSTRAP_TOKEN;
const ownerPassword = process.env.LATCHWAY_CONSOLE_LIVE_E2E_OWNER_PASSWORD;
const providerCredential = process.env.LATCHWAY_CONSOLE_LIVE_E2E_PROVIDER_CREDENTIAL;

// Failed-test artifacts must not capture even the short-lived bootstrap,
// owner, or provider credentials entered by this proof.
test.use({ screenshot: "off", trace: "off", video: "off" });

test.describe("real first-run control plane", () => {
  test.skip(
    !liveStackBaseURL || !bootstrapToken || !ownerPassword || !providerCredential,
    "The live-stack harness supplies an isolated PostgreSQL gateway and ephemeral credentials."
  );

  test("bootstraps, activates a native-mobile configuration, and signs back in", async ({ page }) => {
    await page.goto("/");
    await page.getByLabel("First-owner setup").check();
    await page.getByLabel("One-time bootstrap token").fill(bootstrapToken ?? "");
    await page.getByLabel("Organization name").fill("Latchway Live E2E");
    await page.getByLabel("Organization slug").fill("latchway-live");
    await page.getByLabel("Owner display name").fill("Live E2E Owner");
    await page.getByLabel("Owner email address").fill("owner@live-e2e.invalid");
    await page.getByLabel("Owner password").fill(ownerPassword ?? "");
    await page.getByRole("button", { name: "Create first owner" }).click();

    await expect(
      page.getByRole("heading", { name: "The gateway is ready for control-plane work." })
    ).toBeVisible();
    await page.getByRole("link", { name: /Setup wizard/ }).click();
    await expect(
      page.getByRole("heading", { name: "Configure React Native, iOS, and Android end to end." })
    ).toBeVisible();

    await page.getByLabel("Organization slug").fill("latchway-live");
    await page.getByLabel("Application name").fill("Native Mobile");
    await page.getByLabel("Application slug").fill("native-mobile");
    await page.getByLabel("Firebase project ID").fill("latchway-live-e2e");
    await page.getByLabel("App ID prefix").fill("TEAM1234");
    await page.getByLabel("Bundle ID", { exact: true }).fill("dev.latchway.livee2e");
    await page.getByLabel("Allowed bundle version").fill("1.0.0");
    await page.getByLabel("Package name").fill("dev.latchway.livee2e.android");
    await page.getByLabel("Cloud project number").fill("123456789");
    await page.getByLabel("Certificate SHA-256 digest (base64url)").fill(
      "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
    );
    await page.getByLabel("Input price (nano-USD per million tokens)").fill("250000");
    await page.getByLabel("Output price (nano-USD per million tokens)").fill("2000000");
    await page.getByRole("button", { name: "Create application and environment" }).click();

    await expect(page.getByRole("heading", { name: "Write-only upstream credential" })).toBeVisible();
    await page.getByLabel("Secret value").fill(providerCredential ?? "");
    await page.getByRole("button", { name: "Add credential" }).click();
    await expect(page.getByRole("button", { name: "Credential added" })).toBeVisible();
    await expect(page.getByLabel("Secret value")).toHaveValue("");

    await page.getByRole("button", { name: "Validate and activate with ETag" }).click();
    await expect(page.getByText(/is active/)).toBeVisible();

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(
      page.getByRole("heading", { name: "Sign in to continue setup." })
    ).toBeVisible();

    await page.getByRole("link", { name: /Console access/ }).click();
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await page.getByLabel("Email address").fill("owner@live-e2e.invalid");
    await page.getByLabel("Password").fill(ownerPassword ?? "");
    await page.getByRole("button", { name: "Sign in securely" }).click();
    await expect(
      page.getByRole("heading", { name: "The gateway is ready for control-plane work." })
    ).toBeVisible();
  });
});

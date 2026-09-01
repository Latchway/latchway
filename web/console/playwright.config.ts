import { defineConfig, devices } from "@playwright/test";

const liveStackBaseURL = process.env.LATCHWAY_CONSOLE_LIVE_E2E_BASE_URL;

export default defineConfig({
  expect: { timeout: 8_000 },
  forbidOnly: Boolean(process.env.CI),
  fullyParallel: false,
  reporter: process.env.CI ? "line" : "list",
  retries: process.env.CI ? 1 : 0,
  testDir: "./e2e",
  timeout: 45_000,
  use: {
    baseURL: liveStackBaseURL ?? "http://127.0.0.1:4174",
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  },
  webServer: liveStackBaseURL ? undefined : {
    command: "corepack pnpm dev --host 127.0.0.1 --port 4174",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    url: "http://127.0.0.1:4174"
  },
  projects: [
    { grepInvert: /@mobile/, name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { grepInvert: /@mobile/, name: "firefox", testIgnore: ["live-stack.spec.ts"], use: { ...devices["Desktop Firefox"] } },
    { grepInvert: /@mobile/, name: "webkit", testIgnore: ["live-stack.spec.ts"], use: { ...devices["Desktop Safari"] } },
    { grep: /@mobile/, name: "mobile-webkit", use: { ...devices["iPhone 13"] } }
  ]
});

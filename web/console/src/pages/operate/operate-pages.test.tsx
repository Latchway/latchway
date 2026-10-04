import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility, downloadMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn(), compatibility: { mutationAllowed: true }, downloadMock: vi.fn() }));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { administrator: { email: "owner@example.test", enabled: true, id: "adm_0123456789abcdef" }, capabilities: ["manage_owners", "activate_configuration", "inspect_users", "run_self_tests"], expires_at: null, memberships: [{ organization_id: "org_0123456789abcdef", role: "owner" }], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));
vi.mock("../../components/download", () => ({ downloadText: downloadMock }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: React.ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import type { WorkspaceSearch } from "../../app/workspace-context-value";
import { ids, instant, mutationsOf, renderWithWorkspace } from "../../test/workspace-harness";
import { AuditLogPage } from "../audit/audit-page";
import { SelfTestsPage } from "./self-tests-page";
import { SystemHealthPage } from "./system-health-page";

type Options = { bearerToken?: string; body?: Record<string, unknown>; method?: string } | undefined;

function doctorReport(overrides: Partial<{ checks: unknown[]; overall_state: string }> = {}) {
  const verification = { configured_selections: 1, credential_backed_selections: 1, external_network_selections: 0, registered_active_keys: 1, required_selections: 1, resolved_credential_records: 1 };
  return {
    checks: [
      { id: "database_connectivity", state: "passed", summary: "PostgreSQL is reachable." },
      { id: "external_jwks_reachability", remediation: "Verify provider DNS/TLS reachability.", state: "warning", summary: "The last-known external JWKS refresh state is stale." },
      { id: "worker_heartbeat", remediation: "Start a worker.", state: "failed", summary: "No fresh worker heartbeat." }
    ],
    database: "reachable",
    facts: {
      configuration: { active_configurations: 1, active_environments: 2, cache: { available: true, entries: 2, estimated_bytes: 100, fresh_entries: 2, maximum_entries: 10, maximum_estimated_bytes: 1000, newest_loaded_at: instant, reconciliation_interval_seconds: 30, refreshes_in_flight: 0, stale_entries: 0 }, draft_revisions: 1, highest_revision_number: 3, invalid_revisions: 0, missing_active_configuration: 1, revisions: 3 },
      database: { latency_ms: 2, pool_acquired: 9, pool_idle: 1, pool_maximum: 10, pool_total: 10, pool_utilization_ppm: 900_000, reachable: true, schema_available: 42, schema_current: 42, size_bytes: 52_428_800 },
      expired_quota_reservations: 0,
      jobs: { by_status: [{ count: 2, status: "failed" }], expired_locks: 0, failed_self_tests: 0, last_usage_rollup_at: instant, oldest_pending_at: undefined, recent_self_tests: 0, usage_settlement_backlog: 3 },
      replicas: { fresh_apis: 2, fresh_by_role: [], fresh_workers: 0, newest_heartbeat_at: instant, stale_replicas: 1 },
      retention: { admin_session_retention_hours: 168, job_history_retention_hours: 720, oldest_audit_at: instant, policy_mode: "fixed_operational_operator_tenant_data", runtime_instance_retention_hours: 24 },
      runtime: { build_date: "2026-08-01", clock_offset_ms: 1500, commit: "abcdef1234567890", compatibility_source: "embedded_self", contract_version: "1.1.0", latest_compatible_version: "1.1.6", protocol_versions: [1, 2], role: "all", server_version: "1.1.5" },
      security: { active_secret_records: 4, active_signing_keys: 1, apple_verification: verification, configured_external_jwks_providers: 1, google_verification: verification, identity_provider_errors: 0, identity_providers: 1, pending_signing_keys: 1, retiring_signing_keys: 0, signing_key_expires_at: "2026-12-01T00:00:00Z", stale_identity_provider_jwks: 1 }
    },
    generated_at: new Date().toISOString(),
    overall_state: "degraded",
    report_schema: 1,
    role: "all",
    schema_version: 42,
    status: "ok",
    ...overrides
  };
}

const auditEvent = (id: string, extra: Record<string, unknown> = {}) => ({
  action: "admin.secret_rotate", actor: "owner@example.test", actor_id: "adm_01J00000000000000000000000", actor_kind: "admin_user",
  changes: [{ classification: "sensitive", field: "value", operation: "rotate", redacted: true }], environment_id: ids.environment, id,
  request_id: "", resource_id: "sec_01J00000000000000000000000", resource_type: "secret_record", result: "succeeded", source: "console",
  summary: { changes: [{ classification: "sensitive", field: "value", operation: "rotate", redacted: true }] }, target: "provider_key", timestamp: instant, ...extra
});

beforeEach(() => {
  adminRequestMock.mockReset();
  downloadMock.mockReset();
  compatibility.mutationAllowed = true;
});

describe("System Health", () => {
  it("lists what needs attention with the server's remedy and a way to it, and describes the gateway", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      if (path === "/admin/v1/system/doctor") return Promise.resolve({ data: doctorReport() });
      if (path === "/admin/v1/system") return Promise.reject(new Error("unavailable"));
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    renderWithWorkspace(<SystemHealthPage />);
    expect(await screen.findByText("Degraded")).toBeInTheDocument();
    expect(document.querySelector(".lw-health-status")).toHaveTextContent("2 things need attention: Background workers and Sign-in provider keys.");
    const attention = screen.getByText("Needs attention").closest("section") ?? document.body;
    expect(within(attention as HTMLElement).getByText("Background workers")).toBeInTheDocument();
    expect(attention).toHaveTextContent("What to do: Start a worker.");
    expect(within(attention as HTMLElement).getByRole("link", { name: "Open User sign-in" })).toHaveAttribute("href", "/authentication-providers");
    expect(within(attention as HTMLElement).getByRole("button", { name: "See Replicas" })).toBeInTheDocument();
    expect(screen.getByText("1.1.6 available")).toBeInTheDocument();
    expect(screen.getByText("42 of 42 applied")).toBeInTheDocument();
    expect(screen.getByText(/Connections 9 of 10 in use \(90%\)/)).toBeInTheDocument();
    expect(screen.getByText("1500 ms")).toHaveClass("lw-text-warning");
  });

  it("previews the support bundle's exclusions before saving it", async () => {
    const user = userEvent.setup();
    const bundle = { bundle_schema: 1, generated_at: instant, redaction: { excluded: ["secret_values", "bearer_tokens", "dpop_proofs", "identity_subjects", "request_bodies", "response_bodies", "attestation_evidence", "cookies", "master_key", "csrf_tokens"], mode: "structural_allowlist" }, report: doctorReport(), source: "admin_api" };
    adminRequestMock.mockImplementation((path: string) => {
      if (path === "/admin/v1/system/doctor") return Promise.resolve({ data: doctorReport() });
      if (path === "/admin/v1/system/support-bundle") return Promise.resolve({ data: bundle });
      return Promise.reject(new Error("unavailable"));
    });
    renderWithWorkspace(<SystemHealthPage />);
    await user.click(await screen.findByRole("button", { name: "Support Bundle" }));
    const dialog = screen.getByRole("alertdialog", { name: "Support bundle" });
    expect(await within(dialog).findByText("secret_values")).toBeInTheDocument();
    expect(dialog).toHaveTextContent("structural allowlist");
    await user.click(within(dialog).getByRole("button", { name: "Download Bundle" }));
    expect(downloadMock).toHaveBeenCalledWith("latchway-support-bundle.json", expect.stringContaining("\"structural_allowlist\""), "application/json");
  });
});

describe("Audit Log", () => {
  it("sends the URL's filters and preset period to the API, appends pages and opens an event without its values", async () => {
    const user = userEvent.setup();
    const searchLog: WorkspaceSearch[] = [];
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/audit-events?") && !path.includes("cursor=")) return Promise.resolve({ data: { items: [auditEvent("aud_01J00000000000000000000000")], page: { has_more: true, next_cursor: "next-page" } } });
      if (path.startsWith("/admin/v1/audit-events?") && path.includes("cursor=next-page")) return Promise.resolve({ data: { items: [auditEvent("aud_01J00000000000000000000001", { action: "admin.api_token_revoke", environment_id: undefined, result: "denied" })], page: { has_more: false } } });
      if (path === "/admin/v1/audit-events/aud_01J00000000000000000000000") return Promise.resolve({ data: auditEvent("aud_01J00000000000000000000000") });
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    renderWithWorkspace(<AuditLogPage />, { initial: { action: "admin.secret_rotate", period: "7d", result: "succeeded", source: "console" }, searchLog });

    expect((await screen.findAllByText("provider_key")).length).toBe(1);
    const first = new URL(`https://x${String(adminRequestMock.mock.calls[0]?.[0])}`);
    expect(first.searchParams.get("action")).toBe("admin.secret_rotate");
    expect(first.searchParams.get("result")).toBe("succeeded");
    expect(first.searchParams.get("source")).toBe("console");
    expect(Math.round((Date.now() - Date.parse(first.searchParams.get("start") ?? "")) / 86_400_000)).toBe(7);
    expect(first.searchParams.get("end")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Load More" }));
    expect(await screen.findByText("admin.api_token_revoke")).toBeInTheDocument();
    expect(screen.getAllByText("Organization").length).toBeGreaterThan(0);

    await user.click(screen.getAllByText("provider_key")[0] as HTMLElement);
    expect(searchLog.at(-1)).toEqual({ event: "aud_01J00000000000000000000000" });
    const drawer = await screen.findByRole("complementary", { name: "aud_01J00000000000000000000000" });
    expect(await within(drawer).findByText("Sensitive, never recorded")).toBeInTheDocument();
  });

  it("refuses an event that doesn't match the one selected", async () => {
    adminRequestMock.mockImplementation((path: string) => {
      if (path.startsWith("/admin/v1/audit-events?")) return Promise.resolve({ data: { items: [], page: { has_more: false } } });
      if (path.startsWith("/admin/v1/audit-events/")) return Promise.resolve({ data: auditEvent("aud_01J00000000000000000000009") });
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    });
    renderWithWorkspace(<AuditLogPage />, { initial: { event: "aud_01J00000000000000000000000" } });
    expect(await screen.findByText("Audit event mismatch")).toBeInTheDocument();
  });
});

describe("Self-tests", () => {
  const live = { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: {}, spec: { models: [{ id: "fast", upstream: "openai" }], upstreams: [{ id: "openai" }] } };
  function selfTestServer() {
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
      const method = options?.method ?? "GET";
      if (path === `/admin/v1/environments/${ids.environment}/config`) return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: live, environment_id: ids.environment, id: ids.activeRevision, state: "active", version: 1 }, etag: '"a"' });
      if (path.startsWith(`/admin/v1/environments/${ids.environment}/config-revisions?`)) return Promise.resolve({ data: { items: [], page: { has_more: false } } });
      if (path.startsWith("/admin/v1/self-test-schedules?")) return Promise.resolve({ data: { items: [] } });
      if (path === "/admin/v1/self-tests" && method === "POST") return Promise.resolve({ data: { checks: [], config_revision_id: ids.activeRevision, created_at: instant, environment_id: ids.environment, id: "tst_0123456789abcdef", kind: "upstream", state: "queued" } });
      if (path.startsWith("/admin/v1/self-tests/tst_0123456789abcdef")) return Promise.resolve({ data: { checks: [{ name: "provider", safe_detail: "Bounded request passed.", state: "passed" }], completed_at: instant, config_revision_id: ids.activeRevision, created_at: instant, environment_id: ids.environment, id: "tst_0123456789abcdef", kind: "upstream", state: "passed" } });
      if (path === "/admin/v1/self-test-schedules" && method === "POST") return Promise.resolve({ data: { application_id: ids.application, authorization_credential_id: "tok_0123456789abcdef", config_revision_id: ids.activeRevision, created_at: instant, daily_cost_limit_nano_usd: options?.body?.daily_cost_limit_nano_usd, environment_id: ids.environment, id: "sts_0123456789abcdef", interval_seconds: options?.body?.interval_seconds, kind: "upstream", max_cost_nano_usd: options?.body?.max_cost_nano_usd, model: "fast", next_run_at: instant, status: "active", updated_at: instant, upstream: "openai" } });
      return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
    });
  }

  it("tests a connection against the live revision with an exact nano-USD ceiling and opens the run", async () => {
    const user = userEvent.setup();
    const searchLog: WorkspaceSearch[] = [];
    selfTestServer();
    renderWithWorkspace(<SelfTestsPage />, { searchLog });
    await user.click(await screen.findByRole("button", { name: "AI connection" }));
    await user.selectOptions(screen.getByLabelText("AI connection"), "openai");
    expect(screen.getByLabelText("Model")).toHaveValue("fast");
    await user.clear(screen.getByLabelText("Cost ceiling (USD)"));
    await user.type(screen.getByLabelText("Cost ceiling (USD)"), "0.05");
    await user.click(screen.getByRole("button", { name: "Run Test" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/self-tests"]));
    expect(adminRequestMock.mock.calls.find(([path]) => path === "/admin/v1/self-tests")?.[2]).toMatchObject({ body: { config_revision_id: ids.activeRevision, environment_id: ids.environment, kind: "upstream", max_cost_nano_usd: 50_000_000, model: "fast", upstream: "openai" } });
    expect(searchLog.at(-1)).toMatchObject({ environment_id: ids.environment, self_test_id: "tst_0123456789abcdef" });
    expect(await screen.findByText("Bounded request passed.")).toBeInTheDocument();
  });

  it("binds a schedule to a token sent once as a bearer credential and cleared before the response", async () => {
    const user = userEvent.setup();
    selfTestServer();
    let duringRequest: string | undefined;
    const base = adminRequestMock.getMockImplementation();
    adminRequestMock.mockImplementation((path: string, schema: unknown, options: Options) => {
      if (path === "/admin/v1/self-test-schedules" && options?.method === "POST") duringRequest = (document.getElementById("schedule-token") as HTMLInputElement).value;
      return base?.(path, schema, options);
    });
    renderWithWorkspace(<SelfTestsPage />);
    await user.click(await screen.findByRole("button", { name: "New Schedule" }));
    const drawer = screen.getByRole("complementary", { name: "New schedule" });
    await user.selectOptions(within(drawer).getByLabelText("AI connection"), "openai");
    fireEvent.change(within(drawer).getByLabelText("API token"), { target: { value: "lwt_scheduled_token_value_long_enough_1234567890" } });
    await user.click(within(drawer).getByRole("button", { name: "Create Schedule" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["POST /admin/v1/self-test-schedules"]));
    const options = adminRequestMock.mock.calls.find(([path]) => path === "/admin/v1/self-test-schedules")?.[2] as Options;
    expect(options?.bearerToken).toBe("lwt_scheduled_token_value_long_enough_1234567890");
    expect(options?.body).toEqual({ daily_cost_limit_nano_usd: 240_000_000, environment_id: ids.environment, interval_seconds: 3600, kind: "upstream", max_cost_nano_usd: 10_000_000, model: "fast", upstream: "openai" });
    expect(duringRequest).toBe("");
  });

  it("refuses a run link for another environment", async () => {
    selfTestServer();
    renderWithWorkspace(<SelfTestsPage />, { initial: { environment_id: ids.stagingEnvironment, self_test_id: "tst_0123456789abcdef" } });
    expect(await screen.findByText("Different environment")).toBeInTheDocument();
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
  });
});

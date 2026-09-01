import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SystemDoctorPanel } from "./system-doctor-panel";

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured" } })
}));

const report = {
  checks: [
    {
      id: "database_connectivity",
      state: "passed",
      summary: "PostgreSQL accepted a bounded probe."
    }
  ],
  database: "reachable",
  facts: {
    configuration: {
      active_configurations: 1,
      active_environments: 1,
      cache: {
        available: true,
        entries: 1,
        estimated_bytes: 16384,
        fresh_entries: 1,
        maximum_entries: 1024,
        maximum_estimated_bytes: 25165824,
        newest_loaded_at: "2026-08-29T00:00:00Z",
        reconciliation_interval_seconds: 30,
        refreshes_in_flight: 0,
        stale_entries: 0
      },
      draft_revisions: 0,
      highest_revision_number: 1,
      invalid_revisions: 0,
      missing_active_configuration: 0,
      revisions: 1
    },
    database: {
      latency_ms: 1,
      pool_acquired: 1,
      pool_idle: 1,
      pool_maximum: 4,
      pool_total: 2,
      pool_utilization_ppm: 250_000,
      reachable: true,
      schema_available: 27,
      schema_current: 27,
      size_bytes: 1024
    },
    expired_quota_reservations: 0,
    jobs: {
      by_status: [],
      expired_locks: 0,
      failed_self_tests: 0,
      recent_self_tests: 0,
      usage_settlement_backlog: 0
    },
    replicas: {
      fresh_by_role: [{ count: 1, role: "all" }],
      fresh_apis: 1,
      fresh_workers: 1,
      stale_replicas: 0
    },
    retention: {
      admin_session_retention_hours: 168,
      job_history_retention_hours: 720,
      policy_mode: "fixed_operational_operator_tenant_data",
      runtime_instance_retention_hours: 24
    },
    runtime: {
      build_date: "2026-08-29",
      clock_offset_ms: 0,
      commit: "abc123",
      compatibility_source: "embedded_self",
      contract_version: "1.0.0",
      latest_compatible_version: "1.0.0",
      protocol_versions: [1, 2],
      role: "all",
      server_version: "1.0.0"
    },
    security: {
      active_secret_records: 1,
      active_signing_keys: 1,
      apple_verification: {
        configured_selections: 1,
        credential_backed_selections: 0,
        external_network_selections: 0,
        registered_active_keys: 1,
        required_selections: 1,
        resolved_credential_records: 0
      },
      configured_external_jwks_providers: 1,
      google_verification: {
        configured_selections: 1,
        credential_backed_selections: 0,
        external_network_selections: 1,
        registered_active_keys: 0,
        required_selections: 1,
        resolved_credential_records: 0
      },
      identity_provider_errors: 0,
      identity_providers: 1,
      pending_signing_keys: 0,
      retiring_signing_keys: 0,
      stale_identity_provider_jwks: 0
    }
  },
  generated_at: "2026-08-29T00:00:00Z",
  overall_state: "healthy",
  report_schema: 1,
  role: "all",
  schema_version: 27,
  status: "ok"
};

const bundle = {
  bundle_schema: 1,
  generated_at: report.generated_at,
  redaction: {
    excluded: [
      "access_tokens", "admin_sessions", "api_tokens", "authorization_headers",
      "cookies", "dpop_proofs", "identity_tokens", "master_key",
      "provider_credentials", "raw_attestation_evidence", "request_content",
      "response_content", "secret_values"
    ],
    mode: "structural_allowlist"
  },
  report,
  source: "admin_api"
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("SystemDoctorPanel", () => {
  it("renders the canonical report and downloads only the validated support bundle", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      const document = path.endsWith("/support-bundle") ? bundle : report;
      return new Response(JSON.stringify(document), {
        headers: { "Content-Type": "application/json" },
        status: 200
      });
    });
    vi.stubGlobal("fetch", fetcher);
    const createObjectURL = vi.fn(() => "blob:latchway-support-bundle");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    const { container } = render(<SystemDoctorPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Run checks" }));
    expect(await screen.findByText("PostgreSQL accepted a bounded probe.")).toBeInTheDocument();
    expect(screen.getByText("Configuration")).toBeInTheDocument();
    expect(screen.getByText("Latest compatible version")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Download redacted support bundle" }));
    expect(await screen.findByText("Redacted support bundle downloaded.")).toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledWith(
      "/admin/v1/system/support-bundle",
      expect.objectContaining({ credentials: "same-origin", method: "GET" })
    );
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:latchway-support-bundle");
    expect(container.textContent).not.toContain("provider-secret-value");
  });
});

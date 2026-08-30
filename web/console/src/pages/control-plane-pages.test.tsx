import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({
    data: {
      mode: "configured",
      session: { capabilities: ["inspect_users", "run_self_tests"], organization_id: "org_0123456789abcdef" }
    }
  })
}));

import { AttestationFailuresPage, CostPage, ErrorsPage, LatencyPage, RequestsPage, RouteSimulatorPage, SelfTestsPage, UsagePage } from "./control-plane-pages";

const zeroValues = { cost_nano_usd: 0, input_tokens: 0, logical_requests: 0, output_tokens: 0, total_tokens: 0 };

function analyticsFixture() {
  return {
    analytics: {
      active_users: 2,
      attestation_failure_rate: { denominator: 4, numerator: 1, parts_per_million: 250_000 },
      by_feature: { items: [{ active_users: 2, key: "assistant", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      by_model: { items: [{ active_users: 2, key: "gpt_mobile", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      by_selected_plan: { items: [{ active_users: 2, key: "subscriber", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      cost_per_active_user_nano_usd: { denominator: 2, numerator: 900 },
      failure_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
      fallback_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
      quota_denial_rate: { denominator: 3, numerator: 0, parts_per_million: 0 },
      request_count: 3,
      request_latency: { p50_ms: 100, p95_ms: 300, p99_ms: 500, samples: 3 },
      requests_per_active_user: { denominator: 2, numerator: 3 },
      time_to_first_token: { p50_ms: 20, p95_ms: 40, p99_ms: 60, samples: 3 },
      usage_by_provenance: [
        { cost_source: "openrouter_usage_cost", provenance: "upstream_reported", values: { ...zeroValues, input_tokens: 10, output_tokens: 20, total_tokens: 30 } },
        { provenance: "calculated", values: { ...zeroValues, cost_nano_usd: 900 } },
        { provenance: "estimated", values: zeroValues },
        { provenance: "unknown", values: zeroValues }
      ]
    },
    end: "2026-08-29T01:00:00Z", provenance: ["calculated", "upstream_reported"],
    start: "2026-08-29T00:00:00Z", values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 }
  };
}

function routeSimulationFixture() {
  return {
    allowed: true, application_id: "app_0123456789abcdef", environment_id: "env_0123456789abcdef",
    environment_kind: "production", explanation: ["production policy allowed"],
    facts: { application_id: "app_0123456789abcdef", authenticated: true, environment_id: "env_0123456789abcdef", environment_kind: "production", feature: "assistant", framing_unit_count: 1, normalized_claims: {}, platform: "react_native_ios", requested_input_tokens: 99, requested_output_max: 100, revision_id: "rev_0123456789abcdef", rewritten_request_bytes: 1024, streaming: false, trust_level: "app_verified" },
    fact_usage: [{ affects_cel: false, explanation: "Untrusted estimate only.", fact: "requested_input_tokens", role: "explanatory" }],
    feature: "assistant", limit_plan: "subscriber",
    limits: [{ algorithm: "calendar", hard: true, maximum: 1000, metric: "total_tokens", scope: ["user", "feature"], timezone: "UTC", window: "1d" }],
    model: "gpt_mobile", physical_model: "gpt-5-mini", pricing_confidence: "configured", protocol: "openai_responses",
    reservation: { allocations: [{ algorithm: "calendar", applicable: true, durable: true, metric: "total_tokens", units: 1132 }], applied_output_maximum: 100, cost_bound_known: true, cost_nano_usd_bound: 50, input_accounting: { framing_unit_count: 1, input_token_bound: 1032, maximum_context_tokens: 128000, maximum_framing_tokens_per_request: 4, maximum_framing_tokens_per_unit: 4, method: "utf8_byte_bpe_declared_framing_v1", profile_id: "gpt_mobile_input", required: true, rewritten_request_bytes: 1024 }, pricing_catalog: "mobile_price", total_token_bound: 1132 },
    revision_id: "rev_0123456789abcdef", route: "primary", upstream: "openai", warnings: []
  };
}

afterEach(cleanup);

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("rich usage and route-simulator views", () => {
  it("renders bounded per-user, latency, rate, dimension, and provenance analytics", async () => {
    adminRequestMock.mockImplementation(async (path: string) => path.includes("/summary") ? { data: {
      analytics: {
        active_users: 2,
        attestation_failure_rate: { denominator: 4, numerator: 1, parts_per_million: 250_000 },
        by_feature: { items: [{ active_users: 2, key: "assistant", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
        by_model: { items: [{ active_users: 2, key: "gpt_mobile", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
        by_selected_plan: { items: [{ active_users: 2, key: "subscriber", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
        cost_per_active_user_nano_usd: { denominator: 2, numerator: 900 },
        failure_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
        fallback_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
        quota_denial_rate: { denominator: 3, numerator: 0, parts_per_million: 0 },
        request_count: 3,
        request_latency: { p50_ms: 100, p95_ms: 300, p99_ms: 500, samples: 3 },
        requests_per_active_user: { denominator: 2, numerator: 3 },
        time_to_first_token: { p50_ms: 20, p95_ms: 40, p99_ms: 60, samples: 3 },
        usage_by_provenance: [
          { cost_source: "openrouter_usage_cost", provenance: "upstream_reported", values: { ...zeroValues, input_tokens: 10, output_tokens: 20, total_tokens: 30 } },
          { provenance: "calculated", values: { ...zeroValues, cost_nano_usd: 900 } },
          { provenance: "estimated", values: zeroValues },
          { provenance: "unknown", values: zeroValues }
        ]
      },
      end: "2026-08-29T01:00:00Z", provenance: ["calculated", "upstream_reported"],
      start: "2026-08-29T00:00:00Z", values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 }
    } } : { data: { interval: "hour", points: [] } });
    const user = userEvent.setup();
    render(<UsagePage />);
    await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
    await user.click(screen.getByRole("button", { name: "Load usage" }));

    expect(await screen.findByText("Requests / active user")).toBeInTheDocument();
    expect(screen.getByText("1.5")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Feature usage" })).toBeInTheDocument();
    expect(screen.getByText("gpt_mobile")).toBeInTheDocument();
    expect(screen.getByText("subscriber")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Usage provenance" })).toBeInTheDocument();
    expect(screen.getByText("upstream_reported")).toBeInTheDocument();
    expect(screen.queryByText("openrouter_usage_cost")).not.toBeInTheDocument();
  });

  it("renders token and cost provenance independently for each attempt", async () => {
	const request = { attempts: [{
	  attempt_number: 1, completed_at: "2026-08-29T00:00:00.400Z", cost_provenance: "unknown",
	  failure_code: "timeout", http_status: 504, id: "atm_0123456789abcdef", model: "openai/gpt",
	  route: "primary", started_at: "2026-08-29T00:00:00Z", status: "failed",
	  upstream: "openrouter", usage_provenance: "unknown"
	}, {
	  attempt_number: 2, completed_at: "2026-08-29T00:00:02.500Z", cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost",
	  first_byte_at: "2026-08-29T00:00:01Z", http_status: 200, id: "atm_0123456789abcdeg", model: "openai/gpt",
	  route: "fallback", started_at: "2026-08-29T00:00:00.500Z", status: "succeeded", upstream: "openrouter",
	  usage: { cost_nano_usd: 321, input_tokens: 10, logical_requests: 0, output_tokens: 20, total_tokens: 30 }, usage_provenance: "unknown"
	}], completed_at: "2026-08-29T00:00:03Z", environment_id: "env_0123456789abcdef", feature: "assistant",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  usage: { cost_nano_usd: 321, input_tokens: 10, logical_requests: 1, output_tokens: 20, total_tokens: 30 },
	  user_id: "usr_0123456789abcdef" };
	adminRequestMock.mockImplementation(async (path: string) => path.endsWith(request.id) ? { data: request } : { data: { items: [request], page: { has_more: false } } });
	const user = userEvent.setup();
	render(<RequestsPage />);
	await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
	await user.click(screen.getByRole("button", { name: "List requests" }));
	await user.click(await screen.findByRole("button", { name: "req_0123456789abcdef" }));
	expect(await screen.findByRole("heading", { name: "Request detail" })).toBeInTheDocument();
	expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/requests/req_0123456789abcdef", expect.anything());
	expect(screen.getByRole("heading", { name: "Aggregate usage" })).toBeInTheDocument();
	expect(screen.getByRole("heading", { name: "Ordered upstream attempts" })).toBeInTheDocument();
	expect(screen.getByText("500 ms")).toBeInTheDocument();
	expect(screen.getAllByText("321")).toHaveLength(2);
	expect(screen.getByText("fallback")).toBeInTheDocument();
	expect(screen.getByText("504")).toBeInTheDocument();
	expect(screen.getByText("timeout")).toBeInTheDocument();
	expect(screen.getByText("upstream_reported")).toBeInTheDocument();
	expect(screen.getByText("openrouter_usage_cost")).toBeInTheDocument();
	expect(screen.getByText(/closed, sanitized vocabulary/)).toBeInTheDocument();
	expect(screen.queryByText("upstream_timeout")).not.toBeInTheDocument();
  });

  it("rejects request detail that does not match the selected environment", async () => {
    const listed = { attempts: [], completed_at: "2026-08-29T00:00:01Z", environment_id: "env_0123456789abcdef", feature: "assistant", id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef", protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z", status: "succeeded", user_id: "usr_0123456789abcdef" };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(listed.id) ? { data: { ...listed, environment_id: "env_ffffffffffffffff" } } : { data: { items: [listed], page: { has_more: false } } });
    const user = userEvent.setup();
    render(<RequestsPage />);
    await user.type(screen.getByLabelText("Environment ID"), listed.environment_id);
    await user.click(screen.getByRole("button", { name: "List requests" }));
    await user.click(await screen.findByRole("button", { name: listed.id }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Request detail mismatch");
    expect(screen.queryByRole("heading", { name: "Request detail" })).not.toBeInTheDocument();
  });

  it.each([
    ["Cost", CostPage, "Load cost", "Cost provenance", "Latency distributions"],
    ["Latency", LatencyPage, "Load latency", "Latency distributions", "Cost provenance"],
    ["Errors", ErrorsPage, "Load errors", "Error and recovery rates", "Cost provenance"],
    ["Attestation failures", AttestationFailuresPage, "Load attestation failures", "Attestation rejection aggregate", "Cost provenance"]
  ] as const)("renders %s as a focused analytics page", async (title, Page, loadLabel, expectedHeading, excludedHeading) => {
    adminRequestMock.mockImplementation(async (path: string) => path.includes("/summary") ? { data: analyticsFixture() } : { data: { interval: "hour", points: [] } });
    const user = userEvent.setup();
    render(<Page />);
    await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
    await user.click(screen.getByRole("button", { name: loadLabel }));

    expect(await screen.findByRole("heading", { name: expectedHeading })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: title })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: excludedHeading })).not.toBeInTheDocument();
  });

  it("renders authoritative scope, exact reservation, applicable limits, and fact roles", async () => {
    adminRequestMock.mockResolvedValue({ data: routeSimulationFixture() });
    const user = userEvent.setup();
    render(<RouteSimulatorPage />);
    await user.type(screen.getByLabelText("Revision ID"), "rev_0123456789abcdef");
    await user.type(screen.getByLabelText("Feature"), "assistant");
    await user.click(screen.getByRole("button", { name: "Simulate route" }));

    expect(await screen.findByRole("heading", { name: "Exact conservative reservation" })).toBeInTheDocument();
    expect(screen.getByText("app_0123456789abcdef")).toBeInTheDocument();
    expect(screen.getByText("rev_0123456789abcdef")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Applicable limits" })).toBeInTheDocument();
    expect(screen.getAllByText("requested_input_tokens")).toHaveLength(2);
    expect(screen.getByText("explanatory")).toBeInTheDocument();
  });

  it("loads exact active route context and rejects a cross-environment simulation result", async () => {
    const simulation = { ...routeSimulationFixture(), environment_id: "env_ffffffffffffffff" };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith("/config") ? { data: {
      created_at: "2026-08-29T00:00:00Z", created_by: "adm_0123456789abcdef",
      document: { spec: { features: [{ id: "assistant" }, { id: "search" }] } },
      environment_id: "env_0123456789abcdef", id: "rev_0123456789abcdef", state: "active", version: 1
    } } : { data: simulation });
    const user = userEvent.setup();
    render(<RouteSimulatorPage />);
    await user.type(screen.getByLabelText("Environment context ID"), "env_0123456789abcdef");
    await user.click(screen.getByRole("button", { name: "Load active route context" }));

    expect(await screen.findByText(/Selected active revision/)).toHaveTextContent("2 features");
    expect(screen.getByLabelText("Revision ID")).toHaveValue("rev_0123456789abcdef");
    expect(screen.getByLabelText("Feature")).toHaveValue("assistant");
    await user.click(screen.getByRole("button", { name: "Simulate route" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Route context mismatch");
    expect(screen.queryByRole("heading", { name: "Allowed" })).not.toBeInTheDocument();
  });

  it("creates, lists, reads, and disables a schedule using only durable token metadata", async () => {
    const schedule = {
      application_id: "app_0123456789abcdef", authorization_credential_id: "tok_0123456789abcdef",
      config_revision_id: "rev_0123456789abcdef", created_at: "2026-08-29T00:00:00Z",
      daily_cost_limit_nano_usd: 240_000_000, environment_id: "env_0123456789abcdef",
      id: "sts_0123456789abcdef", interval_seconds: 3600, kind: "upstream", max_cost_nano_usd: 10_000_000,
      model: "canary", next_run_at: "2026-08-29T01:00:00Z", status: "active",
      updated_at: "2026-08-29T00:00:00Z", upstream: "primary"
    } as const;
    adminRequestMock.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string; body?: unknown }) => {
      if (options?.method === "DELETE") return { data: { ...schedule, disabled_at: "2026-08-29T00:10:00Z", disabled_reason_code: "operator_disabled", next_run_at: undefined, status: "disabled", updated_at: "2026-08-29T00:10:00Z" } };
      if (options?.method === "POST") return { data: schedule };
      if (path === `/admin/v1/self-test-schedules/${schedule.id}`) return { data: schedule };
      return { data: { items: [schedule], page: { has_more: false } } };
    });
    const user = userEvent.setup();
    render(<SelfTestsPage />);
    await user.type(screen.getByLabelText("Scheduled environment ID"), schedule.environment_id);
    await user.click(screen.getByRole("button", { name: "Load schedules" }));

    expect(await screen.findByRole("button", { name: schedule.id })).toBeInTheDocument();
    expect(screen.getByText(schedule.config_revision_id)).toBeInTheDocument();
    expect(screen.getByText(schedule.authorization_credential_id)).toBeInTheDocument();
    const bearerToken = "transient-scheduled-self-test-token-material-1234567890";
    await user.type(screen.getByLabelText(/^Durable Admin API token/), bearerToken);
    await user.type(screen.getByLabelText("Scheduled upstream ID"), schedule.upstream);
    await user.type(screen.getByLabelText("Scheduled model ID"), schedule.model);
    await user.click(screen.getByRole("button", { name: "Create schedule" }));

    expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/self-test-schedules", expect.anything(), expect.objectContaining({
      bearerToken, body: expect.not.objectContaining({ authorization_credential_id: expect.anything() }), method: "POST"
    }));
    expect(screen.getByLabelText(/^Durable Admin API token/)).toHaveValue("");
    const createBody = adminRequestMock.mock.calls.find(([path, , options]) => path === "/admin/v1/self-test-schedules" && options?.method === "POST")?.[2]?.body;
    expect(JSON.stringify(createBody)).not.toContain(bearerToken);
    await user.click(screen.getByRole("button", { name: "Disable schedule" }));
    expect(await screen.findByText(`${schedule.id} · disabled`)).toBeInTheDocument();
  });
});

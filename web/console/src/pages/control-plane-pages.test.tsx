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
      session: { capabilities: ["inspect_users"], organization_id: "org_0123456789abcdef" }
    }
  })
}));

import { RequestsPage, RouteSimulatorPage, UsagePage } from "./control-plane-pages";

const zeroValues = { cost_nano_usd: 0, input_tokens: 0, logical_requests: 0, output_tokens: 0, total_tokens: 0 };

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
    expect(screen.getByText("openrouter_usage_cost")).toBeInTheDocument();
  });

  it("renders token and cost provenance independently for each attempt", async () => {
	adminRequestMock.mockResolvedValue({ data: {
	  items: [{ attempts: [{
		cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost",
		id: "atm_0123456789abcdef", model: "openai/gpt", started_at: "2026-08-29T00:00:00Z",
		status: "succeeded", upstream: "openrouter", usage_provenance: "unknown"
	  }], environment_id: "env_0123456789abcdef", feature: "assistant",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  user_id: "usr_0123456789abcdef" }],
	  page: { has_more: false }
	} });
	const user = userEvent.setup();
	render(<RequestsPage />);
	await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
	await user.click(screen.getByRole("button", { name: "List requests" }));
	await user.click(await screen.findByRole("button", { name: "req_0123456789abcdef" }));
	expect(screen.getByText("upstream_reported")).toBeInTheDocument();
	expect(screen.getByText("openrouter_usage_cost")).toBeInTheDocument();
  });

  it("renders authoritative scope, exact reservation, applicable limits, and fact roles", async () => {
    adminRequestMock.mockResolvedValue({ data: {
      allowed: true, application_id: "app_0123456789abcdef", environment_id: "env_0123456789abcdef",
      environment_kind: "production", explanation: ["production policy allowed"],
      facts: { application_id: "app_0123456789abcdef", authenticated: true, environment_id: "env_0123456789abcdef", environment_kind: "production", feature: "assistant", framing_unit_count: 1, normalized_claims: {}, platform: "react_native_ios", requested_input_tokens: 99, requested_output_max: 100, revision_id: "rev_0123456789abcdef", rewritten_request_bytes: 1024, streaming: false, trust_level: "app_verified" },
      fact_usage: [{ affects_cel: false, explanation: "Untrusted estimate only.", fact: "requested_input_tokens", role: "explanatory" }],
      feature: "assistant", limit_plan: "subscriber",
      limits: [{ algorithm: "calendar", hard: true, maximum: 1000, metric: "total_tokens", scope: ["user", "feature"], timezone: "UTC", window: "1d" }],
      model: "gpt_mobile", physical_model: "gpt-5-mini", pricing_confidence: "configured", protocol: "openai_responses",
      reservation: { allocations: [{ algorithm: "calendar", applicable: true, durable: true, metric: "total_tokens", units: 1132 }], applied_output_maximum: 100, cost_bound_known: true, cost_nano_usd_bound: 50, input_accounting: { framing_unit_count: 1, input_token_bound: 1032, maximum_context_tokens: 128000, maximum_framing_tokens_per_request: 4, maximum_framing_tokens_per_unit: 4, method: "utf8_byte_bpe_declared_framing_v1", profile_id: "gpt_mobile_input", required: true, rewritten_request_bytes: 1024 }, pricing_catalog: "mobile_price", total_token_bound: 1132 },
      revision_id: "rev_0123456789abcdef", route: "primary", upstream: "openai", warnings: []
    } });
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
});

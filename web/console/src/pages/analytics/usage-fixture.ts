// Test fixture shaped like GET /admin/v1/usage/summary; parsed through the real schema so it can't drift.
import { UsageSummarySchema } from "../../api/admin";

export const zero = { cost_nano_usd: 0, input_tokens: 0, logical_requests: 0, output_tokens: 0, total_tokens: 0 };

export function summaryFixture(overrides: Record<string, unknown> = {}) {
  return UsageSummarySchema.parse({
    analytics: {
      active_users: 2,
      attestation_failure_rate: { denominator: 4, numerator: 1, parts_per_million: 250_000 },
      by_feature: { items: [{ active_users: 2, key: "assistant", request_count: 3, values: { ...zero, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      by_model: { items: [{ active_users: 2, key: "gpt_mobile", request_count: 3, values: { ...zero, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      by_selected_plan: { items: [{ active_users: 2, key: "legacy_unknown", request_count: 3, values: { ...zero, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      cost_per_active_user_nano_usd: { denominator: 2, numerator: 900 },
      failure_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
      fallback_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
      quota_denial_rate: { denominator: 3, numerator: 0, parts_per_million: 0 },
      request_count: 3,
      request_latency: { p50_ms: 100, p95_ms: 300, p99_ms: 500, samples: 3 },
      requests_per_active_user: { denominator: 2, numerator: 3 },
      time_to_first_token: { p50_ms: 20, p95_ms: 40, p99_ms: 60, samples: 3 },
      usage_by_provenance: [
        { cost_source: "openrouter_usage_cost", provenance: "upstream_reported", values: { ...zero, input_tokens: 10, output_tokens: 20, total_tokens: 30 } },
        { provenance: "calculated", values: { ...zero, cost_nano_usd: 900 } },
        { provenance: "estimated", values: zero },
        { provenance: "unknown", values: zero }
      ]
    },
    end: "2026-08-29T01:00:00Z", provenance: ["calculated", "upstream_reported"],
    start: "2026-08-29T00:00:00Z", values: { ...zero, cost_nano_usd: 900, input_tokens: 10, logical_requests: 3, output_tokens: 20, total_tokens: 30 },
    ...overrides
  });
}

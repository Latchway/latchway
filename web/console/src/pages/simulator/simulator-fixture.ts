import type { RouteSimulation } from "../../api/admin";

/** A complete, schema-valid allowed simulation result for tests. */
export function simulationFixture(overrides: Partial<RouteSimulation> = {}): RouteSimulation {
  return {
    allowed: true, application_id: "app_0123456789abcdef", environment_id: "env_0123456789abcdef",
    environment_kind: "production", explanation: ["The exact compiled production CEL policy allowed the simulated principal."],
    facts: { application_id: "app_0123456789abcdef", authenticated: true, environment_id: "env_0123456789abcdef", environment_kind: "production", expanded_schema_bytes: 0, feature: "assistant", framing_unit_count: 2, image_units: 0, normalized_claims: {}, platform: "ios", requested_input_tokens: 800, requested_output_max: 500, revision_id: "rev_0123456789abcdef", rewritten_request_bytes: 4000, streaming: false, tool_calls: 0, trust_level: "app_verified" },
    fact_usage: [{ affects_cel: true, explanation: "Plan claim", fact: "principal.claims", role: "policy" }],
    fallback_sequence: [{ fallback_on: ["timeout"], model: "fast", physical_model: "gpt-5-mini", route: "primary", upstream: "openai" }, { fallback_on: [], model: "slow", physical_model: "claude", route: "backup", upstream: "anthropic" }],
    feature: "assistant", limit_plan: "free",
    limits: [{ algorithm: "calendar", hard: true, maximum: 1000, metric: "total_tokens", scope: ["user", "feature"], timezone: "UTC", window: "1d" }],
    model: "fast", physical_model: "gpt-5-mini", pricing_confidence: "configured", protocol: "openai_responses",
    reservation: { allocations: [], applied_output_maximum: 500, cost_bound_known: true, cost_nano_usd_bound: 50, input_accounting: { expanded_schema_bytes: 0, framing_unit_count: 2, input_token_bound: 1300, maximum_context_tokens: 128000, maximum_framing_tokens_per_request: 4, maximum_framing_tokens_per_unit: 4, required: true, rewritten_request_bytes: 4000 }, total_token_bound: 1800 },
    revision_id: "rev_0123456789abcdef", route: "primary", upstream: "openai", warnings: [],
    ...overrides
  } as RouteSimulation;
}

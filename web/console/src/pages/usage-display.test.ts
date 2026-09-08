import { describe, expect, it } from "vitest";
import { UsageValuesSchema } from "../api/admin";
import { displayUsageMetric } from "./usage-display";

describe("usage accounting display", () => {
  it("distinguishes absent billing, reported zero and unknown conservative charges", () => {
    const missing = { recorded_units: null, reported_units: null, unknown_units: null, provenance: [] };
    const usage = UsageValuesSchema.parse({
      logical_requests: 1, input_tokens: 0, output_tokens: 0, total_tokens: 92444, cost_nano_usd: 0,
      details: { input_tokens: missing, cost_nano_usd: missing,
        output_tokens: { recorded_units: 0, reported_units: 0, unknown_units: null, provenance: ["upstream_reported"] },
        total_tokens: { recorded_units: 92444, reported_units: null, unknown_units: 92444, provenance: ["unknown"] }
      }
    });
    expect(displayUsageMetric(usage, "input_tokens")).toBe("Not recorded");
    expect(displayUsageMetric(usage, "cost_nano_usd")).toBe("Not recorded");
    expect(displayUsageMetric(usage, "output_tokens")).toBe("0 reported");
    expect(displayUsageMetric(usage, "total_tokens")).toBe("92,444 recorded · 92,444 unknown quota charge");
  });
  it("does not infer billing or reported counts from older aggregate fields", () => {
    expect(displayUsageMetric(undefined, "cost_nano_usd")).toBe("Not recorded");
    expect(displayUsageMetric({ logical_requests: 1, input_tokens: 0, output_tokens: 0, total_tokens: 0, cost_nano_usd: 0 }, "cost_nano_usd")).toBe("0 (ledger; provenance unavailable)");
  });
});

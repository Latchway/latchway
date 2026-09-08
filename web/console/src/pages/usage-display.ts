import type { z } from "zod";
import type { UsageValuesSchema } from "../api/admin";

type Usage = z.infer<typeof UsageValuesSchema>;
type Metric = "input_tokens" | "output_tokens" | "total_tokens" | "cost_nano_usd";

// Legacy numeric totals are ledger charges, not proof of measurement or billing.
export function displayUsageMetric(usage: Usage | undefined, metric: Metric): string {
  if (!usage) return "Not recorded";
  const details = usage.details?.[metric];
  if (!details) return `${usage[metric].toLocaleString()} (ledger; provenance unavailable)`;
  if (details.recorded_units === null) return "Not recorded";
  const suffix = metric === "cost_nano_usd" ? " nUSD" : "";
  if (details.unknown_units !== null) {
    return `${details.recorded_units.toLocaleString()}${suffix} recorded · ${details.unknown_units.toLocaleString()} unknown quota charge`;
  }
  if (details.reported_units === details.recorded_units) {
    return `${details.recorded_units.toLocaleString()}${suffix} reported`;
  }
  return `${details.recorded_units.toLocaleString()}${suffix} recorded (${details.provenance.join(", ")})`;
}

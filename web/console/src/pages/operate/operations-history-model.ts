import type { HealthHistory } from "../../api/operations-history";

type Sample = HealthHistory["samples"][number];
type State = Sample["overall_state"];

export interface HealthIncident {
  checks: string[];
  end: string;
  start: string;
  state: Exclude<State, "healthy">;
}

const RANK: Readonly<Record<State, number>> = { degraded: 1, healthy: 0, unhealthy: 2 };

/**
 * Groups consecutive non-healthy samples into incidents. A gap longer than two sampling intervals ends an incident,
 * since no worker was sampling then and nothing is known about that time.
 */
export function healthIncidents(samples: readonly Sample[], intervalSeconds: number): HealthIncident[] {
  const incidents: HealthIncident[] = [];
  let current: HealthIncident | undefined;
  let previous: number | undefined;
  for (const sample of samples) {
    const at = Date.parse(sample.sampled_at);
    const contiguous = previous !== undefined && at - previous <= 2 * intervalSeconds * 1000;
    if (sample.overall_state === "healthy" || !contiguous) {
      if (current) incidents.push(current);
      current = undefined;
    }
    if (sample.overall_state !== "healthy") {
      const end = new Date(at + intervalSeconds * 1000).toISOString();
      const checks = [...sample.failed_checks, ...sample.warning_checks];
      if (!current) {
        current = { checks: [...new Set(checks)].sort(), end, start: sample.sampled_at, state: sample.overall_state };
      } else {
        current.end = end;
        current.checks = [...new Set([...current.checks, ...checks])].sort();
        if (RANK[sample.overall_state] > RANK[current.state]) current.state = sample.overall_state;
      }
    }
    previous = at;
  }
  if (current) incidents.push(current);
  return incidents;
}

/** The share of sampled time that was healthy, or undefined with no samples. */
export function healthyShare(samples: readonly Sample[]): number | undefined {
  if (!samples.length) return undefined;
  return samples.filter((sample) => sample.overall_state === "healthy").length / samples.length;
}

/** Success rate in percent with one decimal, or undefined with no finished attempts. */
export function successRate(succeeded: number, failed: number): number | undefined {
  const finished = succeeded + failed;
  return finished ? Math.round((succeeded / finished) * 1000) / 10 : undefined;
}

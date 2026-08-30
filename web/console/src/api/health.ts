import { queryOptions, useQuery } from "@tanstack/react-query";
import { z } from "zod";

export const healthEndpoints = {
  liveness: "/healthz",
  readiness: "/readyz"
} as const;

export type HealthKind = keyof typeof healthEndpoints;
export type HealthState = "available" | "degraded" | "unavailable";

export interface HealthCheck {
  detail?: string;
  name: string;
  state: HealthState;
}

export interface HealthResult {
  checks: HealthCheck[];
  endpoint: string;
  kind: HealthKind;
  latencyMs: number;
  observedAt: string;
  state: HealthState;
  statusCode: number;
  summary: string;
  version?: string;
}

const ObjectCheckSchema = z
  .object({
    detail: z.string().optional(),
    message: z.string().optional(),
    name: z.string().optional(),
    ok: z.boolean().optional(),
    status: z.string().optional()
  })
  .passthrough();

const CheckValueSchema = z.union([
  z.boolean(),
  z.string(),
  ObjectCheckSchema
]);

const HealthPayloadSchema = z
  .object({
    checks: z
      .union([
        z.array(ObjectCheckSchema),
        z.record(z.string(), CheckValueSchema)
      ])
      .optional(),
    detail: z.string().optional(),
    message: z.string().optional(),
    status: z.string().optional(),
    version: z.string().optional()
  })
  .passthrough();

type ParsedHealthPayload = z.infer<typeof HealthPayloadSchema>;

function stateFromWord(value: string | undefined): HealthState | undefined {
  if (!value) {
    return undefined;
  }

  const normalized = value.trim().toLowerCase().replaceAll(/[-\s]+/g, "_");
  if (
    ["available", "healthy", "ok", "pass", "passing", "ready", "up"].includes(
      normalized
    )
  ) {
    return "available";
  }
  if (
    ["degraded", "not_ready", "partial", "pending", "warn", "warning"].includes(
      normalized
    )
  ) {
    return "degraded";
  }
  if (
    ["down", "error", "fail", "failed", "failing", "unavailable", "unhealthy"].includes(
      normalized
    )
  ) {
    return "unavailable";
  }
  return undefined;
}

function normalizeCheck(name: string, value: z.infer<typeof CheckValueSchema>): HealthCheck {
  if (typeof value === "boolean") {
    return { name, state: value ? "available" : "unavailable" };
  }

  if (typeof value === "string") {
    return {
      detail: stateFromWord(value) ? undefined : value,
      name,
      state: stateFromWord(value) ?? "degraded"
    };
  }

  const detail = value.detail ?? value.message;
  const state =
    typeof value.ok === "boolean"
      ? value.ok
        ? "available"
        : "unavailable"
      : (stateFromWord(value.status) ?? "degraded");

  return {
    ...(detail ? { detail } : {}),
    name: value.name ?? name,
    state
  };
}

function normalizeChecks(payload: ParsedHealthPayload | undefined): HealthCheck[] {
  if (!payload?.checks) {
    return [];
  }

  if (Array.isArray(payload.checks)) {
    return payload.checks.map((check, index) =>
      normalizeCheck(check.name ?? `check-${index + 1}`, check)
    );
  }

  return Object.entries(payload.checks).map(([name, check]) =>
    normalizeCheck(name, check)
  );
}

function safeSummary(
  payload: ParsedHealthPayload | undefined,
  text: string,
  response: Response
): string {
  const fromPayload = payload?.message ?? payload?.detail ?? payload?.status;
  if (fromPayload?.trim()) {
    return fromPayload.trim().slice(0, 240);
  }
  if (text.trim()) {
    return text.trim().replaceAll(/\s+/g, " ").slice(0, 240);
  }
  if (response.statusText) {
    return response.statusText;
  }
  return response.ok ? "Endpoint responded successfully." : "Endpoint reported a failure.";
}

export async function fetchHealth(
  kind: HealthKind,
  signal?: AbortSignal,
  fetcher: typeof fetch = globalThis.fetch
): Promise<HealthResult> {
  const endpoint = healthEndpoints[kind];
  const startedAt = Date.now();
  const response = await fetcher(endpoint, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json, text/plain;q=0.9" },
    method: "GET",
    signal
  });
  const text = await response.text();
  let candidate: unknown;

  if (text.trim()) {
    try {
      candidate = JSON.parse(text);
    } catch {
      candidate = undefined;
    }
  }

  const parsed = HealthPayloadSchema.safeParse(candidate);
  const payload = parsed.success ? parsed.data : undefined;
  const payloadState = stateFromWord(payload?.status);
  const state = response.ok
    ? (payloadState ?? "available")
    : payloadState === "degraded"
      ? "degraded"
      : "unavailable";

  return {
    checks: normalizeChecks(payload),
    endpoint,
    kind,
    latencyMs: Math.max(0, Date.now() - startedAt),
    observedAt: new Date().toISOString(),
    state,
    statusCode: response.status,
    summary: safeSummary(payload, text, response),
    ...(payload?.version ? { version: payload.version } : {})
  };
}

export function healthQueryOptions(kind: HealthKind) {
  return queryOptions({
    queryKey: ["system-health", kind] as const,
    queryFn: ({ signal }) => fetchHealth(kind, signal),
    refetchInterval: 15_000,
    refetchIntervalInBackground: false,
    retry: 1,
    staleTime: 5_000
  });
}

export function useSystemHealth() {
  const liveness = useQuery(healthQueryOptions("liveness"));
  const readiness = useQuery(healthQueryOptions("readiness"));

  return { liveness, readiness };
}

export function overallHealthState(
  liveness: HealthResult | undefined,
  readiness: HealthResult | undefined
): HealthState | "loading" {
  if (!liveness || !readiness) {
    return "loading";
  }
  if (liveness.state === "unavailable") {
    return "unavailable";
  }
  if (readiness.state !== "available" || liveness.state !== "available") {
    return "degraded";
  }
  return "available";
}

import { z } from "zod";

import {
  adminRequest,
  queryPath,
  type RouteSimulation,
  RouteSimulationBatchSchema,
  type UsageDistribution,
  UsageDistributionSchema,
  type UserOverridePage,
  UserOverridePageSchema
} from "./admin";

/** Server capability for limit impact, override lists, plan share, saved scenarios, batch and failure simulation. */
export const POLICY_INSIGHTS = "admin_policy_insights";

const Identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,62}$/);
const Instant = z.iso.datetime({ offset: true });
const NonnegativeInteger = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

/** The stored input of a saved scenario: a route-simulation request without application or environment. */
export const ScenarioInputSchema = z
  .object({
    failures: z
      .array(z.object({ attempts: z.number().int().min(0).max(32).optional(), condition: z.string().max(64), route: Identifier }).strict())
      .max(16)
      .optional(),
    feature: Identifier,
    platform: z.enum(["ios", "android", "web", "react_native_ios", "react_native_android", "node"]),
    principal: z.object({ authenticated: z.boolean(), claims: z.record(z.string(), z.unknown()) }).strict(),
    request: z
      .object({
        app_version: z.string().max(128).optional(),
        expanded_schema_bytes: NonnegativeInteger.optional(),
        framing_unit_count: NonnegativeInteger.optional(),
        http_method: z.string().max(8).optional(),
        image_units: NonnegativeInteger.optional(),
        requested_input_tokens: NonnegativeInteger.optional(),
        requested_output_max: NonnegativeInteger.optional(),
        rewritten_request_bytes: NonnegativeInteger.optional(),
        streaming: z.boolean(),
        tool_calls: NonnegativeInteger.optional()
      })
      .strict(),
    trust_level: z.enum(["none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug"])
  })
  .strict();
export type ScenarioInput = z.infer<typeof ScenarioInputSchema>;

export const SimulationScenarioSchema = z
  .object({
    application_id: z.string().regex(/^app_[A-Za-z0-9_-]{16,128}$/),
    created_at: Instant,
    created_by: z.string().max(256),
    id: z.string().regex(/^ssc_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$/),
    input: ScenarioInputSchema,
    name: z.string().min(1).max(100),
    updated_at: Instant,
    updated_by: z.string().max(256),
    version: z.number().int().min(1)
  })
  .strict();
export type SimulationScenario = z.infer<typeof SimulationScenarioSchema>;

const ScenarioListSchema = z.object({ items: z.array(SimulationScenarioSchema).max(200) }).strict();

export async function listScenarios(applicationID: string): Promise<SimulationScenario[]> {
  const items = (await adminRequest(`/admin/v1/applications/${applicationID}/simulation-scenarios`, ScenarioListSchema)).data.items;
  if (items.some((item) => item.application_id !== applicationID)) throw new Error("A scenario belonged to another application.");
  return items;
}

export async function saveScenario(applicationID: string, name: string, input: ScenarioInput, existing?: SimulationScenario): Promise<SimulationScenario> {
  const response = existing
    ? await adminRequest(`/admin/v1/simulation-scenarios/${existing.id}`, SimulationScenarioSchema, { body: { input, name, version: existing.version }, method: "PUT" })
    : await adminRequest(`/admin/v1/applications/${applicationID}/simulation-scenarios`, SimulationScenarioSchema, { body: { input, name }, method: "POST" });
  if (response.data.application_id !== applicationID || response.data.name !== name) throw new Error("The saved scenario didn't match what was sent.");
  return response.data;
}

export async function deleteScenario(scenario: SimulationScenario): Promise<void> {
  await adminRequest(queryPath(`/admin/v1/simulation-scenarios/${scenario.id}`, { version: String(scenario.version) }), z.undefined(), { method: "DELETE" });
}

/** Runs up to 50 simulations in one call; each entry is a result or an error message. */
export async function simulateBatch(revisionID: string, bodies: readonly unknown[]): Promise<Array<{ error?: string; result?: RouteSimulation }>> {
  const response = (await adminRequest(`/admin/v1/config-revisions/${revisionID}/simulate-batch`, RouteSimulationBatchSchema, { body: { requests: bodies }, method: "POST" })).data;
  if (response.items.length !== bodies.length || response.items.some((item, index) => item.index !== index || (item.result && item.result.revision_id !== revisionID))) {
    throw new Error("The batch results didn't match the requests sent.");
  }
  return response.items.map((item) => (item.result ? { result: item.result } : { error: item.problem?.detail ?? "Not simulated." }));
}

export interface DistributionQuery {
  end: string;
  environmentID: string;
  feature?: string;
  limitPlan?: string;
  maximum?: number;
  metric: string;
  scope: readonly string[];
  start: string;
  timezone?: string;
  window: string;
}

export async function usageDistribution(query: DistributionQuery): Promise<UsageDistribution> {
  const response = (await adminRequest(queryPath("/admin/v1/usage/distribution", {
    end: query.end,
    environment_id: query.environmentID,
    feature: query.feature,
    limit_plan: query.limitPlan,
    maximum: query.maximum === undefined ? undefined : String(query.maximum),
    metric: query.metric,
    scope: query.scope.join(","),
    start: query.start,
    timezone: query.timezone,
    window: query.window
  }), UsageDistributionSchema)).data;
  if (response.environment_id !== query.environmentID || response.metric !== query.metric) throw new Error("The distribution didn't match the limit asked about.");
  return response;
}

export async function listOverrides(environmentID: string, filters: { cursor?: string; limitPlan?: string; pageSize?: number; status?: "active" | "ended" }): Promise<UserOverridePage> {
  return (await adminRequest(queryPath("/admin/v1/user-overrides", {
    cursor: filters.cursor,
    environment_id: environmentID,
    limit_plan: filters.limitPlan,
    page_size: filters.pageSize === undefined ? undefined : String(filters.pageSize),
    status: filters.status
  }), UserOverridePageSchema)).data;
}

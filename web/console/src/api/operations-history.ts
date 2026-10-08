import { z } from "zod";

import { adminRequest, queryPath, SelfTestSchema, type SelfTestRun, UsageValuesSchema } from "./admin";
import { ApplicationResourceSchema, type ApplicationResource, EnvironmentResourceSchema, type EnvironmentResource, OrganizationResourceSchema } from "./resources";

/** Server capability for health history, per-connection health, the self-test run list and renames. */
export const OPERATIONS_HISTORY = "admin_operations_history";

const Instant = z.iso.datetime({ offset: true });
const Count = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const CheckID = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);
const Identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,62}$/);
const PageInfo = z.object({ has_more: z.boolean(), next_cursor: z.string().max(2048).optional() }).strict();

export const HealthHistorySchema = z
  .object({
    end: Instant,
    interval_seconds: z.literal(300),
    samples: z
      .array(z.object({ failed_checks: z.array(CheckID).max(64), overall_state: z.enum(["healthy", "degraded", "unhealthy"]), sampled_at: Instant, warning_checks: z.array(CheckID).max(64) }).strict())
      .max(2016),
    start: Instant
  })
  .strict();
export type HealthHistory = z.infer<typeof HealthHistorySchema>;

const LatencySchema = z.object({ p50_ms: Count, p95_ms: Count, p99_ms: Count, samples: Count }).strict();

export const ConnectionHealthSchema = z
  .object({
    connections: z
      .array(
        z
          .object({
            attempts: Count,
            canceled: Count,
            duration: LatencySchema,
            failed: Count,
            failures: z.array(z.object({ code: z.string().regex(/^[a-z][a-z0-9_]{0,99}$/), count: Count.min(1) }).strict()),
            fell_back: Count,
            first_byte: LatencySchema,
            rate_limited: Count,
            server_errors: Count,
            succeeded: Count,
            upstream: Identifier,
            usage: UsageValuesSchema
          })
          .strict()
          .refine((connection) => connection.succeeded + connection.failed + connection.canceled <= connection.attempts, { message: "Attempt outcomes exceed the attempt count." })
      )
      .max(200),
    end: Instant,
    environment_id: z.string().regex(/^env_[A-Za-z0-9_-]{16,128}$/),
    interval: z.enum(["hour", "day"]).optional(),
    series: z.array(z.object({ attempts: Count, failed: Count, timestamp: Instant, upstream: Identifier }).strict()).optional(),
    start: Instant,
    truncated: z.boolean()
  })
  .strict();
export type ConnectionHealth = z.infer<typeof ConnectionHealthSchema>;

const SelfTestPageSchema = z.object({ items: z.array(SelfTestSchema).max(200), page: PageInfo }).strict();
export type SelfTestPage = { items: SelfTestRun[]; page: z.infer<typeof PageInfo> };

export async function healthHistory(start: string, end: string): Promise<HealthHistory> {
  return (await adminRequest(queryPath("/admin/v1/system/health-history", { end, start }), HealthHistorySchema)).data;
}

export async function connectionHealth(environmentID: string, start: string, end: string, interval?: "hour" | "day"): Promise<ConnectionHealth> {
  const response = (await adminRequest(queryPath("/admin/v1/usage/connections", { end, environment_id: environmentID, interval, start }), ConnectionHealthSchema)).data;
  if (response.environment_id !== environmentID) throw new Error("The connection health belonged to another environment.");
  return response;
}

export async function listSelfTests(environmentID: string, cursor?: string): Promise<SelfTestPage> {
  const response = (await adminRequest(queryPath("/admin/v1/self-tests", { cursor, environment_id: environmentID, page_size: "20" }), SelfTestPageSchema)).data;
  if (response.items.some((item) => item.environment_id !== environmentID)) throw new Error("A self-test run belonged to another environment.");
  return response;
}

export async function renameOrganization(organizationID: string, displayName: string) {
  const renamed = (await adminRequest(`/admin/v1/organizations/${organizationID}`, OrganizationResourceSchema, { body: { display_name: displayName }, method: "PATCH" })).data;
  if (renamed.id !== organizationID) throw new Error("The server renamed a different organization.");
  return renamed;
}

export async function renameApplication(applicationID: string, displayName: string): Promise<ApplicationResource> {
  const renamed = (await adminRequest(`/admin/v1/applications/${applicationID}`, ApplicationResourceSchema, { body: { display_name: displayName }, method: "PATCH" })).data;
  if (renamed.id !== applicationID) throw new Error("The server renamed a different application.");
  return renamed;
}

export async function renameEnvironment(environmentID: string, displayName: string): Promise<EnvironmentResource> {
  const renamed = (await adminRequest(`/admin/v1/environments/${environmentID}`, EnvironmentResourceSchema, { body: { display_name: displayName }, method: "PATCH" })).data;
  if (renamed.id !== environmentID) throw new Error("The server renamed a different environment.");
  return renamed;
}

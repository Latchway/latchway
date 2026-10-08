import { z } from "zod";

import {
  adminRequest,
  OperationImpactSchema,
  queryPath,
  UserOperationActionSchema,
  type UserOperationAction,
  UserOperationCountsSchema,
  UserOperationImpactSchema,
  UserUsageSchema
} from "./admin";

/** One user's usage for requests started in [start, end). */
export async function getUserUsage(userID: string, environmentID: string, start: Date, end: Date, signal?: AbortSignal) {
  return (await adminRequest(queryPath(`/admin/v1/users/${userID}/usage`, { end: end.toISOString(), environment_id: environmentID, start: start.toISOString() }), UserUsageSchema, { signal })).data;
}

export async function getInstallationImpact(familyID: string, action: "revoke" | "require_renewal", signal?: AbortSignal) {
  return (await adminRequest(queryPath(`/admin/v1/installation-families/${familyID}/operation-impact`, { action }), OperationImpactSchema, { signal })).data;
}

export async function getComponentImpact(componentID: string, action: "revoke" | "require_reattestation", signal?: AbortSignal) {
  return (await adminRequest(queryPath(`/admin/v1/client-components/${componentID}/operation-impact`, { action }), OperationImpactSchema, { signal })).data;
}

const UserBatchImpactSchema = z
  .object({
    action: UserOperationActionSchema,
    applicable: z.number().int().min(0).max(100),
    items: z
      .array(z.object({ impact: UserOperationImpactSchema.optional(), outcome: z.literal("not_found").optional(), user_id: z.string().regex(/^usr_[A-Za-z0-9_-]{16,128}$/) }).strict())
      .max(100),
    totals: UserOperationCountsSchema
  })
  .strict();

const UserBatchResultSchema = z
  .object({
    action: UserOperationActionSchema,
    done: z.number().int().min(0).max(100),
    results: z
      .array(
        z.object({
          operation_id: z.string().regex(/^arq_[A-Za-z0-9_-]{16,128}$/).optional(),
          outcome: z.enum(["done", "changed", "not_found", "forbidden", "failed"]),
          user_id: z.string().regex(/^usr_[A-Za-z0-9_-]{16,128}$/)
        }).strict()
      )
      .max(100)
  })
  .strict();

export type UserBatchImpact = z.infer<typeof UserBatchImpactSchema>;
export type UserBatchResult = z.infer<typeof UserBatchResultSchema>;

/** Previews one action for up to 100 users; each applicable user carries the token the batch must send back. */
export async function previewUserBatch(environmentID: string, action: UserOperationAction, userIDs: readonly string[]) {
  return (await adminRequest(queryPath("/admin/v1/users/batch-impact", { environment_id: environmentID }), UserBatchImpactSchema, { body: { action, user_ids: userIDs }, method: "POST" })).data;
}

/** Applies the previewed action; users whose state changed since the preview come back as "changed". */
export async function applyUserBatch(environmentID: string, action: UserOperationAction, reason: string, items: ReadonlyArray<{ impact_token: string; user_id: string }>) {
  return (await adminRequest(queryPath("/admin/v1/users/batch", { environment_id: environmentID }), UserBatchResultSchema, { body: { acknowledge_immediate_effect: true, action, items, reason }, method: "POST" })).data;
}

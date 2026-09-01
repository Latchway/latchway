import { z } from "zod";

const Identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,62}$/);
const OpaqueID = (prefix: string) => z.string().regex(new RegExp(`^${prefix}_[A-Za-z0-9_-]{16,128}$`, "u"));
const AnyOpaqueID = z.string().regex(/^[a-z][a-z0-9]{1,15}_[A-Za-z0-9_-]{16,128}$/);
const Cursor = z.string().min(1).max(2048);
const Instant = z.iso.datetime({ offset: true });
const SearchModel = z.string().min(1).max(512).refine(
  (value) => !value.includes("\r") && !value.includes("\n") && !value.includes("\u0000"),
  "Model filters cannot contain control characters."
);
const AuditName = (maximum: number) => z.string().min(1).max(maximum).regex(/^[a-z][a-z0-9_.]*$/);
const AuditReason = z.string()
  .min(1)
  .max(100)
  .regex(/^[a-z][a-z0-9._-]{0,99}$/)
  .refine(
    (value) => !/(password|secret|token|credential|authorization|cookie|private[._]key|ciphertext|proof|evidence)/u.test(value),
    "Audit reason codes cannot contain secret-bearing terms."
  );

const NonnegativeIntegerText = z
  .union([z.string(), z.number().int().nonnegative().safe()])
  .transform((value) => String(value))
  .pipe(z.string().regex(/^(0|[1-9][0-9]*)$/))
  .refine((value) => BigInt(value) <= 9_223_372_036_854_775_807n, "Value exceeds the Admin API int64 range.");

function optional<T extends z.ZodType>(schema: T) {
  return z.preprocess((value) => value === "" || value === null ? undefined : value, schema.optional());
}

const workspaceSearchFields = {
  application: optional(Identifier),
  environment: optional(Identifier),
  organization: optional(Identifier)
};

function validateOrderedRange(
  context: z.RefinementCtx,
  minimum: string | undefined,
  maximum: string | undefined,
  maximumPath: string
): void {
  if (minimum !== undefined && maximum !== undefined && BigInt(minimum) > BigInt(maximum)) {
    context.addIssue({ code: "custom", message: "Maximum must be greater than or equal to minimum.", path: [maximumPath] });
  }
}

function validateTimeRange(
  context: z.RefinementCtx,
  start: string | undefined,
  end: string | undefined
): void {
  if (start !== undefined && end !== undefined && Date.parse(start) >= Date.parse(end)) {
    context.addIssue({ code: "custom", message: "End must be later than start.", path: ["end"] });
  }
}

export const RequestRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  component_kind: optional(Identifier),
  cost_max_nano_usd: optional(NonnegativeIntegerText),
  cost_min_nano_usd: optional(NonnegativeIntegerText),
  cursor: optional(Cursor),
  end: optional(Instant),
  error_code: optional(z.string().regex(/^[a-z][a-z0-9_]{0,99}$/)),
  feature: optional(Identifier),
  latency_max_ms: optional(NonnegativeIntegerText),
  latency_min_ms: optional(NonnegativeIntegerText),
  model: optional(SearchModel),
  platform: optional(z.enum(["ios", "android", "web", "react_native_ios", "react_native_android", "node"])),
  request: optional(OpaqueID("req")),
  request_id: optional(OpaqueID("req")),
  route: optional(Identifier),
  sort: optional(z.enum(["started_at_desc", "started_at_asc"])),
  start: optional(Instant),
  status: optional(z.enum(["succeeded", "failed", "denied", "canceled", "unknown"])),
  tokens_max: optional(NonnegativeIntegerText),
  tokens_min: optional(NonnegativeIntegerText),
  trust_source: optional(Identifier),
  upstream: optional(Identifier),
  user_id: optional(OpaqueID("usr"))
}).superRefine((search, context) => {
  validateTimeRange(context, search.start, search.end);
  validateOrderedRange(context, search.latency_min_ms, search.latency_max_ms, "latency_max_ms");
  validateOrderedRange(context, search.tokens_min, search.tokens_max, "tokens_max");
  validateOrderedRange(context, search.cost_min_nano_usd, search.cost_max_nano_usd, "cost_max_nano_usd");
});

export type RequestRouteSearch = z.infer<typeof RequestRouteSearchSchema>;

export function parseRequestRouteSearch(value: unknown): RequestRouteSearch {
  return RequestRouteSearchSchema.parse(value);
}

export const AuditRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  action: optional(AuditName(100)),
  actor_id: optional(z.string().regex(/^(adm|tok)_[A-Za-z0-9_-]{16,128}$/)),
  actor_kind: optional(z.enum(["admin_user", "admin_api_token", "system"])),
  cursor: optional(Cursor),
  end: optional(Instant),
  environment_id: optional(OpaqueID("env")),
  reason: optional(AuditReason),
  resource_id: optional(AnyOpaqueID),
  resource_type: optional(AuditName(64)),
  result: optional(z.enum(["succeeded", "denied", "failed", "indeterminate"])),
  source: optional(z.enum(["console", "cli", "api", "system"])),
  start: optional(Instant)
}).superRefine((search, context) => {
  validateTimeRange(context, search.start, search.end);
});

export type AuditRouteSearch = z.infer<typeof AuditRouteSearchSchema>;

export function parseAuditRouteSearch(value: unknown): AuditRouteSearch {
  return AuditRouteSearchSchema.parse(value);
}

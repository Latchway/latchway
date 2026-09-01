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
const Platform = z.enum(["ios", "android", "web", "react_native_ios", "react_native_android", "node"]);
const TrustLevel = z.enum(["none", "identity_only", "app_verified", "device_verified", "strong_device_verified", "debug"]);
const QueryBoolean = z.preprocess((value) => {
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  return value;
}, z.boolean());
const AppVersion = z.string().min(1).max(128).regex(/^[A-Za-z0-9._+-]+$/);
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

function boundedNonnegativeIntegerText(maximum: number) {
  return NonnegativeIntegerText.refine((value) => BigInt(value) <= BigInt(maximum), `Value must not exceed ${maximum}.`);
}

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
  event: optional(OpaqueID("aud")),
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

export const ConfigurationRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  environment_id: optional(OpaqueID("env"))
});

export type ConfigurationRouteSearch = z.infer<typeof ConfigurationRouteSearchSchema>;

export function parseConfigurationRouteSearch(value: unknown): ConfigurationRouteSearch {
  return ConfigurationRouteSearchSchema.parse(value);
}

function requireEnvironmentForSelection(
  context: z.RefinementCtx,
  environmentID: string | undefined,
  selections: Array<[string, string | undefined]>
): void {
  if (environmentID || selections.every(([, value]) => value === undefined)) return;
  context.addIssue({ code: "custom", message: "An environment is required for this selection.", path: [selections.find(([, value]) => value !== undefined)?.[0] ?? "environment_id"] });
}

export const InstallationFamilyRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  component_id: optional(OpaqueID("cmp")),
  cursor: optional(Cursor),
  environment_id: optional(OpaqueID("env")),
  family_id: optional(OpaqueID("fam")),
  user_id: optional(OpaqueID("usr"))
}).superRefine((search, context) => {
  requireEnvironmentForSelection(context, search.environment_id, [["component_id", search.component_id], ["cursor", search.cursor], ["family_id", search.family_id], ["user_id", search.user_id]]);
  if (search.component_id && !search.family_id) context.addIssue({ code: "custom", message: "A family is required for a component selection.", path: ["component_id"] });
});

export type InstallationFamilyRouteSearch = z.infer<typeof InstallationFamilyRouteSearchSchema>;
export const parseInstallationFamilyRouteSearch = (value: unknown): InstallationFamilyRouteSearch => InstallationFamilyRouteSearchSchema.parse(value);

export const UserRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  cursor: optional(Cursor),
  environment_id: optional(OpaqueID("env")),
  user_id: optional(OpaqueID("usr"))
}).superRefine((search, context) => {
  requireEnvironmentForSelection(context, search.environment_id, [["cursor", search.cursor], ["user_id", search.user_id]]);
});

export type UserRouteSearch = z.infer<typeof UserRouteSearchSchema>;
export const parseUserRouteSearch = (value: unknown): UserRouteSearch => UserRouteSearchSchema.parse(value);

export const InstallationRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  cursor: optional(Cursor),
  environment_id: optional(OpaqueID("env")),
  installation_id: optional(OpaqueID("ins"))
}).superRefine((search, context) => {
  requireEnvironmentForSelection(context, search.environment_id, [["cursor", search.cursor], ["installation_id", search.installation_id]]);
});

export type InstallationRouteSearch = z.infer<typeof InstallationRouteSearchSchema>;
export const parseInstallationRouteSearch = (value: unknown): InstallationRouteSearch => InstallationRouteSearchSchema.parse(value);

export const AnalyticsRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  end: optional(Instant),
  environment_id: optional(OpaqueID("env")),
  interval: optional(z.enum(["hour", "day"])),
  start: optional(Instant)
}).superRefine((search, context) => {
  validateTimeRange(context, search.start, search.end);
  const values = [search.environment_id, search.start, search.end, search.interval];
  if (values.some((value) => value !== undefined) && values.some((value) => value === undefined)) {
    context.addIssue({ code: "custom", message: "Environment, start, end, and interval must be supplied together." });
  }
});

export type AnalyticsRouteSearch = z.infer<typeof AnalyticsRouteSearchSchema>;
export const parseAnalyticsRouteSearch = (value: unknown): AnalyticsRouteSearch => AnalyticsRouteSearchSchema.parse(value);

export const RouteSimulatorRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  app_version: optional(AppVersion),
  authenticated: optional(QueryBoolean),
  environment_id: optional(OpaqueID("env")),
  feature: optional(Identifier),
  framing_unit_count: optional(boundedNonnegativeIntegerText(4096)),
  platform: optional(Platform),
  requested_input_tokens: optional(boundedNonnegativeIntegerText(2_147_483_647)),
  requested_output_max: optional(boundedNonnegativeIntegerText(2_147_483_647)),
  revision_id: optional(OpaqueID("rev")),
  rewritten_request_bytes: optional(boundedNonnegativeIntegerText(104_857_600)),
  streaming: optional(QueryBoolean),
  trust_level: optional(TrustLevel)
}).superRefine((search, context) => {
  requireEnvironmentForSelection(context, search.environment_id, [["revision_id", search.revision_id], ["feature", search.feature]]);
  if (search.feature && !search.revision_id) context.addIssue({ code: "custom", message: "A revision is required for a feature selection.", path: ["feature"] });
});

export type RouteSimulatorRouteSearch = z.infer<typeof RouteSimulatorRouteSearchSchema>;
export const parseRouteSimulatorRouteSearch = (value: unknown): RouteSimulatorRouteSearch => RouteSimulatorRouteSearchSchema.parse(value);

export const SelfTestRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  environment_id: optional(OpaqueID("env")),
  schedule_id: optional(OpaqueID("sts")),
  self_test_id: optional(OpaqueID("tst"))
}).superRefine((search, context) => {
  requireEnvironmentForSelection(context, search.environment_id, [["schedule_id", search.schedule_id], ["self_test_id", search.self_test_id]]);
});

export type SelfTestRouteSearch = z.infer<typeof SelfTestRouteSearchSchema>;
export const parseSelfTestRouteSearch = (value: unknown): SelfTestRouteSearch => SelfTestRouteSearchSchema.parse(value);

export const FeatureRouteSearchSchema = z.object({
  ...workspaceSearchFields,
  feature: optional(Identifier)
});

export type FeatureRouteSearch = z.infer<typeof FeatureRouteSearchSchema>;
export const parseFeatureRouteSearch = (value: unknown): FeatureRouteSearch => FeatureRouteSearchSchema.parse(value);

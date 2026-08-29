import { z } from "zod";

import {
  AdminRequestError,
  adminCSRFToken,
  parseAdminJSON,
  responseProblem
} from "./auth";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const OpaqueID = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{16,128}$/);
const Identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,62}$/);
const Instant = z.iso.datetime({ offset: true });
const OptionalInstant = Instant.optional();
const NonnegativeSafeInteger = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const PageInfo = z
  .object({ has_more: z.boolean(), next_cursor: z.string().max(2048).optional() })
  .strict();

export const AdministratorSchema = z
  .object({
    created_at: Instant,
    disabled_at: OptionalInstant,
    display_name: z.string().min(1).max(200),
    email: z.email().max(320),
    id: OpaqueID,
    membership_id: OpaqueID,
    organization_id: OpaqueID,
    password_reset_required: z.boolean(),
    role: z.enum(["owner", "admin", "operator", "viewer"]),
    status: z.enum(["active", "disabled"]),
    updated_at: Instant
  })
  .strict();

export const AdministratorPageSchema = z
  .object({ items: z.array(AdministratorSchema).max(200), page: PageInfo })
  .strict();

export const AdministratorCapabilitySchema = z
  .string()
  .regex(/^[a-z][a-z0-9_.-]{0,127}$/);

const APITokenScopesSchema = z
  .array(AdministratorCapabilitySchema)
  .min(1)
  .refine((scopes) => new Set(scopes).size === scopes.length, {
    message: "API token scopes must be unique."
  });

export const APITokenMetadataSchema = z
  .object({
    created_at: Instant,
    expires_at: OptionalInstant,
    id: z.string().regex(/^tok_[A-Za-z0-9_-]{16,128}$/),
    name: z.string().min(1).max(256),
    revoked: z.boolean(),
    scopes: APITokenScopesSchema
  })
  .strict();

export const APITokenPageSchema = z
  .object({ items: z.array(APITokenMetadataSchema) })
  .strict();

export const CreatedAPITokenSchema = z
  .object({
    metadata: APITokenMetadataSchema,
    token: z.string().min(32).max(2048).regex(/^[\x21-\x7e]+$/)
  })
  .strict();

export const UserSchema = z
  .object({
    created_at: Instant,
    environment_id: OpaqueID,
    id: OpaqueID,
    identity_providers: z.array(Identifier).max(64),
    last_seen_at: OptionalInstant,
    limit_plan_override: z.unknown().optional(),
    normalized_claims: z.record(z.string(), z.unknown()),
    status: z.enum(["active", "blocked"])
  })
  .strict();

export const UserPageSchema = z
  .object({ items: z.array(UserSchema).max(200), page: PageInfo })
  .strict();

export const InstallationSchema = z
  .object({
    attestation_provider: Identifier.optional(),
    created_at: Instant,
    dpop_jkt: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    environment_id: OpaqueID,
    id: OpaqueID,
    last_seen_at: OptionalInstant,
    platform: z.enum([
      "ios",
      "android",
      "web",
      "react_native_ios",
      "react_native_android",
      "node"
    ]),
    revoked_at: OptionalInstant,
    status: z.enum(["active", "revoked"]),
    trust_expires_at: OptionalInstant,
    trust_level: z.enum([
      "none",
      "identity_only",
      "web_risk_verified",
      "app_verified",
      "device_verified",
      "strong_device_verified",
      "debug"
    ]),
    user_id: OpaqueID
  })
  .strict();

export const InstallationPageSchema = z
  .object({ items: z.array(InstallationSchema).max(200), page: PageInfo })
  .strict();

const UsageValues = z
  .object({
    cost_nano_usd: NonnegativeSafeInteger,
    input_tokens: NonnegativeSafeInteger,
    logical_requests: NonnegativeSafeInteger,
    output_tokens: NonnegativeSafeInteger,
    total_tokens: NonnegativeSafeInteger
  })
  .strict();

const AttemptSchema = z
  .object({
    completed_at: OptionalInstant,
    id: OpaqueID,
    model: z.string().max(512),
    started_at: Instant,
    status: z.enum(["succeeded", "failed", "canceled", "unknown"]),
    upstream: Identifier,
    usage: UsageValues.optional(),
    usage_provenance: z.enum([
      "upstream_reported",
      "calculated",
      "configured",
      "estimated",
      "unknown"
    ]),
    cost_provenance: z.enum(["upstream_reported", "calculated", "estimated", "unknown"]),
    cost_source: Identifier.optional()
  })
  .strict();

export const RequestSchema = z
  .object({
    attempts: z.array(AttemptSchema).max(32),
    completed_at: OptionalInstant,
    environment_id: OpaqueID,
    feature: Identifier,
    id: OpaqueID,
    installation_id: OpaqueID,
    protocol: z.enum([
      "openai_responses",
      "openai_chat",
      "openai_embeddings",
      "anthropic_messages",
      "opaque_http"
    ]),
    started_at: Instant,
    status: z.enum(["succeeded", "failed", "canceled", "unknown"]),
    usage: UsageValues.optional(),
    user_id: OpaqueID
  })
  .strict();

export const RequestPageSchema = z
  .object({ items: z.array(RequestSchema).max(200), page: PageInfo })
  .strict();

export const UsageSummarySchema = z
  .object({
    analytics: z
      .object({
        active_users: NonnegativeSafeInteger,
        attestation_failure_rate: usageRateSchema(),
        by_feature: usageBreakdownSchema(),
        by_model: usageBreakdownSchema(),
        by_selected_plan: usageBreakdownSchema(),
        cost_per_active_user_nano_usd: usageFractionSchema(),
        failure_rate: usageRateSchema(),
        fallback_rate: usageRateSchema(),
        quota_denial_rate: usageRateSchema(),
        request_count: NonnegativeSafeInteger,
        request_latency: usageDistributionSchema(),
        requests_per_active_user: usageFractionSchema(),
        time_to_first_token: usageDistributionSchema(),
        usage_by_provenance: z
          .array(
            z
              .object({
                cost_source: Identifier.optional(),
                provenance: z.enum(["upstream_reported", "calculated", "estimated", "unknown"]),
                values: UsageValues
              })
              .strict()
          )
          .length(4)
      })
      .strict(),
    end: Instant,
    provenance: z.array(z.string()).max(5),
    start: Instant,
    values: UsageValues
  })
  .strict();

function usageFractionSchema() {
  return z
    .object({ numerator: NonnegativeSafeInteger, denominator: NonnegativeSafeInteger })
    .strict();
}

function usageRateSchema() {
  return usageFractionSchema()
    .extend({ parts_per_million: z.number().int().min(0).max(1_000_000) })
    .strict();
}

function usageDistributionSchema() {
  return z
    .object({
      p50_ms: NonnegativeSafeInteger,
      p95_ms: NonnegativeSafeInteger,
      p99_ms: NonnegativeSafeInteger,
      samples: NonnegativeSafeInteger
    })
    .strict();
}

function usageBreakdownSchema() {
  return z
    .object({
      items: z
        .array(
          z
            .object({
              active_users: NonnegativeSafeInteger,
              key: z.string().min(1).max(512),
              request_count: NonnegativeSafeInteger,
              values: UsageValues
            })
            .strict()
        )
        .max(200),
      limit: z.number().int().min(1).max(200),
      truncated: z.boolean()
    })
    .strict();
}

export const UsageTimeseriesSchema = z
  .object({
    interval: z.enum(["hour", "day"]),
    points: z
      .array(z.object({ timestamp: Instant, values: UsageValues }).strict())
      .max(10_000)
  })
  .strict();

export const AuditPageSchema = z
  .object({
    items: z
      .array(
        z
          .object({
            action: z.string().max(128),
            actor: z.string().max(256),
            id: OpaqueID,
            request_id: z.string().max(256),
            result: z.enum(["succeeded", "denied", "failed", "indeterminate"]),
            summary: z.record(z.string(), z.unknown()),
            target: z.string().max(256),
            timestamp: Instant
          })
          .strict()
      )
      .max(200),
    page: PageInfo
  })
  .strict();

export const SelfTestSchema = z
  .object({
    checks: z
      .array(
        z
          .object({
            name: z.string().max(256),
            safe_detail: z.string().max(2048).optional(),
            state: z.enum(["pending", "passed", "failed", "skipped"])
          })
          .strict()
      )
      .max(32),
    completed_at: OptionalInstant,
    created_at: Instant,
    id: OpaqueID,
    kind: z.enum(["local", "upstream", "openrouter"]),
    state: z.enum(["queued", "running", "passed", "failed", "canceled"])
  })
  .strict();

export const SystemStatusSchema = z
  .object({
    contract_version: z.string().max(64),
    database_schema_version: z.string().max(64),
    protocol_versions: z.array(z.number().int()).max(32),
    ready: z.boolean(),
    role: z.enum(["all", "api", "worker"]),
    server_version: z.string().max(128)
  })
  .strict();

const ValidationIssueSchema = z
  .object({
    code: z.string().max(128),
    message: z.string().max(2048),
    path: z.string().max(1024),
    severity: z.enum(["error", "warning"])
  })
  .strict();

export const ValidationSchema = z
  .object({
    checked_at: Instant,
    issues: z.array(ValidationIssueSchema).max(1000),
    valid: z.boolean()
  })
  .strict();

export const RevisionSchema = z
  .object({
    activated_at: OptionalInstant,
    created_at: Instant,
    created_by: z.string().max(256),
    document: z.record(z.string(), z.unknown()),
    environment_id: OpaqueID,
    id: OpaqueID,
    state: z.enum(["draft", "valid", "active", "superseded", "invalid"]),
    validation: ValidationSchema.optional(),
    version: z.number().int().positive()
  })
  .strict();

export const RouteSimulationSchema = z
  .object({
    allowed: z.boolean(),
    application_id: OpaqueID,
    environment_id: OpaqueID,
    environment_kind: z.enum(["development", "staging", "production"]),
    explanation: z.array(z.string().max(1024)),
    facts: z
      .object({
        app_version: z.string().max(128).optional(),
        application_id: OpaqueID,
        authenticated: z.boolean(),
        environment_id: OpaqueID,
        environment_kind: z.enum(["development", "staging", "production"]),
        feature: Identifier,
        framing_unit_count: z.number().int().min(0).max(4096),
        normalized_claims: z.record(z.string(), z.unknown()),
        platform: z.enum(["ios", "android", "web", "react_native_ios", "react_native_android", "node"]),
        requested_input_tokens: z.number().int().min(0).max(100_000_000),
        requested_output_max: z.number().int().min(0).max(100_000_000),
        revision_id: OpaqueID,
        rewritten_request_bytes: z.number().int().min(0).max(104_857_600),
        streaming: z.boolean(),
        trust_level: z.enum(["none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug"])
      })
      .strict(),
    fact_usage: z
      .array(
        z
          .object({
            affects_cel: z.boolean(),
            explanation: z.string().max(1024),
            fact: z.string().max(128),
            role: z.enum(["authentication", "scope", "policy", "reservation", "explanatory"])
          })
          .strict()
      )
      .max(16),
    fallback_sequence: z
      .array(
        z
          .object({
            fallback_on: z.array(z.string()).max(16),
            model: Identifier,
            physical_model: z.string().max(512),
            route: Identifier,
            upstream: Identifier
          })
          .strict()
      )
      .max(32)
      .optional(),
    feature: Identifier,
    limit_plan: Identifier.optional(),
    limits: z
      .array(
        z
          .object({
            algorithm: z.enum(["calendar", "token_bucket", "concurrency", "per_request"]),
            capacity: NonnegativeSafeInteger.optional(),
            hard: z.boolean(),
            maximum: NonnegativeSafeInteger.optional(),
            metric: z.string().max(64),
            per_request_maximum: NonnegativeSafeInteger.optional(),
            refill_per_second: z.string().max(64).optional(),
            scope: z.array(z.string().max(64)).max(9),
            timezone: z.string().max(128).optional(),
            window: z.string().max(128).optional()
          })
          .strict()
      )
      .max(128)
      .optional(),
    matched_access_expression: z.string().max(4096).optional(),
    model: Identifier.optional(),
    physical_model: z.string().max(512).optional(),
    pricing_confidence: z.enum(["configured", "unknown"]).optional(),
    protocol: z.string().max(64).optional(),
    reservation: z
      .object({
        allocations: z
          .array(
            z
              .object({
                algorithm: z.enum(["calendar", "token_bucket", "concurrency", "per_request"]),
                applicable: z.boolean(),
                durable: z.boolean(),
                metric: z.string().max(64),
                units: NonnegativeSafeInteger
              })
              .strict()
          )
          .max(128),
        applied_output_maximum: NonnegativeSafeInteger,
        cost_bound_known: z.boolean(),
        cost_nano_usd_bound: NonnegativeSafeInteger,
        input_accounting: z
          .object({
            framing_unit_count: z.number().int().min(0).max(4096),
            input_token_bound: NonnegativeSafeInteger,
            maximum_context_tokens: NonnegativeSafeInteger,
            maximum_framing_tokens_per_request: NonnegativeSafeInteger,
            maximum_framing_tokens_per_unit: NonnegativeSafeInteger,
            method: z.enum(["utf8_byte_bpe_declared_framing_v1"]).optional(),
            profile_id: Identifier.optional(),
            required: z.boolean(),
            rewritten_request_bytes: z.number().int().min(0).max(104_857_600)
          })
          .strict(),
        pricing_catalog: Identifier.optional(),
        total_token_bound: NonnegativeSafeInteger
      })
      .strict()
      .optional(),
    revision_id: OpaqueID,
    route: Identifier.optional(),
    upstream: Identifier.optional(),
    warnings: z.array(z.string().max(1024)).max(16).optional()
  })
  .strict();

export const NamedResourceSchema = z
  .object({ created_at: Instant, display_name: z.string().max(256), id: OpaqueID, slug: Identifier })
  .strict();

export const ApplicationSchema = NamedResourceSchema.extend({ organization_id: OpaqueID }).strict();
export const EnvironmentSchema = NamedResourceSchema.extend({
  active_revision_id: OpaqueID.optional(),
  application_id: OpaqueID,
  kind: z.enum(["development", "staging", "production"])
}).strict();

export const SecretMetadataSchema = z
  .object({
    algorithm: z.string().max(128),
    created_at: Instant,
    environment_id: OpaqueID,
    id: OpaqueID,
    master_key_id: z.string().max(256),
    name: Identifier,
    rotated_at: OptionalInstant,
    version: z.number().int().positive()
  })
  .strict();

export const ConfigurationPlanSchema = z
  .object({
    changes: z.array(z.object({ operation: z.enum(["add", "remove", "replace"]), path: z.string(), summary: z.string().optional() }).strict()).max(10_000),
    from_revision_id: OpaqueID,
    to_revision_id: OpaqueID,
    warnings: z.array(ValidationIssueSchema).max(1000)
  })
  .strict();

export type ApplicationUser = z.infer<typeof UserSchema>;
export type Administrator = z.infer<typeof AdministratorSchema>;
export type AdministratorPage = z.infer<typeof AdministratorPageSchema>;
export type APITokenMetadata = z.infer<typeof APITokenMetadataSchema>;
export type APITokenPage = z.infer<typeof APITokenPageSchema>;
export type CreatedAPIToken = z.infer<typeof CreatedAPITokenSchema>;
export type ApplicationUserPage = z.infer<typeof UserPageSchema>;
export type Installation = z.infer<typeof InstallationSchema>;
export type InstallationPage = z.infer<typeof InstallationPageSchema>;
export type LogicalRequest = z.infer<typeof RequestSchema>;
export type LogicalRequestPage = z.infer<typeof RequestPageSchema>;
export type UsageSummary = z.infer<typeof UsageSummarySchema>;
export type UsageTimeseries = z.infer<typeof UsageTimeseriesSchema>;
export type AuditPage = z.infer<typeof AuditPageSchema>;
export type SelfTestRun = z.infer<typeof SelfTestSchema>;
export type SystemStatus = z.infer<typeof SystemStatusSchema>;
export type RouteSimulation = z.infer<typeof RouteSimulationSchema>;
export type ConfigurationRevision = z.infer<typeof RevisionSchema>;
export type ConfigurationValidation = z.infer<typeof ValidationSchema>;
export type ConfigurationPlan = z.infer<typeof ConfigurationPlanSchema>;

interface AdminRequestOptions {
  body?: unknown;
  etag?: string;
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  signal?: AbortSignal;
}

export interface AdminResponse<T> {
  data: T;
  etag?: string;
}

export async function adminRequest<T>(
  path: string,
  schema: z.ZodType<T>,
  options: AdminRequestOptions = {},
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<T>> {
  if (!path.startsWith("/admin/v1/") || path.includes("\n") || path.includes("\r")) {
    throw new Error("Invalid canonical Admin API path.");
  }
  const method = options.method ?? "GET";
  const headers: Record<string, string> = {
    Accept: "application/json, application/problem+json"
  };
  if (method !== "GET") {
    const csrf = adminCSRFToken();
    if (!csrf) {
      throw new AdminRequestError({
        code: "csrf_token_required",
        detail: "Refresh the administrator session before making changes.",
        retryable: true,
        status: 0,
        title: "Session confirmation required"
      });
    }
    headers["X-CSRF-Token"] = csrf;
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (options.etag) {
    headers["If-Match"] = options.etag;
  }
  let response: Response;
  try {
    response = await fetcher(path, {
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      cache: "no-store",
      credentials: "same-origin",
      headers,
      method,
      redirect: "error",
      referrerPolicy: "same-origin",
      signal: options.signal
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new AdminRequestError({
      code: "network_error",
      detail: "The gateway could not be reached.",
      retryable: true,
      status: 0,
      title: "Connection failed"
    });
  }
  const length = Number(response.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(length) && length > MAX_RESPONSE_BYTES) {
    throw invalidResponse(response.status);
  }
  const payload = await parseAdminJSON(response);
  if (!response.ok) {
    throw new AdminRequestError(responseProblem(response, payload));
  }
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw invalidResponse(response.status);
  }
  const etag = response.headers.get("ETag")?.trim();
  return { data: parsed.data, ...(etag ? { etag } : {}) };
}

function invalidResponse(status: number): AdminRequestError {
  return new AdminRequestError({
    code: "invalid_response",
    detail: "The gateway returned a non-conforming administrative response.",
    retryable: true,
    status,
    title: "Invalid server response"
  });
}

export function queryPath(path: string, values: Record<string, string | undefined>): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(values)) {
    if (value) query.set(name, value);
  }
  const encoded = query.toString();
  return encoded ? `${path}?${encoded}` : path;
}

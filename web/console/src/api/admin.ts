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
const Platform = z.enum([
  "ios",
  "android",
  "web",
  "node",
  "react_native_ios",
  "react_native_android",
  "watchos",
  "wearos"
]);
const ComponentKind = z.enum([
  "main_app",
  "widget",
  "share_extension",
  "app_intent_extension",
  "notification_service_extension",
  "action_extension",
  "sso_extension",
  "watch_extension",
  "android_app",
  "wear_app",
  "browser",
  "node_process"
]);
const TrustLevel = z.enum([
  "none",
  "identity_only",
  "web_risk_verified",
  "app_verified",
  "device_verified",
  "strong_device_verified",
  "debug"
]);
const TrustSource = z.enum([
  "direct_attested",
  "delegated_from_attested_root",
  "delegated_identity_only",
  "delegated_direct_attested",
  "identity_only",
  "web_risk_verified",
  "debug"
]);
const AttestationProvider = z.enum([
  "app_attest",
  "play_integrity",
  "firebase_app_check",
  "turnstile",
  "debug"
]);
const InstallationFamilyID = z.string().regex(/^fam_[A-Za-z0-9_-]{16,128}$/);
const ClientComponentID = z.string().regex(/^cmp_[A-Za-z0-9_-]{16,128}$/);
const ComponentKeyID = z.string().regex(/^cky_[A-Za-z0-9_-]{16,128}$/);
const ComponentSessionFamilyID = z.string().regex(/^csf_[A-Za-z0-9_-]{16,128}$/);
const ComponentDelegationID = z.string().regex(/^dlg_[A-Za-z0-9_-]{16,128}$/);
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

export const UsageValuesSchema = z
  .object({
    cost_nano_usd: NonnegativeSafeInteger,
    input_tokens: NonnegativeSafeInteger,
    logical_requests: NonnegativeSafeInteger,
    output_tokens: NonnegativeSafeInteger,
    total_tokens: NonnegativeSafeInteger
  })
  .strict();

export const ComponentDelegationSchema = z
  .object({
    attestation_expires_at: Instant,
    attestation_provider: AttestationProvider,
    configuration_revision_id: OpaqueID,
    consumed_at: OptionalInstant,
    created_at: Instant,
    expires_at: Instant,
    feature_scopes: z.array(Identifier).max(256).refine((features) => new Set(features).size === features.length, {
      message: "Delegated feature scopes must be unique."
    }),
    id: ComponentDelegationID,
    identity_expires_at: Instant,
    parent_component_id: ClientComponentID,
    revoked_at: OptionalInstant,
    trust_level: TrustLevel
  })
  .strict();

export const ClientComponentSchema = z
  .object({
    app_version: z.string().min(1).max(128).optional(),
    attestation_provider: AttestationProvider.optional(),
    component_key_id: ComponentKeyID,
    created_at: Instant,
    definition_id: Identifier,
    delegation: ComponentDelegationSchema.optional(),
    dpop_jkt: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    environment_id: OpaqueID,
    granted_features: z.array(Identifier).max(256).refine((features) => new Set(features).size === features.length, {
      message: "Granted features must be unique."
    }),
    id: ClientComponentID,
    installation_family_id: InstallationFamilyID,
    is_root: z.boolean(),
    key_storage_claim: z.enum([
      "unknown",
      "secure_enclave",
      "keychain",
      "strongbox",
      "tee",
      "software",
      "webcrypto",
      "memory"
    ]),
    kind: ComponentKind,
    last_seen_at: Instant,
    parent_attestation_event_id: OpaqueID.optional(),
    parent_component_id: ClientComponentID.optional(),
    platform: Platform,
    refresh_reuse_count: NonnegativeSafeInteger,
    request_count: NonnegativeSafeInteger,
    revocation_reason: z.string().min(1).max(100).optional(),
    revoked_at: OptionalInstant,
    sdk_version: z.string().min(1).max(128).optional(),
    session_expires_at: OptionalInstant,
    session_failure_count: NonnegativeSafeInteger,
    session_family_id: ComponentSessionFamilyID.optional(),
    session_status: z.enum(["active", "revoked", "expired", "replaced"]).optional(),
    status: z.enum(["active", "suspended", "revoked", "replaced"]),
    trust_expires_at: OptionalInstant,
    trust_source: TrustSource,
    trust_verified_at: OptionalInstant,
    updated_at: Instant,
    usage: UsageValuesSchema,
    user_id: OpaqueID
  })
  .strict()
  .superRefine((component, context) => {
    if (component.is_root === Boolean(component.parent_component_id)) {
      context.addIssue({ code: "custom", message: "Only delegated components have a parent component.", path: ["parent_component_id"] });
    }
    if (component.is_root && component.delegation) {
      context.addIssue({ code: "custom", message: "Root components cannot contain delegation provenance.", path: ["delegation"] });
    }
    if (!component.is_root && (!component.delegation || component.delegation.parent_component_id !== component.parent_component_id)) {
      context.addIssue({ code: "custom", message: "Delegated component ancestry is incomplete or inconsistent.", path: ["delegation"] });
    }
    if (Boolean(component.session_family_id) !== Boolean(component.session_status)) {
      context.addIssue({ code: "custom", message: "Component session identity and status must appear together.", path: ["session_family_id"] });
    }
    if ((component.status === "revoked" || component.status === "replaced") !== Boolean(component.revoked_at)) {
      context.addIssue({ code: "custom", message: "Component revocation lifecycle fields are inconsistent.", path: ["revoked_at"] });
    }
    if (Boolean(component.revoked_at) !== Boolean(component.revocation_reason)) {
      context.addIssue({ code: "custom", message: "Component revocation time and reason must appear together.", path: ["revocation_reason"] });
    }
  });

export const ClientComponentPageSchema = z
  .object({ items: z.array(ClientComponentSchema).max(200), page: PageInfo })
  .strict();

export const InstallationFamilySchema = z
  .object({
    component_count: NonnegativeSafeInteger.min(1).max(128),
    components: z.array(ClientComponentSchema).max(128).optional(),
    created_at: Instant,
    environment_id: OpaqueID,
    id: InstallationFamilyID,
    last_seen_at: Instant,
    platform: Platform,
    request_count: NonnegativeSafeInteger,
    revocation_reason: z.string().min(1).max(100).optional(),
    revoked_at: OptionalInstant,
    root_component_id: ClientComponentID,
    root_trust_expires_at: OptionalInstant,
    root_trust_source: TrustSource,
    status: z.enum(["active", "suspended", "revoked"]),
    updated_at: Instant,
    usage: UsageValuesSchema,
    user_id: OpaqueID
  })
  .strict()
  .superRefine((family, context) => {
    if (family.components && family.components.length !== family.component_count) {
      context.addIssue({ code: "custom", message: "Family detail must contain every counted component.", path: ["components"] });
    }
    if (family.components) {
      if (new Set(family.components.map((component) => component.id)).size !== family.components.length) {
        context.addIssue({ code: "custom", message: "Family component identities must be unique.", path: ["components"] });
      }
      if (family.components.some((component) => component.installation_family_id !== family.id || component.environment_id !== family.environment_id)) {
        context.addIssue({ code: "custom", message: "Family components must share the family and environment scope.", path: ["components"] });
      }
      if (!family.components.some((component) => component.id === family.root_component_id && component.is_root)) {
        context.addIssue({ code: "custom", message: "Family detail must contain its root component.", path: ["root_component_id"] });
      }
      const byID = new Map(family.components.map((component) => [component.id, component]));
      for (const component of family.components) {
        if (component.parent_component_id && !byID.has(component.parent_component_id)) {
          context.addIssue({ code: "custom", message: "A component parent is outside the returned family.", path: ["components"] });
        }
        const visited = new Set<string>();
        let cursor: typeof component | undefined = component;
        while (cursor?.parent_component_id) {
          if (visited.has(cursor.id)) {
            context.addIssue({ code: "custom", message: "The component trust graph contains a cycle.", path: ["components"] });
            break;
          }
          visited.add(cursor.id);
          cursor = byID.get(cursor.parent_component_id);
        }
      }
    }
    if ((family.status === "revoked") !== Boolean(family.revoked_at)) {
      context.addIssue({ code: "custom", message: "Family revocation lifecycle fields are inconsistent.", path: ["revoked_at"] });
    }
    if (Boolean(family.revoked_at) !== Boolean(family.revocation_reason)) {
      context.addIssue({ code: "custom", message: "Family revocation time and reason must appear together.", path: ["revocation_reason"] });
    }
  });

export const InstallationFamilyPageSchema = z
  .object({ items: z.array(InstallationFamilySchema).max(200), page: PageInfo })
  .strict();

const PublicAttemptFailureCode = z.enum([
  "canceled",
  "gateway_error",
  "protocol_error",
  "timeout",
  "unavailable",
  "upstream_rejected",
  "unknown"
]);

const AttemptSchema = z
  .object({
    attempt_number: z.number().int().min(1).max(32),
    completed_at: OptionalInstant,
    failure_code: PublicAttemptFailureCode.optional(),
    first_byte_at: OptionalInstant,
    http_status: z.number().int().min(100).max(599).optional(),
    id: OpaqueID,
    model: z.string().max(512),
    route: Identifier,
    started_at: Instant,
    status: z.enum(["succeeded", "failed", "canceled", "unknown"]),
    upstream: Identifier,
    usage: UsageValuesSchema.optional(),
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
  .strict()
  .superRefine((attempt, context) => {
    const startedAt = Date.parse(attempt.started_at);
    const firstByteAt = attempt.first_byte_at ? Date.parse(attempt.first_byte_at) : undefined;
    const completedAt = attempt.completed_at ? Date.parse(attempt.completed_at) : undefined;
    if (firstByteAt !== undefined && firstByteAt < startedAt) {
      context.addIssue({ code: "custom", message: "First byte precedes attempt start.", path: ["first_byte_at"] });
    }
    if (completedAt !== undefined && completedAt < startedAt) {
      context.addIssue({ code: "custom", message: "Completion precedes attempt start.", path: ["completed_at"] });
    }
    if (firstByteAt !== undefined && completedAt !== undefined && firstByteAt > completedAt) {
      context.addIssue({ code: "custom", message: "First byte follows attempt completion.", path: ["first_byte_at"] });
    }
    if (attempt.status === "unknown") {
      if (attempt.completed_at || attempt.http_status || attempt.failure_code) {
        context.addIssue({ code: "custom", message: "In-progress attempts cannot contain terminal fields." });
      }
      return;
    }
    if (!attempt.completed_at) {
      context.addIssue({ code: "custom", message: "Terminal attempts require completion time.", path: ["completed_at"] });
    }
    if (attempt.status === "succeeded") {
      if (!attempt.http_status || attempt.http_status < 200 || attempt.http_status > 299) {
        context.addIssue({ code: "custom", message: "Successful attempts require a 2xx HTTP status.", path: ["http_status"] });
      }
      if (attempt.failure_code) {
        context.addIssue({ code: "custom", message: "Successful attempts cannot contain a failure code.", path: ["failure_code"] });
      }
    } else if (!attempt.failure_code) {
      context.addIssue({ code: "custom", message: "Failed or canceled attempts require a public failure code.", path: ["failure_code"] });
    }
  });

export const RequestSchema = z
  .object({
    attempts: z.array(AttemptSchema).max(32),
    client_component_id: ClientComponentID.optional(),
    completed_at: OptionalInstant,
    component_definition_id: Identifier.optional(),
    component_kind: ComponentKind.optional(),
    environment_id: OpaqueID,
    feature: Identifier,
    framework: Identifier.optional(),
    framework_version: z
      .string()
      .min(1)
      .max(128)
      .refine((value) => !value.includes("\r") && !value.includes("\n") && !value.includes("\0"), {
        message: "Framework versions cannot contain line breaks or NUL bytes."
      })
      .optional(),
    id: OpaqueID,
    installation_id: OpaqueID,
    installation_family_id: InstallationFamilyID.optional(),
    protocol: z.enum([
      "openai_responses",
      "openai_chat",
      "openai_embeddings",
      "anthropic_messages",
      "opaque_http"
    ]),
    started_at: Instant,
    status: z.enum(["succeeded", "failed", "canceled", "unknown"]),
    trust_source: TrustSource.optional(),
    usage: UsageValuesSchema.optional(),
    user_id: OpaqueID
  })
  .strict()
  .superRefine((request, context) => {
    const componentAttribution = [
      request.installation_family_id,
      request.client_component_id,
      request.component_definition_id,
      request.component_kind,
      request.trust_source
    ];
    const attributed = componentAttribution.filter(Boolean).length;
    if (attributed !== 0 && attributed !== componentAttribution.length) {
      context.addIssue({ code: "custom", message: "Component request attribution must be complete.", path: ["client_component_id"] });
    }
    if (Boolean(request.framework) !== Boolean(request.framework_version)) {
      context.addIssue({ code: "custom", message: "Framework identity and version must appear together.", path: ["framework"] });
    }
    const startedAt = Date.parse(request.started_at);
    const completedAt = request.completed_at ? Date.parse(request.completed_at) : undefined;
    if (completedAt !== undefined && completedAt < startedAt) {
      context.addIssue({ code: "custom", message: "Request completion precedes request start.", path: ["completed_at"] });
    }
    if (request.status === "unknown" && request.completed_at) {
      context.addIssue({ code: "custom", message: "In-progress requests cannot contain completion time.", path: ["completed_at"] });
    }
    if (request.status !== "unknown" && !request.completed_at) {
      context.addIssue({ code: "custom", message: "Terminal requests require completion time.", path: ["completed_at"] });
    }
    request.attempts.forEach((attempt, index) => {
      if (attempt.attempt_number !== index + 1) {
        context.addIssue({
          code: "custom",
          message: "Attempts must be contiguous and ordered by attempt number.",
          path: ["attempts", index, "attempt_number"]
        });
      }
    });
  });

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
                values: UsageValuesSchema
              })
              .strict()
          )
          .length(4)
      })
      .strict(),
    end: Instant,
    provenance: z.array(z.string()).max(5),
    start: Instant,
    values: UsageValuesSchema
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
              values: UsageValuesSchema
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
      .array(z.object({ timestamp: Instant, values: UsageValuesSchema }).strict())
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
    schedule_id: OpaqueID.optional(),
    state: z.enum(["queued", "running", "passed", "failed", "canceled"])
  })
  .strict();

export const SelfTestScheduleSchema = z
  .object({
    application_id: OpaqueID,
    authorization_credential_id: z.string().regex(/^tok_[A-Za-z0-9_-]{16,128}$/),
    config_revision_id: OpaqueID,
    created_at: Instant,
    daily_cost_limit_nano_usd: z.number().int().min(1).max(10_000_000_000),
    disabled_at: OptionalInstant,
    disabled_reason_code: Identifier.optional(),
    environment_id: OpaqueID,
    id: OpaqueID,
    interval_seconds: z.number().int().min(3_600).max(2_592_000),
    kind: z.enum(["upstream", "openrouter"]),
    last_enqueued_at: OptionalInstant,
    last_self_test_id: OpaqueID.optional(),
    max_cost_nano_usd: z.number().int().min(1).max(1_000_000_000),
    model: Identifier,
    next_run_at: OptionalInstant,
    status: z.enum(["active", "disabled"]),
    updated_at: Instant,
    upstream: Identifier
  })
  .strict()
  .superRefine((schedule, context) => {
    if (schedule.daily_cost_limit_nano_usd < schedule.max_cost_nano_usd) {
      context.addIssue({ code: "custom", message: "Daily cost limit is below the per-run maximum.", path: ["daily_cost_limit_nano_usd"] });
    }
    if (schedule.status === "active" && (!schedule.next_run_at || schedule.disabled_at || schedule.disabled_reason_code)) {
      context.addIssue({ code: "custom", message: "Active schedule lifecycle fields are inconsistent." });
    }
    if (schedule.status === "disabled" && (schedule.next_run_at || !schedule.disabled_at || !schedule.disabled_reason_code)) {
      context.addIssue({ code: "custom", message: "Disabled schedule lifecycle fields are inconsistent." });
    }
  });

export const SelfTestSchedulePageSchema = z
  .object({ items: z.array(SelfTestScheduleSchema).max(200), page: PageInfo })
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
export type InstallationFamily = z.infer<typeof InstallationFamilySchema>;
export type InstallationFamilyPage = z.infer<typeof InstallationFamilyPageSchema>;
export type ClientComponent = z.infer<typeof ClientComponentSchema>;
export type ClientComponentPage = z.infer<typeof ClientComponentPageSchema>;
export type LogicalRequest = z.infer<typeof RequestSchema>;
export type LogicalRequestPage = z.infer<typeof RequestPageSchema>;
export type UsageSummary = z.infer<typeof UsageSummarySchema>;
export type UsageTimeseries = z.infer<typeof UsageTimeseriesSchema>;
export type AuditPage = z.infer<typeof AuditPageSchema>;
export type SelfTestRun = z.infer<typeof SelfTestSchema>;
export type SelfTestSchedule = z.infer<typeof SelfTestScheduleSchema>;
export type SelfTestSchedulePage = z.infer<typeof SelfTestSchedulePageSchema>;
export type SystemStatus = z.infer<typeof SystemStatusSchema>;
export type RouteSimulation = z.infer<typeof RouteSimulationSchema>;
export type ConfigurationRevision = z.infer<typeof RevisionSchema>;
export type ConfigurationValidation = z.infer<typeof ValidationSchema>;
export type ConfigurationPlan = z.infer<typeof ConfigurationPlanSchema>;

interface AdminRequestOptions {
  bearerToken?: string;
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
  const bearerToken = options.bearerToken;
  if (bearerToken !== undefined && (bearerToken.length < 32 || bearerToken.length > 2048 || !/^[\x21-\x7e]+$/.test(bearerToken))) {
    throw new Error("Invalid transient Admin API token.");
  }
  const headers: Record<string, string> = {
    Accept: "application/json, application/problem+json"
  };
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  } else if (method !== "GET") {
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
      credentials: bearerToken ? "omit" : "same-origin",
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

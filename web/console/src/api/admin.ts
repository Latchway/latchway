import { z } from "zod";

import {
  AdminRequestError,
  adminCSRFToken,
  parseAdminJSON,
  responseProblem
} from "./auth";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_DEVELOPMENT_SAMPLE_BYTES = 2048;
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

export const NoContentSchema = z.undefined();

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

export const AdminSessionMetadataSchema = z
  .object({
    administrator: z
      .object({
        email: z.email().max(320),
        id: z.string().regex(/^adm_[A-Za-z0-9_-]{16,128}$/)
      })
      .strict(),
    created_at: Instant,
    current: z.boolean(),
    expires_at: Instant,
    id: z.string().regex(/^asn_[A-Za-z0-9_-]{16,128}$/),
    last_seen_at: Instant,
    status: z.enum(["active", "expired", "revoked"])
  })
  .strict();

export const AdminSessionMetadataPageSchema = z
  .object({ items: z.array(AdminSessionMetadataSchema).max(200), page: PageInfo })
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
    first_token_at: OptionalInstant,
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
    const firstTokenAt = attempt.first_token_at ? Date.parse(attempt.first_token_at) : undefined;
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
    if (firstTokenAt !== undefined && (firstByteAt === undefined || firstTokenAt < firstByteAt)) {
      context.addIssue({ code: "custom", message: "First token requires and cannot precede first byte.", path: ["first_token_at"] });
    }
    if (firstTokenAt !== undefined && completedAt !== undefined && firstTokenAt > completedAt) {
      context.addIssue({ code: "custom", message: "First token follows attempt completion.", path: ["first_token_at"] });
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

const RequestDecisionStageName = z.enum([
  "identity_verified",
  "client_trust_verified",
  "client_context_validated",
  "configuration_loaded",
  "request_inspected",
  "policy_evaluated",
  "route_selected",
  "quota_rule_evaluated",
  "quota_reserved",
  "lifecycle_recovered"
]);

export const RequestDecisionStageSchema = z
  .object({
    completed_at: Instant,
    config_revision_id: OpaqueID,
    duration_ms: NonnegativeSafeInteger,
    failure_code: z.string().regex(/^[a-z][a-z0-9_]{0,99}$/).optional(),
    limit_algorithm: z.enum(["calendar", "token_bucket", "per_request", "concurrency"]).optional(),
    limit_maximum: NonnegativeSafeInteger.optional(),
    limit_metric: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/).optional(),
    limit_plan_key: Identifier.optional(),
    limit_rule_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
    model: Identifier.optional(),
    number: z.number().int().min(1).max(256),
    outcome: z.enum(["succeeded", "denied", "failed", "cancelled"]),
    physical_model: z.string().min(1).max(512).refine((value) => !/[\r\n\0]/.test(value)).optional(),
    policy_rule_key: z.string().regex(/^([a-z][a-z0-9_-]{0,62}|[A-Za-z0-9_-]{43})$/).optional(),
    route: Identifier.optional(),
    stage: RequestDecisionStageName,
    started_at: Instant,
    upstream: Identifier.optional()
  })
  .strict()
  .superRefine((stage, context) => {
    const startedAt = Date.parse(stage.started_at);
    const completedAt = Date.parse(stage.completed_at);
    if (completedAt < startedAt || completedAt - startedAt !== stage.duration_ms) {
      context.addIssue({ code: "custom", message: "Decision-stage timing is inconsistent.", path: ["duration_ms"] });
    }
    if ((stage.outcome === "succeeded") === Boolean(stage.failure_code)) {
      context.addIssue({ code: "custom", message: "Only unsuccessful decision stages require a failure code.", path: ["failure_code"] });
    }
    const limitFields = [stage.limit_rule_key, stage.limit_metric, stage.limit_algorithm, stage.limit_maximum];
    const limitFieldsPresent = limitFields.filter((value) => value !== undefined).length;
    if (limitFieldsPresent !== 0 && limitFieldsPresent !== limitFields.length) {
      context.addIssue({ code: "custom", message: "Decision-stage limit provenance must be complete.", path: ["limit_rule_key"] });
    }
    const routeFields = [stage.route, stage.upstream, stage.model, stage.physical_model];
    const routeFieldsPresent = routeFields.filter((value) => value !== undefined).length;
    if (routeFieldsPresent !== 0 && routeFieldsPresent !== routeFields.length) {
      context.addIssue({ code: "custom", message: "Decision-stage route provenance must be complete.", path: ["route"] });
    }
  });

export const RequestSchema = z
  .object({
    attempts: z.array(AttemptSchema).max(32),
    client_component_id: ClientComponentID.optional(),
    completed_at: OptionalInstant,
    component_definition_id: Identifier.optional(),
    component_kind: ComponentKind.optional(),
    config_revision_id: OpaqueID,
    decision_stages: z.array(RequestDecisionStageSchema).max(256),
    environment_id: OpaqueID,
    failure_code: z.string().regex(/^[a-z][a-z0-9_]{0,99}$/).optional(),
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
    selected_limit_plan: Identifier,
    selected_model: Identifier.optional(),
    selected_physical_model: z.string().min(1).max(512).refine((value) => !/[\r\n\0]/.test(value)).optional(),
    selected_route: Identifier.optional(),
    selected_upstream: Identifier.optional(),
    started_at: Instant,
    status: z.enum(["succeeded", "failed", "denied", "canceled", "unknown"]),
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
    const selectedRouteFields = [request.selected_route, request.selected_upstream, request.selected_model, request.selected_physical_model];
    const selectedRouteFieldsPresent = selectedRouteFields.filter(Boolean).length;
    if (selectedRouteFieldsPresent !== 0 && selectedRouteFieldsPresent !== selectedRouteFields.length) {
      context.addIssue({ code: "custom", message: "Selected-route provenance must be complete.", path: ["selected_route"] });
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
    let terminalStage = false;
    request.decision_stages.forEach((stage, index) => {
      if (stage.number !== index + 1) {
        context.addIssue({ code: "custom", message: "Decision stages must be contiguous and ordered.", path: ["decision_stages", index, "number"] });
      }
      if (stage.config_revision_id !== request.config_revision_id) {
        context.addIssue({ code: "custom", message: "Decision-stage revision must match its request.", path: ["decision_stages", index, "config_revision_id"] });
      }
      if (terminalStage) {
        context.addIssue({ code: "custom", message: "No decision stage may follow a terminal stage.", path: ["decision_stages", index] });
      }
      terminalStage ||= stage.outcome !== "succeeded";
      if (stage.limit_plan_key && stage.limit_plan_key !== request.selected_limit_plan) {
        context.addIssue({ code: "custom", message: "Decision-stage plan must match its request.", path: ["decision_stages", index, "limit_plan_key"] });
      }
      if (stage.route && request.selected_route && stage.stage === "route_selected" && stage.route !== request.selected_route) {
        context.addIssue({ code: "custom", message: "Route-selection stage must match the durable selected route.", path: ["decision_stages", index, "route"] });
      }
    });
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

export const DevelopmentSampleSchema = z
  .object({
    feature: Identifier,
    model: z.string().min(1).max(512).refine((value) => !/[\r\n\0]/.test(value)),
    protocol: z.literal("openai_responses"),
    request_id: z.string().regex(/^req_[A-Za-z0-9_-]{16,128}$/),
    status: z.literal("succeeded")
  })
  .strict();

export const ConfirmedUserOperationRequestSchema = z
  .object({
    acknowledge_immediate_effect: z.literal(true),
    impact_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    reason: z.string().trim().min(1).max(500).refine((value) => !value.includes("\0"))
  })
  .strict();

export const UserOperationCountsSchema = z
  .object({
    active_client_components: NonnegativeSafeInteger,
    active_component_refresh_tokens: NonnegativeSafeInteger,
    active_component_sessions: NonnegativeSafeInteger,
    active_installation_families: NonnegativeSafeInteger,
    active_refresh_tokens: NonnegativeSafeInteger,
    active_session_grants: NonnegativeSafeInteger
  })
  .strict();

export const UserOperationActionSchema = z.enum([
  "block",
  "unblock",
  "require_reauthentication",
  "require_app_reverification"
]);

export const UserOperationImpactSchema = z
  .object({
    access_effect: z.string().min(1).max(128),
    action: UserOperationActionSchema,
    applicable: z.boolean(),
    counts: UserOperationCountsSchema,
    current_status: z.enum(["active", "blocked"]),
    immediate: z.boolean(),
    impact_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    reversible: z.boolean(),
    summary: z.string().min(1).max(1024)
  })
  .strict();

export const UserOperationResultSchema = z
  .object({
    impact: UserOperationImpactSchema,
    operation_id: z.string().regex(/^arq_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$/),
    user: UserSchema
  })
  .strict();

export const EffectiveConfigurationSubjectSchema = z
  .object({
    component_id: ClientComponentID.optional(),
    id: z.string().regex(/^(usr|req)_[A-Za-z0-9_-]{16,128}$/),
    installation_id: z.string().regex(/^ins_[A-Za-z0-9_-]{16,128}$/).optional(),
    kind: z.enum(["user", "request"]),
    user_id: z.string().regex(/^usr_[A-Za-z0-9_-]{16,128}$/)
  })
  .strict()
  .superRefine((subject, context) => {
    const expectedPrefix = subject.kind === "user" ? "usr_" : "req_";
    if (!subject.id.startsWith(expectedPrefix)) {
      context.addIssue({ code: "custom", message: "Effective-configuration subject kind and identifier disagree.", path: ["id"] });
    }
  });

export const EffectiveConfigurationInputSchema = z
  .object({
    availability: z.enum(["available", "unavailable"]),
    detail: z.string().min(1).max(2048),
    fact: z.string().regex(/^[a-z][a-z0-9_]{0,62}$/),
    keys: z.array(z.string().min(1).max(128)).max(64).refine((keys) => new Set(keys).size === keys.length).optional(),
    source: z.string().min(1).max(512),
    values: z.record(z.string(), z.string().max(512)).refine((values) => Object.keys(values).length <= 16).optional()
  })
  .strict();

export const EffectiveLimitSchema = z
  .object({
    algorithm: z.enum(["calendar", "token_bucket", "per_request", "concurrency"]),
    capacity: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    hard: z.literal(true),
    index: z.number().int().min(0).max(63),
    maximum: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    metric: Identifier,
    per_request_maximum: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    refill_per_second: z.string().regex(/^[0-9]+(?:\.[0-9]+)?$/).optional(),
    scope: z.array(Identifier).min(1).max(8).refine((scope) => new Set(scope).size === scope.length),
    source: z.string().min(1).max(512),
    timezone: z.string().min(1).max(128).optional(),
    window: z.string().min(2).max(32).optional()
  })
  .strict()
  .superRefine((limit, context) => {
    const present = (value: unknown) => value !== undefined;
    const valid =
      (limit.algorithm === "calendar" && present(limit.maximum) && present(limit.window) && present(limit.timezone) && !present(limit.capacity) && !present(limit.refill_per_second) && !present(limit.per_request_maximum)) ||
      (limit.algorithm === "token_bucket" && present(limit.capacity) && present(limit.refill_per_second) && !present(limit.maximum) && !present(limit.window) && !present(limit.timezone) && !present(limit.per_request_maximum)) ||
      (limit.algorithm === "per_request" && present(limit.per_request_maximum) && !present(limit.maximum) && !present(limit.capacity) && !present(limit.refill_per_second) && !present(limit.window) && !present(limit.timezone)) ||
      (limit.algorithm === "concurrency" && present(limit.maximum) && !present(limit.capacity) && !present(limit.refill_per_second) && !present(limit.per_request_maximum) && !present(limit.window) && !present(limit.timezone));
    if (!valid) context.addIssue({ code: "custom", message: "Effective-limit parameters do not match the algorithm." });
  });

export const EffectiveRouteSchema = z
  .object({
    configured_priority: NonnegativeSafeInteger,
    configured_weight: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    fallback_on: z.array(Identifier).max(32).refine((values) => new Set(values).size === values.length),
    match_expression: z.string().min(1).max(4096),
    model: Identifier,
    observed: z.boolean(),
    order: z.number().int().min(1).max(32),
    physical_model: z.string().min(1).max(512),
    retry_maximum_attempts: z.number().int().min(1).max(32),
    retry_on: z.array(Identifier).max(32).refine((values) => new Set(values).size === values.length),
    route: Identifier,
    source: z.string().min(1).max(512),
    sticky_by: z.string().min(1).max(256).optional(),
    upstream: Identifier
  })
  .strict();

export const EffectiveOutputSchema = z
  .object({
    configured_absolute_maximum_tokens: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    configured_default_maximum_tokens: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    effective_default_maximum_tokens: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    effective_maximum_tokens: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    requested_maximum_tokens: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    source: z.string().min(1).max(512)
  })
  .strict();

export const EffectiveConfigurationSchema = z
  .object({
    component_allowed: z.boolean().optional(),
    component_definition_id: Identifier.optional(),
    decision_stages: z.array(RequestDecisionStageSchema).max(256),
    denial_reason: z.string().min(1).max(128).optional(),
    environment_id: OpaqueID,
    environment_kind: z.enum(["development", "staging", "production"]),
    evaluation_mode: z.enum(["current_user_projection", "recorded_request"]),
    feature: Identifier,
    inputs: z.array(EffectiveConfigurationInputSchema).max(16),
    limit_plan: Identifier.optional(),
    limit_plan_source: z.string().min(1).max(128).optional(),
    limits: z.array(EffectiveLimitSchema).max(64),
    matched_access_expression: z.string().min(1).max(4096).optional(),
    matched_limit_plan_expression: z.string().min(1).max(4096).optional(),
    output: EffectiveOutputSchema.optional(),
    policy_outcome: z.enum(["allowed", "denied", "unavailable"]),
    protocol: z.enum(["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages", "opaque_http"]).optional(),
    request_status: z.enum(["succeeded", "failed", "denied", "canceled", "unknown"]).optional(),
    revision_id: OpaqueID,
    routes: z.array(EffectiveRouteSchema).max(32),
    selected_route: EffectiveRouteSchema.optional(),
    subject: EffectiveConfigurationSubjectSchema,
    user_override_id: OpaqueID.optional(),
    warnings: z.array(z.string().min(1).max(2048)).max(16)
  })
  .strict()
  .superRefine((configuration, context) => {
    const expectedKind = configuration.evaluation_mode === "current_user_projection" ? "user" : "request";
    if (configuration.subject.kind !== expectedKind) {
      context.addIssue({ code: "custom", message: "Evaluation mode and subject kind disagree.", path: ["subject", "kind"] });
    }
    configuration.routes.forEach((route, index) => {
      if (route.order !== index + 1) {
        context.addIssue({ code: "custom", message: "Effective routes must be contiguous and ordered.", path: ["routes", index, "order"] });
      }
    });
  });

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

export const AuditChangeSchema = z
  .object({
    classification: z.enum(["public", "sensitive"]),
    field: z.string().regex(/^[a-z][a-z0-9_.]{0,63}$/),
    operation: z.enum(["set", "clear", "add", "remove", "rotate", "consume", "revoke"]),
    redacted: z.boolean()
  })
  .strict()
  .refine((change) => change.redacted === (change.classification === "sensitive"), {
    message: "Audit redaction marker and classification disagree."
  });

export const AuditEventSchema = z
  .object({
    action: z.string().regex(/^[a-z][a-z0-9_.]{0,99}$/),
    actor: z.string().max(256),
    actor_id: z.string().regex(/^(adm|tok)_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$/).optional(),
    actor_kind: z.enum(["admin_user", "admin_api_token", "system"]),
    changes: z.array(AuditChangeSchema).max(100),
    environment_id: OpaqueID.optional(),
    id: z.string().regex(/^aud_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$/),
    reason: z.string().regex(/^[a-z][a-z0-9._-]{0,99}$/).refine(
      (value) => !/(password|secret|token|credential|authorization|cookie|private_key|ciphertext|proof|evidence)/.test(value),
      { message: "Audit reason code is not redaction-safe." }
    ).optional(),
    request_id: z.union([z.literal(""), z.string().regex(/^arq_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$/)]),
    resource_id: z.string().regex(/^[a-z][a-z0-9]{1,15}_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$/),
    resource_type: z.string().regex(/^[a-z][a-z0-9_.]{0,63}$/),
    result: z.enum(["succeeded", "denied", "failed", "indeterminate"]),
    source: z.enum(["console", "cli", "api", "system"]),
    summary: z.object({ changes: z.array(AuditChangeSchema).max(100) }).strict(),
    target: z.string().max(256),
    timestamp: Instant
  })
  .strict()
  .superRefine((event, context) => {
    if (JSON.stringify(event.changes) !== JSON.stringify(event.summary.changes)) {
      context.addIssue({ code: "custom", message: "Audit summary and canonical changes disagree." });
    }
    const expectedActor = event.actor_id ? `${event.actor_kind}:${event.actor_id}` : event.actor_kind;
    if (event.actor !== expectedActor || (event.actor_kind === "system") !== (event.source === "system")) {
      context.addIssue({ code: "custom", message: "Audit actor and source attribution disagree." });
    }
    if ((event.actor_kind === "admin_user" && !event.actor_id?.startsWith("adm_")) ||
      (event.actor_kind === "admin_api_token" && !event.actor_id?.startsWith("tok_")) ||
      (event.source === "console" && event.actor_kind !== "admin_user") ||
      (event.source === "cli" && event.actor_kind !== "admin_api_token")) {
      context.addIssue({ code: "custom", message: "Audit source is incompatible with the authenticated actor kind." });
    }
    if (event.target !== `${event.resource_type}:${event.resource_id}`) {
      context.addIssue({ code: "custom", message: "Audit target and resource attribution disagree." });
    }
  });

export const AuditPageSchema = z
  .object({
    items: z.array(AuditEventSchema).max(200),
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
    config_revision_id: OpaqueID.optional(),
    environment_id: z.string().regex(/^env_[A-Za-z0-9_-]{16,128}$/),
    id: OpaqueID,
    kind: z.enum(["local", "upstream", "openrouter"]),
    schedule_id: OpaqueID.optional(),
    state: z.enum(["queued", "running", "passed", "failed", "canceled"])
  })
  .strict()
  .superRefine((run, context) => {
    if (run.kind === "local" && run.config_revision_id) {
      context.addIssue({ code: "custom", message: "Local self-tests cannot claim a configuration revision.", path: ["config_revision_id"] });
    }
    if (run.kind !== "local" && !run.config_revision_id) {
      context.addIssue({ code: "custom", message: "Provider self-tests must identify their exact configuration revision.", path: ["config_revision_id"] });
    }
  });

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
    mutation_ready: z.boolean(),
    protocol_versions: z.array(z.number().int()).max(32),
    ready: z.boolean(),
    role: z.enum(["all", "api", "worker"]),
    server_capabilities: z
      .array(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/))
      .max(32)
      .refine((capabilities) => new Set(capabilities).size === capabilities.length, {
        message: "Server capabilities must be unique."
      }),
    server_version: z.string().max(128)
  })
  .strict();

const DoctorCheckSchema = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
    remediation: z.string().max(512).optional(),
    state: z.enum(["passed", "warning", "failed", "skipped"]),
    summary: z.string().min(1).max(512)
  })
  .strict();

const Count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

const DoctorVerificationDependencyFactsSchema = z
  .object({
    configured_selections: Count,
    credential_backed_selections: Count,
    external_network_selections: Count,
    registered_active_keys: Count,
    required_selections: Count,
    resolved_credential_records: Count
  })
  .strict();

export const DoctorReportSchema = z
  .object({
    checks: z.array(DoctorCheckSchema).min(1).max(32),
    database: z.enum(["reachable", "unreachable"]),
    facts: z
      .object({
        configuration: z
          .object({
            active_configurations: Count,
            active_environments: Count,
            cache: z
              .object({
                available: z.boolean(),
                entries: z.number().int().min(0).max(1024),
                estimated_bytes: z.number().int().min(0).max(25_165_824),
                fresh_entries: z.number().int().min(0).max(1024),
                maximum_entries: z.number().int().min(0).max(1024),
                maximum_estimated_bytes: z.number().int().min(0).max(25_165_824),
                newest_loaded_at: OptionalInstant,
                reconciliation_interval_seconds: z.number().int().min(0).max(3600),
                refreshes_in_flight: z.number().int().min(0).max(1024),
                stale_entries: z.number().int().min(0).max(1024)
              })
              .strict(),
            draft_revisions: Count,
            highest_revision_number: Count,
            invalid_revisions: Count,
            missing_active_configuration: Count,
            revisions: Count
          })
          .strict(),
        database: z
          .object({
            latency_ms: Count,
            pool_acquired: Count,
            pool_idle: Count,
            pool_maximum: Count,
            pool_total: Count,
            pool_utilization_ppm: z.number().int().min(0).max(1_000_000),
            reachable: z.boolean(),
            schema_available: Count,
            schema_current: Count,
            size_bytes: Count
          })
          .strict(),
        expired_quota_reservations: Count,
        jobs: z
          .object({
            by_status: z.array(z.object({ count: Count, status: z.enum(["pending", "running", "succeeded", "failed", "dead"]) }).strict()).max(5),
            expired_locks: Count,
            failed_self_tests: Count,
            last_external_jwks_refresh_at: OptionalInstant,
            last_retention_at: OptionalInstant,
            last_signing_key_rotation_at: OptionalInstant,
            last_usage_reconciliation_at: OptionalInstant,
            last_usage_rollup_at: OptionalInstant,
            oldest_pending_at: OptionalInstant,
            recent_self_tests: Count,
            usage_settlement_backlog: Count
          })
          .strict(),
        replicas: z
          .object({
            fresh_by_role: z.array(z.object({ count: Count, role: z.enum(["all", "api", "worker"]) }).strict()).max(3),
            fresh_apis: Count,
            fresh_workers: Count,
            newest_heartbeat_at: OptionalInstant,
            stale_replicas: Count
          })
          .strict(),
        retention: z
          .object({
            admin_session_retention_hours: Count,
            job_history_retention_hours: Count,
            oldest_audit_at: OptionalInstant,
            oldest_request_at: OptionalInstant,
            oldest_usage_at: OptionalInstant,
            policy_mode: z.literal("fixed_operational_operator_tenant_data"),
            runtime_instance_retention_hours: Count
          })
          .strict(),
        runtime: z
          .object({
            build_date: z.string().max(128),
            clock_offset_ms: z.number().int(),
            commit: z.string().max(128),
            compatibility_source: z.literal("embedded_self"),
            contract_version: z.string().max(64),
            latest_compatible_version: z.string().min(1).max(128),
            protocol_versions: z.array(z.number().int().positive()).min(1).max(32),
            role: z.enum(["all", "api", "worker"]),
            server_version: z.string().max(128)
          })
          .strict(),
        security: z
          .object({
            active_secret_records: Count,
            active_signing_keys: Count,
            apple_verification: DoctorVerificationDependencyFactsSchema,
            configured_external_jwks_providers: Count,
            google_verification: DoctorVerificationDependencyFactsSchema,
            identity_provider_errors: Count,
            identity_providers: Count,
            pending_signing_keys: Count,
            retiring_signing_keys: Count,
            signing_key_expires_at: OptionalInstant,
            stale_identity_provider_jwks: Count
          })
          .strict()
      })
      .strict(),
    generated_at: Instant,
    overall_state: z.enum(["healthy", "degraded", "unhealthy"]),
    report_schema: z.literal(1),
    role: z.enum(["all", "api", "worker"]),
    schema_version: Count,
    status: z.enum(["ok", "error"])
  })
  .strict();

export const SupportBundleSchema = z
  .object({
    bundle_schema: z.literal(1),
    generated_at: Instant,
    redaction: z
      .object({
        excluded: z.array(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/)).min(10).max(32),
        mode: z.literal("structural_allowlist")
      })
      .strict(),
    report: DoctorReportSchema,
    source: z.enum(["admin_api", "local_cli", "unknown"])
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
        image_units: z.number().int().min(0).max(1_000_000),
        normalized_claims: z.record(z.string(), z.unknown()),
        platform: z.enum(["ios", "android", "web", "react_native_ios", "react_native_android", "node"]),
        requested_input_tokens: z.number().int().min(0).max(100_000_000),
        requested_output_max: z.number().int().min(0).max(100_000_000),
        revision_id: OpaqueID,
        rewritten_request_bytes: z.number().int().min(0).max(104_857_600),
        streaming: z.boolean(),
        tool_calls: z.number().int().min(0).max(1_000_000),
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
      .max(20),
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
export type AdminSessionMetadata = z.infer<typeof AdminSessionMetadataSchema>;
export type AdminSessionMetadataPage = z.infer<typeof AdminSessionMetadataPageSchema>;
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
export type RequestDecisionStage = z.infer<typeof RequestDecisionStageSchema>;
export type ConfirmedUserOperationRequest = z.infer<typeof ConfirmedUserOperationRequestSchema>;
export type UserOperationAction = z.infer<typeof UserOperationActionSchema>;
export type UserOperationImpact = z.infer<typeof UserOperationImpactSchema>;
export type UserOperationResult = z.infer<typeof UserOperationResultSchema>;
export type EffectiveConfiguration = z.infer<typeof EffectiveConfigurationSchema>;
export type UsageSummary = z.infer<typeof UsageSummarySchema>;
export type UsageTimeseries = z.infer<typeof UsageTimeseriesSchema>;
export type AuditPage = z.infer<typeof AuditPageSchema>;
export type AuditEvent = z.infer<typeof AuditEventSchema>;
export type DoctorReport = z.infer<typeof DoctorReportSchema>;
export type SupportBundle = z.infer<typeof SupportBundleSchema>;
export type SelfTestRun = z.infer<typeof SelfTestSchema>;
export type SelfTestSchedule = z.infer<typeof SelfTestScheduleSchema>;
export type SelfTestSchedulePage = z.infer<typeof SelfTestSchedulePageSchema>;
export type SystemStatus = z.infer<typeof SystemStatusSchema>;
export type RouteSimulation = z.infer<typeof RouteSimulationSchema>;
export type ConfigurationRevision = z.infer<typeof RevisionSchema>;
export type ConfigurationValidation = z.infer<typeof ValidationSchema>;
export type ConfigurationPlan = z.infer<typeof ConfigurationPlanSchema>;
export type DevelopmentSample = z.infer<typeof DevelopmentSampleSchema>;

interface AdminRequestOptions {
  bearerToken?: string;
  body?: unknown;
  etag?: string;
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  reason?: string;
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
    Accept: "application/json, application/problem+json",
    "X-Latchway-Admin-Source": "console"
  };
	if (options.reason !== undefined) {
		if (!/^[a-z][a-z0-9._-]{0,99}$/.test(options.reason) || /(password|secret|token|credential|authorization|cookie|private_key|ciphertext|proof|evidence)/.test(options.reason)) {
			throw new Error("Invalid redaction-safe audit reason code.");
		}
		headers["X-Latchway-Audit-Reason"] = options.reason;
	}
  if (
    options.reason === undefined &&
    options.body !== null &&
    typeof options.body === "object" &&
    !Array.isArray(options.body) &&
    typeof (options.body as Record<string, unknown>).reason === "string" &&
    ((options.body as Record<string, unknown>).reason as string).trim() !== ""
  ) {
    headers["X-Latchway-Audit-Reason"] = "operator_reason_provided";
  }
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

// runDevelopmentSample talks only to the loopback helper mounted by
// `latchway develop`. The helper owns a synthetic debug-attested client; this
// request deliberately carries neither an administrator bearer token nor a
// CSRF token and is unavailable on normal deployments.
export async function runDevelopmentSample(
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<DevelopmentSample>> {
  let response: Response;
  try {
    response = await fetcher("/development/v1/sample-request", {
      body: "{}",
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      method: "POST",
      redirect: "error",
      referrerPolicy: "same-origin"
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new AdminRequestError({
      code: "network_error",
      detail: "The isolated development helper could not be reached.",
      retryable: true,
      status: 0,
      title: "Development sample failed"
    });
  }
  const length = Number(response.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(length) && length > MAX_DEVELOPMENT_SAMPLE_BYTES) {
    throw invalidDevelopmentResponse(response.status);
  }
  const payload = await parseAdminJSON(response, MAX_DEVELOPMENT_SAMPLE_BYTES);
  if (!response.ok) {
    throw new AdminRequestError(responseProblem(response, payload));
  }
  const parsed = DevelopmentSampleSchema.safeParse(payload);
  if (!parsed.success) {
    throw invalidDevelopmentResponse(response.status);
  }
  return { data: parsed.data };
}

function invalidDevelopmentResponse(status: number): AdminRequestError {
  return new AdminRequestError({
    code: "invalid_response",
    detail: "The isolated development helper returned non-conforming sample metadata.",
    retryable: true,
    status,
    title: "Invalid development response"
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

export interface EffectiveUserConfigurationQuery {
  componentID?: string;
  environmentID: string;
  estimatedInputTokens?: number;
  feature: string;
  installationID?: string;
  maximumOutputTokens?: number;
  streaming?: boolean;
}

function parseOperationalPathID(value: string, prefix: "req_" | "usr_"): string {
  const parsed = OpaqueID.parse(value);
  if (!parsed.startsWith(prefix)) throw new Error(`Expected a ${prefix === "req_" ? "request" : "user"} identifier.`);
  return parsed;
}

export function getUserEffectiveConfiguration(
  userID: string,
  query: EffectiveUserConfigurationQuery,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<EffectiveConfiguration>> {
  const parsedUserID = parseOperationalPathID(userID, "usr_");
  const environmentID = OpaqueID.parse(query.environmentID);
  const feature = Identifier.parse(query.feature);
  if (query.installationID && query.componentID) throw new Error("Choose either an installation or a component.");
  const estimatedInputTokens = query.estimatedInputTokens === undefined
    ? undefined
    : z.number().int().min(0).max(2_147_483_647).parse(query.estimatedInputTokens).toString();
  const maximumOutputTokens = query.maximumOutputTokens === undefined
    ? undefined
    : z.number().int().min(0).max(2_147_483_647).parse(query.maximumOutputTokens).toString();
  return adminRequest(
    queryPath(`/admin/v1/users/${parsedUserID}/effective-configuration`, {
      component_id: query.componentID ? ClientComponentID.parse(query.componentID) : undefined,
      environment_id: environmentID,
      estimated_input_tokens: estimatedInputTokens,
      feature,
      installation_id: query.installationID ? z.string().regex(/^ins_[A-Za-z0-9_-]{16,128}$/).parse(query.installationID) : undefined,
      maximum_output_tokens: maximumOutputTokens,
      streaming: query.streaming === undefined ? undefined : String(query.streaming)
    }),
    EffectiveConfigurationSchema,
    {},
    fetcher
  );
}

export function getRequestEffectiveConfiguration(
  requestID: string,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<EffectiveConfiguration>> {
  return adminRequest(
    `/admin/v1/requests/${parseOperationalPathID(requestID, "req_")}/effective-configuration`,
    EffectiveConfigurationSchema,
    {},
    fetcher
  );
}

export function getUserOperationImpact(
  userID: string,
  environmentID: string,
  action: UserOperationAction,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<UserOperationImpact>> {
  return adminRequest(
    queryPath(`/admin/v1/users/${parseOperationalPathID(userID, "usr_")}/operation-impact`, {
      action: UserOperationActionSchema.parse(action),
      environment_id: OpaqueID.parse(environmentID)
    }),
    UserOperationImpactSchema,
    {},
    fetcher
  );
}

export function setApplicationUserBlocked(
  userID: string,
  environmentID: string,
  blocked: boolean,
  confirmation: ConfirmedUserOperationRequest,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<ApplicationUser>> {
  return adminRequest(
    queryPath(`/admin/v1/users/${parseOperationalPathID(userID, "usr_")}/${blocked ? "block" : "unblock"}`, {
      environment_id: OpaqueID.parse(environmentID)
    }),
    UserSchema,
    { body: ConfirmedUserOperationRequestSchema.parse(confirmation), method: "POST" },
    fetcher
  );
}

function requireApplicationUserOperation(
  userID: string,
  environmentID: string,
  route: "require-reauthentication" | "require-app-reverification",
  confirmation: ConfirmedUserOperationRequest,
  fetcher: typeof fetch
): Promise<AdminResponse<UserOperationResult>> {
  return adminRequest(
    queryPath(`/admin/v1/users/${parseOperationalPathID(userID, "usr_")}/${route}`, {
      environment_id: OpaqueID.parse(environmentID)
    }),
    UserOperationResultSchema,
    { body: ConfirmedUserOperationRequestSchema.parse(confirmation), method: "POST" },
    fetcher
  );
}

export function requireApplicationUserReauthentication(
  userID: string,
  environmentID: string,
  confirmation: ConfirmedUserOperationRequest,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<UserOperationResult>> {
  return requireApplicationUserOperation(userID, environmentID, "require-reauthentication", confirmation, fetcher);
}

export function requireApplicationUserAppReverification(
  userID: string,
  environmentID: string,
  confirmation: ConfirmedUserOperationRequest,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminResponse<UserOperationResult>> {
  return requireApplicationUserOperation(userID, environmentID, "require-app-reverification", confirmation, fetcher);
}

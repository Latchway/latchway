import { z } from "zod";

import type { components } from "../generated/admin-api";

type AdminSchema<Name extends keyof components["schemas"]> = components["schemas"][Name];

const opaqueID = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[A-Za-z0-9_-]{16,128}$`));

const ApplicationID = opaqueID("app");
const EnvironmentID = opaqueID("env");
const RevisionID = opaqueID("rev");
const SecretID = opaqueID("sec");
const UserID = opaqueID("usr");
const OverrideID = opaqueID("uov");
const OrganizationID = opaqueID("org");
const Identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,62}$/);
const Instant = z.iso.datetime({ offset: true });
const OptionalInstant = Instant.optional();
const PageInfo = z
  .object({ has_more: z.boolean(), next_cursor: z.string().max(2048).optional() })
  .strict();

export const OrganizationResourceSchema: z.ZodType<AdminSchema<"Organization">> = z
  .object({
    created_at: Instant,
    display_name: z.string().min(1).max(200),
    id: OrganizationID,
    slug: Identifier
  })
  .strict();

export const OrganizationResourcePageSchema: z.ZodType<AdminSchema<"OrganizationPage">> = z
  .object({
    items: z.array(OrganizationResourceSchema).max(200),
    page: PageInfo
  })
  .strict();

export const ApplicationResourceSchema: z.ZodType<AdminSchema<"Application">> = z
  .object({
    created_at: Instant,
    display_name: z.string().min(1).max(200),
    id: ApplicationID,
    organization_id: OrganizationID,
    slug: Identifier
  })
  .strict();

export const ApplicationResourcePageSchema: z.ZodType<AdminSchema<"ApplicationPage">> = z
  .object({
    items: z.array(ApplicationResourceSchema).max(200),
    page: PageInfo
  })
  .strict();

export const EnvironmentResourceSchema: z.ZodType<AdminSchema<"Environment">> = z
  .object({
    active_revision_id: RevisionID.optional(),
    application_id: ApplicationID,
    created_at: Instant,
    display_name: z.string().min(1).max(200),
    id: EnvironmentID,
    kind: z.enum(["development", "staging", "production"]),
    slug: Identifier
  })
  .strict();

export const EnvironmentResourceListSchema: z.ZodType<{ items: AdminSchema<"Environment">[] }> = z
  .object({ items: z.array(EnvironmentResourceSchema).max(1000) })
  .strict();

export const SecretResourceSchema = z
  .object({
    algorithm: z.string().min(1).max(128),
    created_at: Instant,
    environment_id: EnvironmentID,
    id: SecretID,
    master_key_id: z.string().min(1).max(256),
    name: Identifier,
    rotated_at: OptionalInstant,
    version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER)
  })
  .strict();

export const SecretResourcePageSchema = z
  .object({
    items: z.array(SecretResourceSchema).max(200),
    page: PageInfo
  })
  .strict();

const ValidationIssueSchema = z
  .object({
    code: z.string().regex(/^[a-z][a-z0-9_]{0,127}$/),
    message: z.string().max(2048),
    path: z.string().max(1024),
    severity: z.enum(["error", "warning"])
  })
  .strict();

const ValidationReportSchema = z
  .object({
    checked_at: Instant,
    issues: z.array(ValidationIssueSchema).max(1000),
    valid: z.boolean()
  })
  .strict();

const ConfigurationDocumentSchema = z
  .record(z.string().max(128), z.unknown())
  .refine((document) => Object.keys(document).length <= 16, {
    message: "Configuration document has too many top-level fields."
  });

export const ConfigurationRevisionResourceSchema = z
  .object({
    activated_at: OptionalInstant,
    created_at: Instant,
    created_by: z.string().min(1).max(256),
    document: ConfigurationDocumentSchema,
    environment_id: EnvironmentID,
    id: RevisionID,
    state: z.enum(["draft", "valid", "active", "superseded", "invalid"]),
    validation: ValidationReportSchema.optional(),
    version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER)
  })
  .strict();

// The history UI intentionally asks for one full revision per page. A
// configuration document can approach one MiB, while the canonical browser
// client bounds the entire response to two MiB.
export const ConfigurationRevisionResourcePageSchema = z
  .object({
    items: z.array(ConfigurationRevisionResourceSchema).max(1),
    page: PageInfo
  })
  .strict();

export const UserLimitOverrideResourceSchema = z
  .object({
    created_at: Instant,
    expires_at: OptionalInstant,
    id: OverrideID,
    limit_plan: Identifier,
    reason: z.string().min(1).max(500)
  })
  .strict();

const NormalizedClaimsSchema = z
  .record(z.string().max(128), z.unknown())
  .refine((claims) => Object.keys(claims).length <= 64, {
    message: "Normalized claim set is too large."
  });

export const UserOverrideResourceSchema = z
  .object({
    created_at: Instant,
    environment_id: EnvironmentID,
    id: UserID,
    identity_providers: z.array(Identifier).min(1).max(64),
    last_seen_at: OptionalInstant,
    limit_plan_override: UserLimitOverrideResourceSchema.optional(),
    normalized_claims: NormalizedClaimsSchema,
    status: z.enum(["active", "blocked"])
  })
  .strict();

export type ApplicationResource = z.infer<typeof ApplicationResourceSchema>;
export type ApplicationResourcePage = z.infer<typeof ApplicationResourcePageSchema>;
export type EnvironmentResource = z.infer<typeof EnvironmentResourceSchema>;
export type OrganizationResource = z.infer<typeof OrganizationResourceSchema>;
export type SecretResource = z.infer<typeof SecretResourceSchema>;
export type SecretResourcePage = z.infer<typeof SecretResourcePageSchema>;
export type ConfigurationRevisionResource = z.infer<typeof ConfigurationRevisionResourceSchema>;
export type ConfigurationRevisionResourcePage = z.infer<typeof ConfigurationRevisionResourcePageSchema>;
export type UserOverrideResource = z.infer<typeof UserOverrideResourceSchema>;

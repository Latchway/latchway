import { describe, expect, it } from "vitest";

import {
  ApplicationResourcePageSchema,
  ConfigurationRevisionResourcePageSchema,
  SecretResourceSchema,
  UserOverrideResourceSchema
} from "./resources";

const instant = "2026-08-29T00:00:00Z";

const revision = {
  activated_at: instant,
  created_at: instant,
  created_by: "adm_0123456789abcdef",
  document: {
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: {},
    spec: {}
  },
  environment_id: "env_0123456789abcdef",
  id: "rev_0123456789abcdef",
  state: "active",
  version: 2
};

describe("resource-management response schemas", () => {
  it("accepts a bounded canonical application page", () => {
    expect(ApplicationResourcePageSchema.parse({
      items: [{
        created_at: instant,
        display_name: "Mobile",
        id: "app_0123456789abcdef",
        organization_id: "org_0123456789abcdef",
        slug: "mobile",
        status: "active"
      }],
      page: { has_more: false }
    }).items).toHaveLength(1);
  });

  it("rejects plaintext or unknown fields in secret metadata", () => {
    const metadata = {
      algorithm: "xchacha20poly1305",
      created_at: instant,
      environment_id: "env_0123456789abcdef",
      id: "sec_0123456789abcdef",
      master_key_id: "master-key",
      name: "primary_api_key",
      value: "must-not-be-returned",
      version: 1
    };

    expect(SecretResourceSchema.safeParse(metadata).success).toBe(false);
    const withoutPlaintext = Object.fromEntries(
      Object.entries(metadata).filter(([name]) => name !== "value")
    );
    expect(SecretResourceSchema.parse(withoutPlaintext).name).toBe("primary_api_key");
  });

  it("bounds history to one full configuration document per browser page", () => {
    expect(ConfigurationRevisionResourcePageSchema.parse({
      items: [revision],
      page: { has_more: true, next_cursor: "next" }
    }).items).toHaveLength(1);
    expect(ConfigurationRevisionResourcePageSchema.safeParse({
      items: [revision, { ...revision, id: "rev_1123456789abcdef", version: 1 }],
      page: { has_more: false }
    }).success).toBe(false);
  });

  it("rejects unbounded or extra user-override fields", () => {
    const user = {
      created_at: instant,
      environment_id: "env_0123456789abcdef",
      id: "usr_0123456789abcdef",
      identity_providers: ["firebase"],
      limit_plan_override: {
        created_at: instant,
        id: "uov_0123456789abcdef",
        limit_plan: "subscriber",
        reason: "support-approved"
      },
      normalized_claims: { plan: "subscriber" },
      status: "active"
    };
    expect(UserOverrideResourceSchema.parse(user).limit_plan_override?.limit_plan).toBe("subscriber");
    expect(UserOverrideResourceSchema.safeParse({ ...user, external_subject: "plaintext-subject" }).success).toBe(false);
    expect(UserOverrideResourceSchema.safeParse({
      ...user,
      normalized_claims: Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`claim_${index}`, index]))
    }).success).toBe(false);
  });
});

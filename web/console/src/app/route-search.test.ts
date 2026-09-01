import { describe, expect, it } from "vitest";

import {
  AnalyticsRouteSearchSchema,
  AuditRouteSearchSchema,
  ConfigurationRouteSearchSchema,
  FeatureRouteSearchSchema,
  InstallationFamilyRouteSearchSchema,
  InstallationRouteSearchSchema,
  parseAnalyticsRouteSearch,
  parseAuditRouteSearch,
  parseConfigurationRouteSearch,
  parseInstallationFamilyRouteSearch,
  parseRequestRouteSearch,
  parseRouteSimulatorRouteSearch,
  RequestRouteSearchSchema,
  RouteSimulatorRouteSearchSchema,
  SelfTestRouteSearchSchema,
  UserRouteSearchSchema
} from "./route-search";

describe("request route search", () => {
  it("parses every request-list filter into bounded canonical URL state", () => {
    expect(parseRequestRouteSearch({
      application: "mobile-app",
      component_kind: "main_app",
      cost_max_nano_usd: 2_000,
      cost_min_nano_usd: "1000",
      cursor: "next-request-page",
      end: "2026-08-30T00:00:00Z",
      environment: "production",
      error_code: "upstream_timeout",
      feature: "assistant",
      latency_max_ms: 5_000,
      latency_min_ms: "50",
      model: "openai/gpt-5-mini",
      organization: "example",
      platform: "react_native_ios",
      request: "req_0123456789abcdef",
      request_id: "req_1123456789abcdef",
      route: "primary",
      sort: "started_at_asc",
      start: "2026-08-29T00:00:00Z",
      status: "failed",
      tokens_max: 4_096,
      tokens_min: "10",
      trust_source: "direct_attested",
      upstream: "openrouter",
      user_id: "usr_0123456789abcdef"
    })).toEqual({
      application: "mobile-app",
      component_kind: "main_app",
      cost_max_nano_usd: "2000",
      cost_min_nano_usd: "1000",
      cursor: "next-request-page",
      end: "2026-08-30T00:00:00Z",
      environment: "production",
      error_code: "upstream_timeout",
      feature: "assistant",
      latency_max_ms: "5000",
      latency_min_ms: "50",
      model: "openai/gpt-5-mini",
      organization: "example",
      platform: "react_native_ios",
      request: "req_0123456789abcdef",
      request_id: "req_1123456789abcdef",
      route: "primary",
      sort: "started_at_asc",
      start: "2026-08-29T00:00:00Z",
      status: "failed",
      tokens_max: "4096",
      tokens_min: "10",
      trust_source: "direct_attested",
      upstream: "openrouter",
      user_id: "usr_0123456789abcdef"
    });
  });

  it("rejects invalid enums, time windows, and ordered numeric ranges", () => {
    expect(RequestRouteSearchSchema.safeParse({ status: "complete" }).success).toBe(false);
    expect(RequestRouteSearchSchema.safeParse({
      end: "2026-08-29T00:00:00Z",
      start: "2026-08-30T00:00:00Z"
    }).success).toBe(false);
    expect(RequestRouteSearchSchema.safeParse({
      latency_max_ms: "10",
      latency_min_ms: "11"
    }).success).toBe(false);
    expect(RequestRouteSearchSchema.safeParse({
      cost_max_nano_usd: "9223372036854775808"
    }).success).toBe(false);
  });

  it("drops route-foreign keys when navigation preserves the previous search", () => {
    expect(parseRequestRouteSearch({ application: "mobile-app", reason: "operator_action", status: "failed" }))
      .toEqual({ application: "mobile-app", status: "failed" });
  });
});

describe("audit route search", () => {
  it("parses every audit route field and strips request-only state", () => {
    expect(parseAuditRouteSearch({
      action: "admin.user_block",
      actor_id: "tok_0123456789abcdef",
      actor_kind: "admin_api_token",
      application: "mobile-app",
      component_kind: "main_app",
      cursor: "next-audit-page",
      end: "2026-08-30T00:00:00Z",
      environment: "production",
      environment_id: "env_0123456789abcdef",
      event: "aud_0123456789abcdef",
      organization: "example",
      reason: "security_response",
      resource_id: "usr_0123456789abcdef",
      resource_type: "application_user",
      result: "succeeded",
      source: "console",
      start: "2026-08-29T00:00:00Z"
    })).toEqual({
      action: "admin.user_block",
      actor_id: "tok_0123456789abcdef",
      actor_kind: "admin_api_token",
      application: "mobile-app",
      cursor: "next-audit-page",
      end: "2026-08-30T00:00:00Z",
      environment: "production",
      environment_id: "env_0123456789abcdef",
      event: "aud_0123456789abcdef",
      organization: "example",
      reason: "security_response",
      resource_id: "usr_0123456789abcdef",
      resource_type: "application_user",
      result: "succeeded",
      source: "console",
      start: "2026-08-29T00:00:00Z"
    });
  });

  it("rejects secret-bearing reasons and invalid time windows", () => {
    expect(AuditRouteSearchSchema.safeParse({ reason: "rotated_api_token" }).success).toBe(false);
    expect(AuditRouteSearchSchema.safeParse({ event: "req_0123456789abcdef" }).success).toBe(false);
    expect(AuditRouteSearchSchema.safeParse({
      end: "2026-08-29T00:00:00Z",
      start: "2026-08-29T00:00:00Z"
    }).success).toBe(false);
  });
});

describe("configuration route search", () => {
  it("retains only a canonical environment selection and workspace slugs", () => {
    expect(parseConfigurationRouteSearch({
      application: "mobile-app",
      environment: "production",
      environment_id: "env_0123456789abcdef",
      request: "req_0123456789abcdef"
    })).toEqual({
      application: "mobile-app",
      environment: "production",
      environment_id: "env_0123456789abcdef"
    });
  });

  it("rejects an untyped or truncated environment identifier", () => {
    expect(ConfigurationRouteSearchSchema.safeParse({ environment_id: "app_0123456789abcdef" }).success).toBe(false);
    expect(ConfigurationRouteSearchSchema.safeParse({ environment_id: "env_short" }).success).toBe(false);
  });
});

describe("shareable operational route search", () => {
  it("retains a complete bounded Installation Family drill-down", () => {
    expect(parseInstallationFamilyRouteSearch({
      component_id: "cmp_0123456789abcdef",
      cursor: "next-family-page",
      environment_id: "env_0123456789abcdef",
      family_id: "fam_0123456789abcdef",
      user_id: "usr_0123456789abcdef"
    })).toEqual({
      component_id: "cmp_0123456789abcdef",
      cursor: "next-family-page",
      environment_id: "env_0123456789abcdef",
      family_id: "fam_0123456789abcdef",
      user_id: "usr_0123456789abcdef"
    });
    expect(InstallationFamilyRouteSearchSchema.safeParse({ component_id: "cmp_0123456789abcdef", environment_id: "env_0123456789abcdef" }).success).toBe(false);
    expect(InstallationFamilyRouteSearchSchema.safeParse({ family_id: "fam_0123456789abcdef" }).success).toBe(false);
  });

  it("requires environment scope for user, installation, and self-test selections", () => {
    expect(UserRouteSearchSchema.safeParse({ user_id: "usr_0123456789abcdef" }).success).toBe(false);
    expect(InstallationRouteSearchSchema.safeParse({ installation_id: "ins_0123456789abcdef" }).success).toBe(false);
    expect(SelfTestRouteSearchSchema.safeParse({ self_test_id: "tst_0123456789abcdef" }).success).toBe(false);
    expect(SelfTestRouteSearchSchema.safeParse({ environment_id: "env_0123456789abcdef", schedule_id: "sts_0123456789abcdef", self_test_id: "tst_0123456789abcdef" }).success).toBe(true);
  });

  it("accepts only complete ordered analytics windows", () => {
    expect(parseAnalyticsRouteSearch({
      end: "2026-08-30T00:00:00Z",
      environment_id: "env_0123456789abcdef",
      interval: "hour",
      start: "2026-08-29T00:00:00Z"
    })).toMatchObject({ interval: "hour" });
    expect(AnalyticsRouteSearchSchema.safeParse({ environment_id: "env_0123456789abcdef" }).success).toBe(false);
    expect(AnalyticsRouteSearchSchema.safeParse({ end: "2026-08-29T00:00:00Z", environment_id: "env_0123456789abcdef", interval: "day", start: "2026-08-30T00:00:00Z" }).success).toBe(false);
  });

  it("keeps only non-PII simulator request shape and strips sensitive local state", () => {
    const parsed = parseRouteSimulatorRouteSearch({
      app_version: "1.2.3-beta",
      authenticated: "true",
      claims: "{\"plan\":\"premium\"}",
      confirmation: "REVOKE",
      credential: "provider-key",
      environment_id: "env_0123456789abcdef",
      feature: "assistant",
      framing_unit_count: 2,
      platform: "react_native_ios",
      reason: "operator prose",
      requested_input_tokens: 100,
      requested_output_max: "200",
      revision_id: "rev_0123456789abcdef",
      rewritten_request_bytes: 4096,
      streaming: "false",
      token: "secret-token",
      trust_level: "app_verified"
    });
    expect(parsed).toEqual({
      app_version: "1.2.3-beta",
      authenticated: true,
      environment_id: "env_0123456789abcdef",
      feature: "assistant",
      framing_unit_count: "2",
      platform: "react_native_ios",
      requested_input_tokens: "100",
      requested_output_max: "200",
      revision_id: "rev_0123456789abcdef",
      rewritten_request_bytes: "4096",
      streaming: false,
      trust_level: "app_verified"
    });
    expect(RouteSimulatorRouteSearchSchema.safeParse({ environment_id: "env_0123456789abcdef", feature: "assistant" }).success).toBe(false);
    expect(RouteSimulatorRouteSearchSchema.safeParse({ environment_id: "env_0123456789abcdef", framing_unit_count: 4097 }).success).toBe(false);
  });

  it("keeps feature selection canonical and drops route-foreign sensitive values", () => {
    expect(FeatureRouteSearchSchema.parse({ feature: "assistant", reason: "never-share", secret: "never-share" })).toEqual({ feature: "assistant" });
    expect(FeatureRouteSearchSchema.safeParse({ feature: "Assistant display name" }).success).toBe(false);
  });
});

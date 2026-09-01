import { describe, expect, it } from "vitest";

import {
  AuditRouteSearchSchema,
  parseAuditRouteSearch,
  parseRequestRouteSearch,
  RequestRouteSearchSchema
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
  it("parses every audit-list filter and strips request-only state", () => {
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
    expect(AuditRouteSearchSchema.safeParse({
      end: "2026-08-29T00:00:00Z",
      start: "2026-08-29T00:00:00Z"
    }).success).toBe(false);
  });
});

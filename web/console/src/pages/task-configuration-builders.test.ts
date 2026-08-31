import { describe, expect, it } from "vitest";

import type { JSONRecord } from "./configuration-slice";
import {
  buildClientAccessDocument,
  buildConnectionDocument,
  buildUsagePlanDocument,
  describeLimit,
  specRecords,
  usdToNanoUSD
} from "./task-configuration-builders";

function documentFixture(): JSONRecord {
  return {
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: { application: "habitify", environment: "production", labels: { owner: "mobile" }, organization: "example" },
    spec: {
      attestationPolicies: [{ id: "existing", platforms: { node: { mode: "disabled", provider: "debug" } } }],
      componentDefinitions: [],
      features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "existing", id: "assistant", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [] }],
      identityProviders: [],
      inputAccountingProfiles: [],
      limitPlans: [],
      models: [],
      pricingCatalogs: [],
      privacy: { requestBodyLogging: false, responseBodyLogging: false },
      upstreams: []
    }
  };
}

describe("task-oriented configuration builders", () => {
  it("converts operator-entered USD to exact integer nano-USD", () => {
    expect(usdToNanoUSD("0")).toBe(0);
    expect(usdToNanoUSD("0.000000001")).toBe(1);
    expect(usdToNanoUSD("0.25")).toBe(250_000_000);
    expect(usdToNanoUSD("2")).toBe(2_000_000_000);
    expect(() => usdToNanoUSD("1e-3")).toThrow("no exponent notation");
    expect(() => usdToNanoUSD("0.0000000001")).toThrow("nine decimal places");
  });

  it("adds one HTTPS connection, model, accounting profile, and pricing catalog without leaking or dropping document fields", () => {
    const original = documentFixture();
    const result = buildConnectionDocument(original, {
      authentication: "bearer",
      baseURL: "https://api.example.test/v1/",
      connectionID: "primary",
      inputPriceUSDPerMillion: "0.25",
      maximumContextTokens: 128_000,
      maximumFramingTokensPerMessage: 4,
      maximumFramingTokensPerRequest: 8,
      modelID: "assistant_default",
      outputPriceUSDPerMillion: "2",
      physicalModel: "provider-model-v1",
      protocol: "openai_responses",
      providerType: "openai_compatible",
      requestPriceUSD: "0.000001",
      secretName: "provider_api_key"
    });

    expect(result.metadata).toEqual(original.metadata);
    expect((result.spec as JSONRecord).privacy).toEqual((original.spec as JSONRecord).privacy);
    expect(specRecords(result, "upstreams")).toEqual([{
      authentication: { secretRef: "secret/provider_api_key", type: "bearer" },
      baseUrl: "https://api.example.test/v1",
      id: "primary",
      type: "openai_compatible"
    }]);
    expect(specRecords(result, "models")[0]).toMatchObject({ id: "assistant_default", inputAccountingRef: "assistant_default_input", pricingRef: "assistant_default_pricing", upstream: "primary" });
    expect(specRecords(result, "pricingCatalogs")[0]?.entries).toEqual([{ inputNanoUsdPerMillion: 250_000_000, model: "assistant_default", outputNanoUsdPerMillion: 2_000_000_000, requestNanoUsd: 1_000 }]);
    expect(JSON.stringify(result)).not.toContain("provider credential");
    expect(specRecords(original, "upstreams")).toEqual([]);
    expect(() => buildConnectionDocument(original, {
      authentication: "none", baseURL: "http://127.0.0.1:19090", connectionID: "local", inputPriceUSDPerMillion: "0", maximumContextTokens: 1, maximumFramingTokensPerMessage: 0, maximumFramingTokensPerRequest: 0, modelID: "local_model", outputPriceUSDPerMillion: "0", physicalModel: "fixture", protocol: "openai_responses", providerType: "openai_compatible", requestPriceUSD: "0"
    })).toThrow("HTTPS is required");
    expect(() => buildConnectionDocument(original, {
      authentication: "none", baseURL: "https://api.anthropic.com", connectionID: "mismatched", inputPriceUSDPerMillion: "0", maximumContextTokens: 1, maximumFramingTokensPerMessage: 0, maximumFramingTokensPerRequest: 0, modelID: "mismatched_model", outputPriceUSDPerMillion: "0", physicalModel: "fixture", protocol: "openai_responses", providerType: "anthropic", requestPriceUSD: "0"
    })).toThrow("matches the connection type");
  });

  it.each([
    {
      expectedProvider: "app_attest",
      input: { appIDPrefix: "TEAM123", appleBundleID: "com.example.habitify", appleBundleVersion: "42", appleValidationCategory: 4 as const, platform: "ios" as const }
    },
    {
      expectedProvider: "play_integrity",
      input: { androidCertificateDigest: "A".repeat(43), androidCloudProjectNumber: 123456, androidPackageName: "com.example.habitify", androidVersionCode: 42, platform: "android" as const }
    },
    {
      expectedProvider: "firebase_app_check",
      input: { firebaseAppID: "1:123456:web:abcdef", firebaseProjectNumber: "123456", platform: "web" as const, webOrigin: "https://app.example.test" }
    }
  ])("builds a production $input.platform root component and required verification policy", ({ expectedProvider, input }) => {
    const result = buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: `${input.platform}_clients`,
      componentID: `${input.platform}_main`,
      environmentKind: "production",
      featureID: "assistant",
      ...input
    });
    expect(specRecords(result, "componentDefinitions")[0]).toMatchObject({ allowedFeatures: ["assistant"], attestation: { provider: expectedProvider, strategy: "direct" }, familyRole: "root", platform: input.platform });
    expect(specRecords(result, "attestationPolicies").find((policy) => policy.id === `${input.platform}_clients`)).toMatchObject({ id: `${input.platform}_clients`, platforms: { [input.platform]: { mode: "required", provider: expectedProvider } } });
    expect(specRecords(result, "features").find((feature) => feature.id === "assistant")?.attestationPolicy).toBe(`${input.platform}_clients`);
    expect(JSON.stringify(specRecords(result, "attestationPolicies").find((policy) => policy.id === `${input.platform}_clients`))).not.toContain("debug");
  });

  it("adds Firebase user authentication with the application surface when explicitly requested", () => {
    const result = buildClientAccessDocument(documentFixture(), {
      appIDPrefix: "TEAM123",
      appleBundleID: "com.example.habitify",
      appleBundleVersion: "42",
      attestationPolicyID: "ios_clients",
      componentID: "ios_main",
      environmentKind: "production",
      featureID: "assistant",
      firebaseProjectID: "habitify-prod",
      identityProviderID: "firebase",
      platform: "ios"
    });
    expect(specRecords(result, "identityProviders")).toEqual([{ id: "firebase", projectId: "habitify-prod", type: "firebase" }]);
  });

  it("adds a platform to an existing feature policy without dropping its other platform selections", () => {
    const result = buildClientAccessDocument(documentFixture(), {
      appIDPrefix: "TEAM123",
      appleBundleID: "com.example.habitify",
      appleBundleVersion: "42",
      attestationPolicyID: "existing",
      componentID: "ios_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "ios"
    });
    const policy = specRecords(result, "attestationPolicies").find((candidate) => candidate.id === "existing");
    expect(policy?.platforms).toMatchObject({ ios: { mode: "required", provider: "app_attest" }, node: { mode: "disabled", provider: "debug" } });
  });

  it("turns common operator limits into hard runtime rules with readable summaries", () => {
    const result = buildUsagePlanDocument(documentFixture(), {
      dailyCostUSD: "1.5",
      dailyInputTokens: 100_000,
      dailyLogicalRequests: 100,
      dailyOutputTokens: 50_000,
      dailyTotalTokens: 150_000,
      maximumConcurrentRequests: 4,
      perRequestInputTokens: 20_000,
      perRequestOutputTokens: 2_000,
      planID: "starter",
      scope: "user_feature",
      timezone: "UTC"
    });
    const plan = specRecords(result, "limitPlans")[0];
    const limits = plan?.limits as JSONRecord[];
    expect(limits).toHaveLength(8);
    expect(limits.every((limit) => limit.hard === true && JSON.stringify(limit.scope) === JSON.stringify(["user", "feature"]))).toBe(true);
    expect(limits).toContainEqual({ algorithm: "calendar", hard: true, maximum: 1_500_000_000, metric: "cost_nano_usd", scope: ["user", "feature"], timezone: "UTC", window: "1d" });
    expect(describeLimit(limits[0]!)).toContain("per 1d (UTC)");
    expect(() => buildUsagePlanDocument(documentFixture(), { dailyCostUSD: "", dailyInputTokens: 0, dailyLogicalRequests: 0, dailyOutputTokens: 0, dailyTotalTokens: 0, maximumConcurrentRequests: 0, perRequestInputTokens: 0, perRequestOutputTokens: 0, planID: "empty", scope: "user", timezone: "UTC" })).toThrow("at least one enforceable limit");
  });
});

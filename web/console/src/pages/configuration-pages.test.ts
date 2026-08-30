import { describe, expect, it } from "vitest";

import { buildNativeSnippets, buildNativeTemplate } from "./native-template";
import nativeTemplateFixture from "./native-template.fixture.json";

describe("native setup template", () => {
  it("binds all native platforms and trusted Responses accounting", () => {
    const document = JSON.parse(buildNativeTemplate({
      application: "mobile-app",
      environment: "production",
      organization: "example",
      firebaseProject: "example-mobile",
      appIDPrefix: "TEAM1234",
      bundleID: "com.example.mobile",
      bundleVersion: "2.3.4",
      packageName: "com.example.mobile.android",
      cloudProject: 123456789,
      certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      upstreamURL: "https://api.openai.com/v1",
      physicalModel: "operator-reviewed-model",
      maximumFramingTokensPerRequest: 13,
      maximumFramingTokensPerMessage: 7,
      maximumContextTokens: 131072,
      authentication: { type: "bearer", secretName: "primary_api_key" },
      inputNanoUsdPerMillion: 250000,
      outputNanoUsdPerMillion: 2000000,
      requestNanoUsd: 0,
      dailyInputTokenMaximum: 75000,
      dailyOutputTokenMaximum: 25000,
      dailyTotalTokenMaximum: 100000,
      perRequestInputTokenMaximum: 20000
    })) as {
      spec: {
        attestationPolicies: Array<{ platforms: Record<string, unknown> }>;
        componentDefinitions: Array<Record<string, unknown>>;
        inputAccountingProfiles: Array<Record<string, unknown>>;
        pricingCatalogs: Array<Record<string, unknown>>;
        models: Array<Record<string, unknown>>;
        limitPlans: Array<{ limits: Array<Record<string, unknown>> }>;
      };
    };

    expect(document).toEqual(nativeTemplateFixture);
    expect(Object.keys(document.spec.attestationPolicies[0]?.platforms ?? {}).sort()).toEqual([
      "react_native_android", "react_native_ios"
    ]);
    expect(document.spec.attestationPolicies[0]?.platforms).toMatchObject({
      react_native_ios: { minimumTrustLevel: "app_verified", appAttest: { allowedBundleVersions: ["2.3.4"] } },
      react_native_android: { minimumTrustLevel: "device_verified" }
    });
    expect(document.spec.componentDefinitions).toEqual([
      {
        id: "react-native-ios-main", platform: "react_native_ios", kind: "main_app",
        identifiers: { bundleIdentifiers: ["com.example.mobile"] }, familyRole: "root",
        attestation: { strategy: "direct", provider: "app_attest" }, allowedFeatures: ["assistant"]
      },
      {
        id: "react-native-android-main", platform: "react_native_android", kind: "android_app",
        identifiers: { packageNames: ["com.example.mobile.android"] }, familyRole: "root",
        attestation: { strategy: "direct", provider: "play_integrity" }, allowedFeatures: ["assistant"]
      }
    ]);
    expect(document.spec.inputAccountingProfiles).toEqual([{
      id: "assistant_default_responses_accounting",
      protocol: "openai_responses",
      method: "utf8_byte_bpe_declared_framing_v1",
      physicalModel: "operator-reviewed-model",
      maximumFramingTokensPerRequest: 13,
      maximumFramingTokensPerMessage: 7,
      maximumContextTokens: 131072
    }]);
    expect(document.spec.models).toEqual([{
      id: "assistant_default",
      upstream: "primary",
      upstreamModel: "operator-reviewed-model",
      capabilities: ["openai_responses"],
      inputAccountingRef: "assistant_default_responses_accounting",
      pricingRef: "operator_pricing"
    }]);
    expect(document.spec.pricingCatalogs).toEqual([{
      id: "operator_pricing", currency: "USD", entries: [{
        model: "assistant_default", inputNanoUsdPerMillion: 250000,
        outputNanoUsdPerMillion: 2000000, requestNanoUsd: 0
      }]
    }]);
    expect(document.spec.limitPlans[0]?.limits).toEqual(expect.arrayContaining([
      expect.objectContaining({ metric: "input_tokens", algorithm: "calendar", maximum: 75000, hard: true }),
      expect.objectContaining({ metric: "total_tokens", algorithm: "calendar", maximum: 100000, hard: true }),
      expect.objectContaining({ metric: "input_tokens", algorithm: "per_request", perRequestMaximum: 20000, hard: true })
    ]));
  });

  it("allows no-auth only as an explicit template input", () => {
    const input = JSON.parse(buildNativeTemplate({
      application: "mobile-app", environment: "production", organization: "example",
      firebaseProject: "example-mobile", appIDPrefix: "TEAM1234", bundleID: "com.example.mobile",
      bundleVersion: "2.3.4", packageName: "com.example.mobile.android", cloudProject: 123456789,
      certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      upstreamURL: "https://fixture.example.test/v1", physicalModel: "fixture-model",
      maximumFramingTokensPerRequest: 8, maximumFramingTokensPerMessage: 4,
      maximumContextTokens: 4096, authentication: { type: "none" },
      inputNanoUsdPerMillion: 0, outputNanoUsdPerMillion: 0, requestNanoUsd: 0,
      dailyInputTokenMaximum: 1000, dailyOutputTokenMaximum: 1000,
      dailyTotalTokenMaximum: 2000, perRequestInputTokenMaximum: 100
    })) as { spec: { upstreams: Array<{ authentication: unknown }> } };
    expect(input.spec.upstreams[0]?.authentication).toEqual({ type: "none" });
  });

  it("generates exact native roots when Swift and Kotlin are selected", () => {
    const document = JSON.parse(buildNativeTemplate({
      application: "mobile-app", environment: "production", organization: "example",
      firebaseProject: "example-mobile", appIDPrefix: "TEAM1234", bundleID: "com.example.mobile",
      bundleVersion: "2.3.4", packageName: "com.example.mobile.android", clientSurface: "native",
      cloudProject: 123456789, certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      upstreamURL: "https://fixture.example.test/v1", physicalModel: "fixture-model",
      maximumFramingTokensPerRequest: 8, maximumFramingTokensPerMessage: 4,
      maximumContextTokens: 4096, authentication: { type: "none" },
      inputNanoUsdPerMillion: 0, outputNanoUsdPerMillion: 0, requestNanoUsd: 0,
      dailyInputTokenMaximum: 1000, dailyOutputTokenMaximum: 1000,
      dailyTotalTokenMaximum: 2000, perRequestInputTokenMaximum: 100
    })) as { spec: { attestationPolicies: Array<{ platforms: Record<string, unknown> }>; componentDefinitions: Array<{ id: string; platform: string }> } };

    expect(Object.keys(document.spec.attestationPolicies[0]?.platforms ?? {}).sort()).toEqual(["android", "ios"]);
    expect(document.spec.componentDefinitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "ios-main", platform: "ios" }),
      expect.objectContaining({ id: "android-main", platform: "android" })
    ]));
  });

  it("rejects overlapping Apple and Android Component Definition identifiers", () => {
    expect(() => buildNativeTemplate({
      application: "mobile-app", environment: "production", organization: "example",
      firebaseProject: "example-mobile", appIDPrefix: "TEAM1234", bundleID: "com.example.mobile",
      bundleVersion: "2.3.4", packageName: "com.example.mobile", cloudProject: 123456789,
      certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      upstreamURL: "https://fixture.example.test/v1", physicalModel: "fixture-model",
      maximumFramingTokensPerRequest: 8, maximumFramingTokensPerMessage: 4,
      maximumContextTokens: 4096, authentication: { type: "none" },
      inputNanoUsdPerMillion: 0, outputNanoUsdPerMillion: 0, requestNanoUsd: 0,
      dailyInputTokenMaximum: 1000, dailyOutputTokenMaximum: 1000,
      dailyTotalTokenMaximum: 2000, perRequestInputTokenMaximum: 100
    })).toThrow("component_identifier_duplicate");
  });

  it("emits a runnable React Native configuration and matching first request", () => {
    const snippets = buildNativeSnippets({
      applicationID: "app_01J00000000000000000000000",
      cloudProjectNumber: "123456789",
      environmentSlug: "production"
    });
    expect(snippets.reactNative).toContain('identityProvider: "firebase"');
    expect(snippets.reactNative).toContain('playIntegrityCloudProjectNumber: "123456789"');
    expect(snippets.reactNative).toContain("latchway.fetch" + '("/v1/responses"');
    expect(snippets.reactNative).toContain('latchwayFeature: "assistant"');
    expect(Object.values(snippets).every((snippet) =>
      snippet.includes("app_01J00000000000000000000000"))).toBe(true);
  });
});

import { describe, expect, it } from "vitest";

import { buildFirstRunTemplate, type FirstRunTemplateInput, type SetupPlatformScope } from "./configuration-pages";
import { buildNativeSnippets, buildNativeTemplate, type NativeTemplateInput } from "./native-template";
import nativeTemplateFixture from "./native-template.fixture.json";

function nativeTemplateInput(overrides: Partial<NativeTemplateInput> = {}): NativeTemplateInput {
  return {
    application: "mobile-app",
    environment: "production",
    environmentKind: "production",
    organization: "example",
    firebaseProject: "example-mobile",
    appIDPrefix: "TEAM1234",
    bundleID: "com.example.mobile",
    bundleVersion: "234",
    appleDistribution: "app_store",
    packageName: "com.example.mobile.android",
    cloudProject: 123456789,
    certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    upstreamURL: "https://fixture.example.test/v1",
    physicalModel: "fixture-model",
    maximumFramingTokensPerRequest: 8,
    maximumFramingTokensPerMessage: 4,
    maximumContextTokens: 4096,
    authentication: { type: "none" },
    inputNanoUsdPerMillion: 0,
    outputNanoUsdPerMillion: 0,
    requestNanoUsd: 0,
    dailyInputTokenMaximum: 1000,
    dailyOutputTokenMaximum: 1000,
    dailyTotalTokenMaximum: 2000,
    perRequestInputTokenMaximum: 100,
    ...overrides
  };
}

function firstRunTemplateInput(platformScope: SetupPlatformScope): FirstRunTemplateInput {
  const apple = ["ios", "native_both", "react_native_ios", "react_native_both"].includes(platformScope);
  const android = ["android", "native_both", "react_native_android", "react_native_both"].includes(platformScope);
  return {
    application: "mobile-app",
    environment: "production",
    environmentKind: "production",
    organization: "example",
    firebaseProject: "example-mobile",
    platformScope,
    ...(apple ? {
      appIDPrefix: "TEAM1234",
      appleDistribution: "app_store" as const,
      bundleID: "com.example.mobile",
      bundleVersion: "234"
    } : {}),
    ...(android ? {
      androidVersionCode: 42,
      certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      cloudProject: 123456789,
      packageName: "com.example.mobile.android",
      playIntegrityCredential: { type: "metadata" as const }
    } : {}),
    ...(platformScope === "web" ? {
      firebaseAppID: "1:123456789:web:abc123",
      firebaseProjectNumber: "123456789",
      webOrigin: "https://app.example.com"
    } : {}),
    upstreamURL: "https://fixture.example.test/v1",
    physicalModel: "fixture-model",
    maximumFramingTokensPerRequest: 8,
    maximumFramingTokensPerMessage: 4,
    maximumContextTokens: 4096,
    authentication: { type: "none" },
    inputNanoUsdPerMillion: 0,
    outputNanoUsdPerMillion: 0,
    requestNanoUsd: 0,
    dailyInputTokenMaximum: 1000,
    dailyOutputTokenMaximum: 1000,
    dailyTotalTokenMaximum: 2000,
    perRequestInputTokenMaximum: 100
  };
}

describe("platform-scoped first-run template", () => {
  it.each([
    ["ios", ["ios"], ["ios-main"]],
    ["android", ["android"], ["android-main"]],
    ["web", ["web"], ["web-main"]],
    ["react_native_ios", ["react_native_ios"], ["react-native-ios-main"]],
    ["react_native_android", ["react_native_android"], ["react-native-android-main"]],
    ["react_native_both", ["react_native_android", "react_native_ios"], ["react-native-android-main", "react-native-ios-main"]]
  ] as const)("emits only %s evidence and Component Definitions", (scope, expectedPlatforms, expectedComponents) => {
    const text = buildFirstRunTemplate(firstRunTemplateInput(scope));
    const document = JSON.parse(text) as {
      metadata: { description: string };
      spec: {
        attestationPolicies: Array<{ id: string; platforms: Record<string, unknown> }>;
        componentDefinitions: Array<{ id: string; platform: string }>;
        features: Array<{ attestationPolicy: string }>;
      };
    };

    expect(Object.keys(document.spec.attestationPolicies[0]?.platforms ?? {}).sort()).toEqual(expectedPlatforms);
    expect(document.spec.componentDefinitions.map((component) => component.id).sort()).toEqual(expectedComponents);
    expect(document.spec.componentDefinitions.map((component) => component.platform).sort()).toEqual(expectedPlatforms);
    expect(document.metadata.description).toContain("production gateway");
    expect(text).not.toContain("latchway.unused");

    const includesApple = expectedPlatforms.some((platform) => platform.endsWith("ios"));
    const includesAndroid = expectedPlatforms.some((platform) => platform.endsWith("android"));
    expect(text.includes('"appAttest"')).toBe(includesApple);
    expect(text.includes('"playIntegrity"')).toBe(includesAndroid);
    expect(text.includes('"firebaseAppCheck"')).toBe(scope === "web");
    expect(document.spec.features[0]?.attestationPolicy).toBe(scope === "web" ? "web" : "native");
  });

  it("pins the exact Web origin and Firebase App Check application without native-proof claims", () => {
    const document = JSON.parse(buildFirstRunTemplate(firstRunTemplateInput("web"))) as {
      spec: {
        attestationPolicies: Array<{ platforms: { web: Record<string, unknown> } }>;
        componentDefinitions: Array<Record<string, unknown>>;
      };
    };
    expect(document.spec.attestationPolicies[0]?.platforms.web).toEqual({
      allowedOrigins: ["https://app.example.com"],
      firebaseAppCheck: { allowedAppIds: ["1:123456789:web:abc123"], projectNumber: "123456789" },
      minimumTrustLevel: "web_risk_verified",
      mode: "required",
      provider: "firebase_app_check"
    });
    expect(document.spec.componentDefinitions).toEqual([{
      allowedFeatures: ["assistant"],
      attestation: { provider: "firebase_app_check", strategy: "direct" },
      familyRole: "root",
      id: "web-main",
      identifiers: { origins: ["https://app.example.com"] },
      kind: "browser",
      platform: "web"
    }]);
    expect(JSON.stringify(document)).not.toMatch(/appAttest|playIntegrity|device_verified/u);
  });

  it("requires only the evidence selected by the platform scope", () => {
    expect(() => buildFirstRunTemplate(firstRunTemplateInput("ios"))).not.toThrow();
    expect(() => buildFirstRunTemplate(firstRunTemplateInput("android"))).not.toThrow();
    expect(() => buildFirstRunTemplate(firstRunTemplateInput("web"))).not.toThrow();
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("ios"), bundleID: undefined })).toThrow(/Bundle ID/u);
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("android"), cloudProject: undefined })).toThrow(/Cloud project number/u);
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("react_native_android"), cloudProject: 1 })).toThrow(/Cloud project number/u);
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("web"), firebaseAppID: undefined })).toThrow(/Firebase project number/u);
  });

  it("uses the canonical 3–255 character App Attest bundle-ID grammar", () => {
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("ios"), bundleID: "a.b" })).not.toThrow();
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("ios"), bundleID: `a${"b".repeat(254)}` })).not.toThrow();
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("ios"), bundleID: `a${"b".repeat(255)}` })).toThrow(/Bundle ID/u);
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("ios"), bundleID: "-invalid" })).toThrow(/Bundle ID/u);
  });

  it("rejects a non-HTTPS production Web origin while allowing exact development loopback", () => {
    expect(() => buildFirstRunTemplate({ ...firstRunTemplateInput("web"), webOrigin: "http://app.example.com" })).toThrow(/canonical HTTPS/u);
    const development = buildFirstRunTemplate({
      ...firstRunTemplateInput("web"),
      environment: "development",
      environmentKind: "development",
      webOrigin: "http://127.0.0.1:5173"
    });
    expect(development).toContain('"http://127.0.0.1:5173"');
  });
});

describe("native setup template", () => {
  it("binds all native platforms and trusted Responses accounting", () => {
    const document = JSON.parse(buildNativeTemplate({
      application: "mobile-app",
      environment: "production",
      environmentKind: "production",
      organization: "example",
      firebaseProject: "example-mobile",
      appIDPrefix: "TEAM1234",
      bundleID: "com.example.mobile",
      bundleVersion: "234",
      appleDistribution: "app_store",
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
      react_native_ios: { minimumTrustLevel: "app_verified", appAttest: { allowedBundleVersions: ["234"] } },
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
      environmentKind: "production", appleDistribution: "app_store",
      firebaseProject: "example-mobile", appIDPrefix: "TEAM1234", bundleID: "com.example.mobile",
      bundleVersion: "234", packageName: "com.example.mobile.android", cloudProject: 123456789,
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
      environmentKind: "production", appleDistribution: "app_store",
      firebaseProject: "example-mobile", appIDPrefix: "TEAM1234", bundleID: "com.example.mobile",
      bundleVersion: "234", packageName: "com.example.mobile.android", clientSurface: "native",
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
      environmentKind: "production", appleDistribution: "app_store",
      firebaseProject: "example-mobile", appIDPrefix: "TEAM1234", bundleID: "com.example.mobile",
      bundleVersion: "234", packageName: "com.example.mobile", cloudProject: 123456789,
      certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      upstreamURL: "https://fixture.example.test/v1", physicalModel: "fixture-model",
      maximumFramingTokensPerRequest: 8, maximumFramingTokensPerMessage: 4,
      maximumContextTokens: 4096, authentication: { type: "none" },
      inputNanoUsdPerMillion: 0, outputNanoUsdPerMillion: 0, requestNanoUsd: 0,
      dailyInputTokenMaximum: 1000, dailyOutputTokenMaximum: 1000,
      dailyTotalTokenMaximum: 2000, perRequestInputTokenMaximum: 100
    })).toThrow("component_identifier_duplicate");
  });

  it.each([
    ["development", "development", "development", 3],
    ["testflight", "production", "production", 2],
    ["app_store", "production", "production", 4],
    ["ad_hoc_enterprise", "production", "production", 5]
  ] as const)("maps %s signing to exact App Attest policy", (appleDistribution, environmentKind, appAttestEnvironment, validationCategory) => {
    const document = JSON.parse(buildNativeTemplate(nativeTemplateInput({
      appleDistribution,
      environmentKind
    }))) as {
      spec: {
        attestationPolicies: Array<{
          platforms: {
            react_native_ios: {
              appAttest: {
                allowedBundleVersions: string[];
                allowedValidationCategories: number[];
                environment: string;
              };
            };
          };
        }>;
      };
    };
    expect(document.spec.attestationPolicies[0]?.platforms.react_native_ios.appAttest).toMatchObject({
      environment: appAttestEnvironment,
      allowedValidationCategories: [validationCategory],
      allowedBundleVersions: ["234"]
    });
  });

  it("rejects development App Attest in a production environment", () => {
    expect(() => buildNativeTemplate(nativeTemplateInput({
      appleDistribution: "development",
      environmentKind: "production"
    }))).toThrow("app_attest_environment_mismatch");
  });

  it("rejects an unknown Apple distribution instead of choosing a category", () => {
    expect(() => buildNativeTemplate(nativeTemplateInput({
      appleDistribution: "operating_system" as NativeTemplateInput["appleDistribution"]
    }))).toThrow("app_attest_distribution_invalid");
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

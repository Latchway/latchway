import { describe, expect, it } from "vitest";

import type { JSONRecord } from "./configuration-slice";
import {
  buildClientAccessDocument,
  buildConnectionDocument,
  buildUsagePlanDocument,
  clientPlatformReadiness,
  describeLimit,
  specRecords,
  usdToNanoUSD
} from "./task-configuration-builders";

const validCertificateDigest = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
const metadataPlayCredential = { type: "metadata" } as const;

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
      baseURL: "https://api.example.test/v1",
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
    })).toThrow("canonical HTTPS");
    expect(() => buildConnectionDocument(original, {
      authentication: "none", baseURL: "https://api.anthropic.com", connectionID: "mismatched", inputPriceUSDPerMillion: "0", maximumContextTokens: 1, maximumFramingTokensPerMessage: 0, maximumFramingTokensPerRequest: 0, modelID: "mismatched_model", outputPriceUSDPerMillion: "0", physicalModel: "fixture", protocol: "openai_responses", providerType: "anthropic", requestPriceUSD: "0"
    })).toThrow("matches the connection type");
  });

  it.each([
    "https://operator:secret@api.example.test/v1",
    "https://api.example.test/v1?token=secret",
    "https://api.example.test/v1#fragment",
    "https://api.example.test/v1%2Fmodels",
    "https://api.example.test/v1//models",
    "https://api.example.test/v1/../models",
    "https://API.example.test/v1",
    "https://api.example.test:443/v1",
    "https://api.example.test/v1/"
  ])("rejects a non-canonical or credential-bearing guided upstream URL: %s", (baseURL) => {
    expect(() => buildConnectionDocument(documentFixture(), {
      authentication: "none",
      baseURL,
      connectionID: "primary",
      inputPriceUSDPerMillion: "0",
      maximumContextTokens: 1,
      maximumFramingTokensPerMessage: 0,
      maximumFramingTokensPerRequest: 0,
      modelID: "assistant_default",
      outputPriceUSDPerMillion: "0",
      physicalModel: "fixture",
      protocol: "openai_responses",
      providerType: "openai_compatible",
      requestPriceUSD: "0"
    })).toThrow("Upstream URL");
  });

  it.each([
    {
      expectedProvider: "app_attest",
      input: { appIDPrefix: "TEAM123", appleBundleID: "com.example.habitify", appleBundleVersion: "42", appleValidationCategory: 4 as const, platform: "ios" as const }
    },
    {
      expectedProvider: "play_integrity",
      input: { androidCertificateDigest: validCertificateDigest, androidCloudProjectNumber: 123456, androidPackageName: "com.example.habitify", androidVersionCode: 42, platform: "android" as const, playIntegrityCredential: metadataPlayCredential }
    },
    {
      expectedProvider: "app_attest",
      input: { appIDPrefix: "TEAM123", appleBundleID: "com.example.habitify", appleBundleVersion: "42", appleValidationCategory: 4 as const, platform: "react_native_ios" as const }
    },
    {
      expectedProvider: "play_integrity",
      input: { androidCertificateDigest: validCertificateDigest, androidCloudProjectNumber: 123456, androidPackageName: "com.example.habitify", androidVersionCode: 42, platform: "react_native_android" as const, playIntegrityCredential: metadataPlayCredential }
    },
    {
      expectedProvider: "firebase_app_check",
      input: { firebaseAppID: "1:123456:web:abcdef", firebaseProjectNumber: "123456", platform: "web" as const, webOrigin: "https://app.example.test" }
    }
  ])("builds a production $input.platform root component and required verification policy", ({ expectedProvider, input }) => {
    const result = buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing",
      componentID: `${input.platform}_main`,
      environmentKind: "production",
      featureID: "assistant",
      ...input
    });
    expect(specRecords(result, "componentDefinitions")[0]).toMatchObject({ allowedFeatures: ["assistant"], attestation: { provider: expectedProvider, strategy: "direct" }, familyRole: "root", platform: input.platform });
    expect(specRecords(result, "attestationPolicies").find((policy) => policy.id === "existing")).toMatchObject({
      id: "existing",
      platforms: {
        [input.platform]: {
          minimumTrustLevel: expectedProvider === "play_integrity" ? "device_verified" :
            expectedProvider === "firebase_app_check" ? "web_risk_verified" : "app_verified",
          mode: "required",
          provider: expectedProvider
        }
      }
    });
    expect(specRecords(result, "features").find((feature) => feature.id === "assistant")?.attestationPolicy).toBe("existing");
    expect(specRecords(result, "attestationPolicies").find((policy) => policy.id === "existing")?.platforms).toMatchObject({ node: { mode: "disabled", provider: "debug" } });
  });

  it("builds Cloudflare Turnstile web trust with an exact origin, hostname, action, and logical secret reference", () => {
    const result = buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing",
      componentID: "web_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "web",
      turnstileExpectedAction: "latchway_session",
      turnstileSecretName: "turnstile_private",
      webOrigin: "https://app.example.test",
      webVerificationProvider: "turnstile"
    });
    const policy = specRecords(result, "attestationPolicies").find((candidate) => candidate.id === "existing");
    expect(policy).toMatchObject({
      platforms: {
        web: {
          allowedOrigins: ["https://app.example.test"],
          minimumTrustLevel: "web_risk_verified",
          mode: "required",
          provider: "turnstile",
          secretRef: "secret/turnstile_private",
          turnstile: { allowedHostnames: ["app.example.test"], expectedAction: "latchway_session" }
        }
      }
    });
    expect(specRecords(result, "componentDefinitions")[0]).toMatchObject({ attestation: { provider: "turnstile", strategy: "direct" }, identifiers: { origins: ["https://app.example.test"] }, platform: "web" });
    expect(JSON.stringify(result)).not.toContain("siteverify-secret-value");
    expect(() => buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing", componentID: "web_main", environmentKind: "production", featureID: "assistant", platform: "web", turnstileExpectedAction: "spaces are invalid", turnstileSecretName: "turnstile_private", webOrigin: "https://app.example.test", webVerificationProvider: "turnstile"
    })).toThrow("Turnstile action");
    expect(() => buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing", componentID: "web_main", environmentKind: "production", featureID: "assistant", platform: "web", turnstileExpectedAction: "latchway_session", turnstileSecretName: "turnstile_private", webOrigin: "https://operator:secret@app.example.test", webVerificationProvider: "turnstile"
    })).toThrow("Browser origin");
    expect(() => buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing", componentID: "web_main", environmentKind: "development", featureID: "assistant", platform: "web", turnstileExpectedAction: "latchway_session", turnstileSecretName: "turnstile_private", webOrigin: "ftp://localhost", webVerificationProvider: "turnstile"
    })).toThrow("Browser origin");
  });

  it.each([
    { environmentKind: "production" as const, origin: "https://App.Example.Test" },
    { environmentKind: "production" as const, origin: "https://app.example.test/" },
    { environmentKind: "staging" as const, origin: "http://localhost:3000" },
    { environmentKind: "development" as const, origin: "http://localhost:0" },
    { environmentKind: "production" as const, origin: "https://app..example.test" }
  ])("rejects a non-exact browser origin $origin in $environmentKind", ({ environmentKind, origin }) => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing",
      componentID: "web_main",
      environmentKind,
      featureID: "assistant",
      firebaseAppID: "1:123456:web:abcdef",
      firebaseProjectNumber: "123456",
      platform: "web",
      webOrigin: origin
    })).toThrow(/browser origin/i);
  });

  it("accepts exact loopback HTTP only for a development browser surface", () => {
    const result = buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing",
      componentID: "web_main",
      environmentKind: "development",
      featureID: "assistant",
      firebaseAppID: "1:123456:web:abcdef",
      firebaseProjectNumber: "123456",
      platform: "web",
      webOrigin: "http://127.0.0.1:3000"
    });
    expect(specRecords(result, "componentDefinitions")[0]?.identifiers).toEqual({ origins: ["http://127.0.0.1:3000"] });
  });

  it("adds Firebase user authentication with the application surface when explicitly requested", () => {
    const result = buildClientAccessDocument(documentFixture(), {
      appIDPrefix: "TEAM123",
      appleBundleID: "com.example.habitify",
      appleBundleVersion: "42",
      attestationPolicyID: "existing",
      componentID: "ios_main",
      environmentKind: "production",
      featureID: "assistant",
      firebaseProjectID: "habitify-prod",
      identityProviderID: "firebase",
      platform: "ios"
    });
    expect(specRecords(result, "identityProviders")).toEqual([{ id: "firebase", projectId: "habitify-prod", type: "firebase" }]);
  });

  it.each([
    { category: 2 as const, environmentKind: "staging" as const, expected: "production" },
    { category: 3 as const, environmentKind: "development" as const, expected: "development" },
    { category: 4 as const, environmentKind: "development" as const, expected: "production" },
    { category: 5 as const, environmentKind: "staging" as const, expected: "production" }
  ])("derives App Attest environment from Apple validation category $category", ({ category, environmentKind, expected }) => {
    const result = buildClientAccessDocument(documentFixture(), {
      appIDPrefix: "TEAM123",
      appleBundleID: "com.example.habitify",
      appleBundleVersion: "42",
      appleValidationCategory: category,
      attestationPolicyID: "existing",
      componentID: "ios_main",
      environmentKind,
      featureID: "assistant",
      platform: "ios"
    });
    const policy = specRecords(result, "attestationPolicies").find((candidate) => candidate.id === "existing");
    expect(policy).toMatchObject({ platforms: { ios: { appAttest: { environment: expected } } } });
  });

  it("rejects development-signed App Attest in a production environment", () => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      appIDPrefix: "TEAM123",
      appleBundleID: "com.example.habitify",
      appleBundleVersion: "42",
      appleValidationCategory: 3,
      attestationPolicyID: "existing",
      componentID: "ios_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "ios"
    })).toThrow("Production environments require");
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

  it("refuses to silently rebind an existing feature to a different verification policy", () => {
    const original = documentFixture();
    expect(() => buildClientAccessDocument(original, {
      appIDPrefix: "TEAM123",
      appleBundleID: "com.example.habitify",
      appleBundleVersion: "42",
      attestationPolicyID: "replacement",
      componentID: "ios_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "ios"
    })).toThrow("selected feature's existing verification policy");
    expect(specRecords(original, "features")[0]?.attestationPolicy).toBe("existing");
    expect(specRecords(original, "attestationPolicies").map((policy) => policy.id)).toEqual(["existing"]);
  });

  it.each([
    { appleBundleID: "com..example.habitify", appleBundleVersion: "42", expected: "Bundle ID" },
    { appleBundleID: "com.-example.habitify", appleBundleVersion: "42", expected: "Bundle ID" },
    { appleBundleID: "com.example.habitify", appleBundleVersion: "42..1", expected: "CFBundleVersion" }
  ])("rejects non-canonical Apple proof identity values", ({ appleBundleID, appleBundleVersion, expected }) => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      appIDPrefix: "TEAM123",
      appleBundleID,
      appleBundleVersion,
      attestationPolicyID: "existing",
      componentID: "ios_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "ios"
    })).toThrow(expected);
  });

  it("persists exact Play version bounds and the selected server credential source", () => {
    const result = buildClientAccessDocument(documentFixture(), {
      androidCertificateDigest: validCertificateDigest,
      androidCloudProjectNumber: 123456,
      androidPackageName: "com.example.habitify",
      androidVersionCode: 42,
      attestationPolicyID: "existing",
      componentID: "android_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "android",
      playIntegrityCredential: { secretName: "play_integrity_service_account", type: "service_account" }
    });
    const policy = specRecords(result, "attestationPolicies").find((candidate) => candidate.id === "existing");
    expect(policy).toMatchObject({
      platforms: {
        android: {
          playIntegrity: {
            allowTestingResponses: false,
            certificateSha256Digests: [validCertificateDigest],
            cloudProjectNumber: 123456,
            credentialSource: "service_account",
            maximumVersionCode: 42,
            minimumVersionCode: 42,
            packageName: "com.example.habitify",
            requireLicensed: true
          },
          secretRef: "secret/play_integrity_service_account"
        }
      }
    });
  });

  it.each([
    { androidCertificateDigest: "A".repeat(43), androidPackageName: "com.example.habitify", expected: "nonzero canonical" },
    { androidCertificateDigest: validCertificateDigest, androidPackageName: "com..example", expected: "Android package name" }
  ])("rejects invalid Android proof identity values", ({ androidCertificateDigest, androidPackageName, expected }) => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      androidCertificateDigest,
      androidCloudProjectNumber: 123456,
      androidPackageName,
      androidVersionCode: 42,
      attestationPolicyID: "existing",
      componentID: "android_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "android",
      playIntegrityCredential: metadataPlayCredential
    })).toThrow(expected);
  });

  it("requires an explicit Play Integrity credential source", () => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      androidCertificateDigest: validCertificateDigest,
      androidCloudProjectNumber: 123456,
      androidPackageName: "com.example.habitify",
      androidVersionCode: 42,
      attestationPolicyID: "existing",
      componentID: "android_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "android"
    })).toThrow("credential source");
  });

  it.each(["0", "012345", "18446744073709551616"])("rejects non-canonical Firebase project number %s", (firebaseProjectNumber) => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      attestationPolicyID: "existing",
      componentID: "web_main",
      environmentKind: "production",
      featureID: "assistant",
      firebaseAppID: "1:123456:web:abcdef",
      firebaseProjectNumber,
      platform: "web",
      webOrigin: "https://app.example.test"
    })).toThrow("Firebase project number");
  });

  it("requires an exact positive Android version code in the guided flow", () => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      androidCertificateDigest: validCertificateDigest,
      androidCloudProjectNumber: 123456,
      androidPackageName: "com.example.habitify",
      androidVersionCode: 0,
      attestationPolicyID: "existing",
      componentID: "android_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "android",
      playIntegrityCredential: metadataPlayCredential
    })).toThrow("Version code must be a positive safe integer");
  });

  it("requires a canonical Play cloud project number compatible with the native SDKs", () => {
    expect(() => buildClientAccessDocument(documentFixture(), {
      androidCertificateDigest: validCertificateDigest,
      androidCloudProjectNumber: 1,
      androidPackageName: "com.example.habitify",
      androidVersionCode: 42,
      attestationPolicyID: "existing",
      componentID: "android_main",
      environmentKind: "production",
      featureID: "assistant",
      platform: "react_native_android",
      playIntegrityCredential: metadataPlayCredential
    })).toThrow("Cloud project number must contain 6 through 19");
  });

  it("reports readiness separately for every exact native, React Native, and web platform binding", () => {
    const document = documentFixture();
    const spec = document.spec as JSONRecord;
    spec.identityProviders = [{ id: "firebase", projectId: "habitify-prod", type: "firebase" }];
    spec.attestationPolicies = [{
      id: "clients",
      platforms: {
        android: { mode: "required", provider: "play_integrity", playIntegrity: {} },
        ios: { appAttest: {}, mode: "required", provider: "app_attest" },
        react_native_android: { mode: "required", provider: "play_integrity", playIntegrity: {} },
        react_native_ios: { appAttest: {}, mode: "required", provider: "app_attest" },
        web: { firebaseAppCheck: {}, mode: "required", provider: "firebase_app_check" }
      }
    }];
    spec.features = [{ ...(spec.features as JSONRecord[])[0], attestationPolicy: "clients" }];
    spec.componentDefinitions = [
      { allowedFeatures: ["assistant"], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: "ios_main", kind: "main_app", platform: "ios" },
      { allowedFeatures: ["assistant"], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: "android_main", kind: "android_app", platform: "android" },
      { allowedFeatures: ["assistant"], attestation: { provider: "firebase_app_check", strategy: "direct" }, familyRole: "root", id: "web_main", kind: "browser", platform: "web" },
      { allowedFeatures: ["assistant"], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: "react_native_ios_main", kind: "main_app", platform: "react_native_ios" },
      { allowedFeatures: ["assistant"], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: "react_native_android_main", kind: "android_app", platform: "react_native_android" }
    ];

    const cards = clientPlatformReadiness(document);
    expect(cards.map(({ key }) => key)).toEqual(["ios", "android", "web", "react_native_ios", "react_native_android"]);
    expect(cards.every(({ ready }) => ready)).toBe(true);
    expect(cards.find(({ key }) => key === "react_native_ios")?.configured).toContain("react_native_ios_main");
    expect(cards.find(({ key }) => key === "react_native_android")?.test).toContain("react_native_android");

    (spec.componentDefinitions as JSONRecord[])[4]!.attestation = { provider: "debug", strategy: "direct" };
    const unavailable = clientPlatformReadiness(document).find(({ key }) => key === "react_native_android");
    expect(unavailable?.ready).toBe(false);
    expect(unavailable?.missing).toContain("A feature granted by the root component and bound to the same verification policy");
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

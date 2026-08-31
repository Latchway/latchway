export interface NativeTemplateInput {
  application: string;
  environment: string;
  environmentKind: "development" | "staging" | "production";
  organization: string;
  firebaseProject: string;
  appIDPrefix: string;
  bundleID: string;
  bundleVersion: string;
  appleDistribution: "development" | "testflight" | "app_store" | "ad_hoc_enterprise";
  packageName: string;
  clientSurface?: "native" | "react_native";
  cloudProject: number;
  certificateDigest: string;
  upstreamURL: string;
  physicalModel: string;
  maximumFramingTokensPerRequest: number;
  maximumFramingTokensPerMessage: number;
  maximumContextTokens: number;
  authentication: { type: "bearer"; secretName: string } | { type: "none" };
  inputNanoUsdPerMillion: number;
  outputNanoUsdPerMillion: number;
  requestNanoUsd: number;
  dailyInputTokenMaximum: number;
  dailyOutputTokenMaximum: number;
  dailyTotalTokenMaximum: number;
  perRequestInputTokenMaximum: number;
}

export function buildNativeTemplate(input: NativeTemplateInput): string {
  if (input.bundleID === input.packageName) {
    throw new Error("component_identifier_duplicate");
  }
  const appAttestPolicy = {
    development: { environment: "development", validationCategory: 3 },
    testflight: { environment: "production", validationCategory: 2 },
    app_store: { environment: "production", validationCategory: 4 },
    ad_hoc_enterprise: { environment: "production", validationCategory: 5 }
  } as const;
  const appAttest = appAttestPolicy[input.appleDistribution];
  if (!appAttest || (input.environmentKind !== "development" && input.environmentKind !== "staging" && input.environmentKind !== "production")) {
    throw new Error("app_attest_distribution_invalid");
  }
  if (input.environmentKind === "production" && appAttest.environment !== "production") {
    throw new Error("app_attest_environment_mismatch");
  }
  const clientSurface = input.clientSurface ?? "react_native";
  const iosPlatform = clientSurface === "react_native" ? "react_native_ios" : "ios";
  const androidPlatform = clientSurface === "react_native" ? "react_native_android" : "android";
  const iosDefinitionID = clientSurface === "react_native" ? "react-native-ios-main" : "ios-main";
  const androidDefinitionID = clientSurface === "react_native" ? "react-native-android-main" : "android-main";
  const appAttestSelection = {
    provider: "app_attest", mode: "required", minimumTrustLevel: "app_verified",
    appAttest: {
      appIdPrefix: input.appIDPrefix,
      bundleId: input.bundleID,
      environment: appAttest.environment,
      allowedValidationCategories: [appAttest.validationCategory],
      allowedBundleVersions: [input.bundleVersion]
    }
  };
  const playIntegritySelection = {
    provider: "play_integrity", mode: "required", minimumTrustLevel: "device_verified",
    playIntegrity: { packageName: input.packageName, cloudProjectNumber: input.cloudProject, certificateSha256Digests: [input.certificateDigest], minimumDeviceIntegrity: "device", requireLicensed: true, allowTestingResponses: false, minimumVersionCode: 1, maximumVersionCode: 0, credentialSource: "metadata" }
  };
  return JSON.stringify({
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: {
      organization: input.organization,
      application: input.application,
      environment: input.environment,
      description: clientSurface === "react_native"
        ? `React Native iOS and Android ${input.environmentKind} gateway`
        : `Native iOS and Android ${input.environmentKind} gateway`
    },
    spec: {
      identityProviders: [{ id: "firebase", type: "firebase", projectId: input.firebaseProject }],
      attestationPolicies: [{
        id: "native",
        platforms: {
          [iosPlatform]: appAttestSelection,
          [androidPlatform]: playIntegritySelection
        }
      }],
      componentDefinitions: [{
        id: iosDefinitionID,
        platform: iosPlatform,
        kind: "main_app",
        identifiers: { bundleIdentifiers: [input.bundleID] },
        familyRole: "root",
        attestation: { strategy: "direct", provider: "app_attest" },
        allowedFeatures: ["assistant"]
      }, {
        id: androidDefinitionID,
        platform: androidPlatform,
        kind: "android_app",
        identifiers: { packageNames: [input.packageName] },
        familyRole: "root",
        attestation: { strategy: "direct", provider: "play_integrity" },
        allowedFeatures: ["assistant"]
      }],
      upstreams: [{
        id: "primary", type: "openai_compatible", baseUrl: input.upstreamURL,
        authentication: input.authentication.type === "bearer"
          ? { type: "bearer", secretRef: `secret/${input.authentication.secretName}` }
          : { type: "none" }
      }],
      inputAccountingProfiles: [{
        id: "assistant_default_responses_accounting",
        protocol: "openai_responses",
        method: "utf8_byte_bpe_declared_framing_v1",
        physicalModel: input.physicalModel,
        maximumFramingTokensPerRequest: input.maximumFramingTokensPerRequest,
        maximumFramingTokensPerMessage: input.maximumFramingTokensPerMessage,
        maximumContextTokens: input.maximumContextTokens
      }],
      pricingCatalogs: [{
        id: "operator_pricing", currency: "USD", entries: [{
          model: "assistant_default",
          inputNanoUsdPerMillion: input.inputNanoUsdPerMillion,
          outputNanoUsdPerMillion: input.outputNanoUsdPerMillion,
          requestNanoUsd: input.requestNanoUsd
        }]
      }],
      models: [{
        id: "assistant_default", upstream: "primary", upstreamModel: input.physicalModel,
        capabilities: ["openai_responses"], inputAccountingRef: "assistant_default_responses_accounting",
        pricingRef: "operator_pricing"
      }],
      limitPlans: [{ id: "standard", limits: [
        { metric: "logical_requests", algorithm: "calendar", scope: ["user", "feature"], window: "1d", maximum: 100, hard: true },
        { metric: "input_tokens", algorithm: "calendar", scope: ["user", "feature"], window: "1d", maximum: input.dailyInputTokenMaximum, hard: true },
        { metric: "output_tokens", algorithm: "calendar", scope: ["user", "feature"], window: "1d", maximum: input.dailyOutputTokenMaximum, hard: true },
        { metric: "total_tokens", algorithm: "calendar", scope: ["user", "feature"], window: "1d", maximum: input.dailyTotalTokenMaximum, hard: true },
        { metric: "input_tokens", algorithm: "per_request", scope: ["user", "feature"], perRequestMaximum: input.perRequestInputTokenMaximum, hard: true }
      ] }],
      features: [{
        id: "assistant", protocol: "openai_responses", attestationPolicy: "native",
        access: { expression: "principal.authenticated" }, limitPlan: { expression: "'standard'" },
        output: { defaultMaximumTokens: 800, absoluteMaximumTokens: 2000 },
        routes: [{ id: "primary", when: "true", model: "assistant_default", priority: 10 }]
      }]
    }
  }, null, 2);
}

export function buildNativeSnippets(input: {
  applicationID: string;
  cloudProjectNumber: string;
  environmentSlug: string;
}): { android: string; ios: string; reactNative: string } {
  const fetchMethod = "latchway.fetch";
  return {
    reactNative: `const latchway = createLatchwayClient({
  baseURL: gatewayURL,
  applicationID: "${input.applicationID}",
  environment: "${input.environmentSlug}",
  identityProvider: "firebase",
  getIdentityToken,
  android: { playIntegrityCloudProjectNumber: "${input.cloudProjectNumber}" },
});

const response = await ${fetchMethod}("/v1/responses", {
  method: "POST",
  latchwayFeature: "assistant",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ model: "client", input: "Hello" }),
});`,
    ios: `LatchwayConfiguration(
  baseURL: gatewayURL,
  applicationID: "${input.applicationID}",
  environment: "${input.environmentSlug}",
  identityProvider: "firebase"
)`,
    android: `LatchwayConfiguration(
  baseUrl = gatewayUrl,
  applicationId = "${input.applicationID}",
  environment = "${input.environmentSlug}",
  defaultFeature = "assistant",
)`
  };
}

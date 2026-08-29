export interface NativeTemplateInput {
  application: string;
  environment: string;
  organization: string;
  firebaseProject: string;
  appIDPrefix: string;
  bundleID: string;
  bundleVersion: string;
  packageName: string;
  cloudProject: number;
  certificateDigest: string;
  upstreamURL: string;
  physicalModel: string;
  maximumFramingTokensPerRequest: number;
  maximumFramingTokensPerMessage: number;
  maximumContextTokens: number;
  secretName?: string;
}

export function buildNativeTemplate(input: NativeTemplateInput): string {
  const appAttestSelection = {
    provider: "app_attest", mode: "required", minimumTrustLevel: "app_verified",
    appAttest: { appIdPrefix: input.appIDPrefix, bundleId: input.bundleID, environment: "production", allowedValidationCategories: [1], allowedBundleVersions: [input.bundleVersion] }
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
      description: "React Native iOS and Android production gateway"
    },
    spec: {
      identityProviders: [{ id: "firebase", type: "firebase", projectId: input.firebaseProject }],
      attestationPolicies: [{
        id: "native",
        platforms: {
          ios: appAttestSelection,
          android: playIntegritySelection,
          react_native_ios: appAttestSelection,
          react_native_android: playIntegritySelection
        }
      }],
      upstreams: [{
        id: "primary", type: "openai_compatible", baseUrl: input.upstreamURL,
        authentication: input.secretName ? { type: "bearer", secretRef: `secret/${input.secretName}` } : { type: "none" }
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
      models: [{
        id: "assistant_default", upstream: "primary", upstreamModel: input.physicalModel,
        capabilities: ["openai_responses"], inputAccountingRef: "assistant_default_responses_accounting"
      }],
      limitPlans: [{ id: "standard", limits: [
        { metric: "logical_requests", algorithm: "calendar", scope: ["user", "feature"], window: "1d", maximum: 100, hard: true },
        { metric: "output_tokens", algorithm: "calendar", scope: ["user", "feature"], window: "1d", maximum: 100000, hard: true },
        { metric: "input_tokens", algorithm: "per_request", scope: ["user", "feature"], perRequestMaximum: 20000, hard: true }
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

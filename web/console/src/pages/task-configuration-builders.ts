import {
  cloneConfigurationDocument,
  configurationAreas,
  upsertAreaResource,
  type JSONRecord
} from "./configuration-slice";
import {
  requireAndroidPackageName,
  requireAppleBundleID,
  requireAppleBundleVersion,
  requireCanonicalBrowserOrigin,
  requireCloudProjectNumber,
  requireFirebaseProjectNumber,
  requireGuidedUpstreamURL,
  requirePlayCertificateDigest,
  requireTurnstileHostname
} from "./client-proof-validation";

const identifierPattern = /^[a-z][a-z0-9_-]{0,62}$/;
const protocols = ["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages"] as const;

export type TaskProtocol = typeof protocols[number];

export function isJSONRecord(value: unknown): value is JSONRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function specRecords(document: JSONRecord, key: string): JSONRecord[] {
  if (!isJSONRecord(document.spec)) return [];
  const values = document.spec[key];
  return Array.isArray(values) ? values.filter(isJSONRecord) : [];
}

function requireIdentifier(value: string, label: string): string {
  if (!identifierPattern.test(value)) throw new Error(`${label} must be a canonical identifier.`);
  return value;
}

function requireSafePositive(value: number, label: string, allowZero = false): number {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) throw new Error(`${label} must be a ${allowZero ? "non-negative" : "positive"} safe integer.`);
  return value;
}

export function usdToNanoUSD(value: string): number {
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?$/.exec(value.trim());
  if (!match) throw new Error("USD values accept at most nine decimal places and no exponent notation.");
  const whole = BigInt(match[1]!);
  const fraction = BigInt((match[2] ?? "").padEnd(9, "0"));
  const nano = whole * 1_000_000_000n + fraction;
  if (nano > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("USD value exceeds the console's exact integer range.");
  return Number(nano);
}

export interface ConnectionTaskInput {
  authentication: "bearer" | "none";
  baseURL: string;
  connectionID: string;
  inputPriceUSDPerMillion: string;
  maximumContextTokens: number;
  maximumFramingTokensPerMessage: number;
  maximumFramingTokensPerRequest: number;
  modelID: string;
  outputPriceUSDPerMillion: string;
  physicalModel: string;
  protocol: TaskProtocol;
  providerType: "anthropic" | "openai_compatible";
  requestPriceUSD: string;
  secretName?: string;
}

export function buildConnectionDocument(document: JSONRecord, input: ConnectionTaskInput): JSONRecord {
  const connectionID = requireIdentifier(input.connectionID, "Connection ID");
  const modelID = requireIdentifier(input.modelID, "Model ID");
  if (!protocols.includes(input.protocol)) throw new Error("Choose a supported protocol.");
  const requiredProviderType = input.protocol === "anthropic_messages" ? "anthropic" : "openai_compatible";
  if (input.providerType !== requiredProviderType) throw new Error("Choose a protocol that matches the connection type.");
  if (!input.physicalModel.trim() || input.physicalModel.length > 256) throw new Error("Physical model must contain 1 through 256 characters.");
  const accountingID = requireIdentifier(`${modelID}_input`, "Derived input-accounting ID");
  const pricingID = requireIdentifier(`${modelID}_pricing`, "Derived pricing ID");
  const location = { baseUrl: requireGuidedUpstreamURL(input.baseURL) };
  const authentication = input.authentication === "bearer"
    ? { type: "bearer", secretRef: `secret/${requireIdentifier(input.secretName ?? "", "Secret name")}` }
    : { type: "none" };
  const upstream: JSONRecord = { authentication, id: connectionID, type: input.providerType, ...location };
  const accounting: JSONRecord = {
    id: accountingID,
    maximumContextTokens: requireSafePositive(input.maximumContextTokens, "Maximum context tokens"),
    maximumFramingTokensPerMessage: requireSafePositive(input.maximumFramingTokensPerMessage, "Per-message framing tokens", true),
    maximumFramingTokensPerRequest: requireSafePositive(input.maximumFramingTokensPerRequest, "Per-request framing tokens", true),
    method: "utf8_byte_bpe_declared_framing_v1",
    physicalModel: input.physicalModel,
    protocol: input.protocol
  };
  const model: JSONRecord = {
    capabilities: [input.protocol],
    id: modelID,
    inputAccountingRef: accountingID,
    pricingRef: pricingID,
    upstream: connectionID,
    upstreamModel: input.physicalModel
  };
  const pricing: JSONRecord = {
    currency: "USD",
    entries: [{
      inputNanoUsdPerMillion: usdToNanoUSD(input.inputPriceUSDPerMillion),
      model: modelID,
      outputNanoUsdPerMillion: usdToNanoUSD(input.outputPriceUSDPerMillion),
      requestNanoUsd: usdToNanoUSD(input.requestPriceUSD)
    }],
    id: pricingID
  };
  let next = cloneConfigurationDocument(document);
  next = upsertAreaResource(next, configurationAreas.upstreams.collections[0]!, undefined, upstream).document;
  next = upsertAreaResource(next, configurationAreas.modelsPricing.collections[1]!, undefined, accounting).document;
  next = upsertAreaResource(next, configurationAreas.modelsPricing.collections[0]!, undefined, model).document;
  next = upsertAreaResource(next, configurationAreas.modelsPricing.collections[2]!, undefined, pricing).document;
  return next;
}

export interface ClientAccessTaskInput {
  androidCertificateDigest?: string;
  androidCloudProjectNumber?: number;
  androidPackageName?: string;
  androidVersionCode?: number;
  appIDPrefix?: string;
  appleBundleID?: string;
  appleBundleVersion?: string;
  appleValidationCategory?: 2 | 3 | 4 | 5;
  attestationPolicyID: string;
  componentID: string;
  environmentKind: "development" | "production" | "staging";
  featureID: string;
  firebaseAppID?: string;
  firebaseProjectID?: string;
  firebaseProjectNumber?: string;
  identityProviderID?: string;
  platform: ClientPlatform;
  playIntegrityCredential?: { type: "metadata" } | { type: "service_account"; secretName: string };
  turnstileExpectedAction?: string;
  turnstileSecretName?: string;
  webVerificationProvider?: WebVerificationProvider;
  webOrigin?: string;
}

export type ClientPlatform = "android" | "ios" | "react_native_android" | "react_native_ios" | "web";
export type WebVerificationProvider = "firebase_app_check" | "turnstile";

const firebaseAppIDPattern = /^[!-~]{5,256}$/;
const turnstileActionPattern = /^[A-Za-z0-9_-]{1,32}$/;

export function buildClientAccessDocument(document: JSONRecord, input: ClientAccessTaskInput): JSONRecord {
  const policyID = requireIdentifier(input.attestationPolicyID, "Verification policy ID");
  const componentID = requireIdentifier(input.componentID, "Component ID");
  const featureID = requireIdentifier(input.featureID, "Feature ID");
  const selectedFeature = specRecords(document, "features").find((feature) => feature.id === featureID);
  if (!selectedFeature) throw new Error("Choose a feature from the active configuration.");
  const selectedFeaturePolicy = selectedFeature.attestationPolicy;
  if (selectedFeaturePolicy !== undefined) {
    if (typeof selectedFeaturePolicy !== "string" || !identifierPattern.test(selectedFeaturePolicy)) {
      throw new Error("The selected feature has an invalid verification policy binding.");
    }
    if (selectedFeaturePolicy !== policyID) {
      throw new Error("Add this client surface to the selected feature's existing verification policy; changing the feature's policy requires an explicit configuration edit.");
    }
  }
  let selection: JSONRecord;
  let component: JSONRecord;
  if (input.platform === "ios" || input.platform === "react_native_ios") {
    if (!input.appIDPrefix?.match(/^[A-Z0-9]{1,64}$/)) throw new Error("Enter the exact App ID prefix, bundle ID, and CFBundleVersion.");
    const bundleID = requireAppleBundleID(input.appleBundleID);
    const bundleVersion = requireAppleBundleVersion(input.appleBundleVersion);
    const category = input.appleValidationCategory ?? (input.environmentKind === "development" ? 3 : 4);
    const appAttestEnvironment = category === 3 ? "development" : "production";
    if (input.environmentKind === "production" && appAttestEnvironment !== "production") {
      throw new Error("Production environments require TestFlight, App Store, or ad hoc / enterprise distribution.");
    }
    selection = { appAttest: { allowedBundleVersions: [bundleVersion], allowedValidationCategories: [category], appIdPrefix: input.appIDPrefix, bundleId: bundleID, environment: appAttestEnvironment }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" };
    component = { allowedFeatures: [featureID], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: componentID, identifiers: { bundleIdentifiers: [bundleID] }, kind: "main_app", platform: input.platform };
  } else if (input.platform === "android" || input.platform === "react_native_android") {
    const packageName = requireAndroidPackageName(input.androidPackageName);
    const certificateDigest = requirePlayCertificateDigest(input.androidCertificateDigest);
    const project = requireCloudProjectNumber(input.androidCloudProjectNumber ?? 0);
    const version = requireSafePositive(input.androidVersionCode ?? 0, "Version code");
    const credential = input.playIntegrityCredential;
    if (!credential || (credential.type !== "metadata" && credential.type !== "service_account")) {
      throw new Error("Choose the Play Integrity server credential source.");
    }
    selection = { minimumTrustLevel: "device_verified", mode: "required", ...(credential.type === "service_account" ? { secretRef: `secret/${requireIdentifier(credential.secretName, "Play Integrity secret name")}` } : {}), playIntegrity: { allowTestingResponses: input.environmentKind !== "production", certificateSha256Digests: [certificateDigest], cloudProjectNumber: project, credentialSource: credential.type, maximumVersionCode: version, minimumDeviceIntegrity: "device", minimumVersionCode: version, packageName, requireLicensed: input.environmentKind === "production" }, provider: "play_integrity" };
    component = { allowedFeatures: [featureID], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: componentID, identifiers: { packageNames: [packageName] }, kind: "android_app", platform: input.platform };
  } else {
    const origin = requireCanonicalBrowserOrigin(input.webOrigin, input.environmentKind);
    const exactOrigin = origin.origin;
    const provider = input.webVerificationProvider ?? "firebase_app_check";
    if (provider !== "firebase_app_check" && provider !== "turnstile") throw new Error("Choose Firebase App Check or Cloudflare Turnstile for web verification.");
    if (provider === "firebase_app_check") {
      const projectNumber = requireFirebaseProjectNumber(input.firebaseProjectNumber);
      if (!input.firebaseAppID?.match(firebaseAppIDPattern)) throw new Error("Enter the Firebase project number and exact web app ID.");
      selection = { allowedOrigins: [exactOrigin], firebaseAppCheck: { allowedAppIds: [input.firebaseAppID], projectNumber }, minimumTrustLevel: "web_risk_verified", mode: "required", provider };
    } else {
      if (!turnstileActionPattern.test(input.turnstileExpectedAction ?? "")) throw new Error("Turnstile action must contain 1 through 32 letters, numbers, underscores, or hyphens.");
      const hostname = requireTurnstileHostname(origin.hostname);
      selection = { allowedOrigins: [exactOrigin], minimumTrustLevel: "web_risk_verified", mode: "required", provider, secretRef: `secret/${requireIdentifier(input.turnstileSecretName ?? "", "Turnstile secret name")}`, turnstile: { allowedHostnames: [hostname], expectedAction: input.turnstileExpectedAction } };
    }
    component = { allowedFeatures: [featureID], attestation: { provider, strategy: "direct" }, familyRole: "root", id: componentID, identifiers: { origins: [exactOrigin] }, kind: "browser", platform: "web" };
  }
  const existingPolicy = specRecords(document, "attestationPolicies").find((candidate) => candidate.id === policyID);
  let existingPlatforms: JSONRecord | undefined;
  if (existingPolicy) {
    if (!isJSONRecord(existingPolicy.platforms)) throw new Error("The selected verification policy has an invalid platform map.");
    existingPlatforms = existingPolicy.platforms;
  }
  const policy: JSONRecord = existingPolicy
    ? { ...existingPolicy, platforms: { ...existingPlatforms, [input.platform]: selection } }
    : { id: policyID, maxAge: "10m", platforms: { [input.platform]: selection } };
  let next = cloneConfigurationDocument(document);
  if (input.identityProviderID || input.firebaseProjectID) {
    const identity: JSONRecord = { id: requireIdentifier(input.identityProviderID ?? "", "Identity provider ID"), projectId: input.firebaseProjectID, type: "firebase" };
    if (!input.firebaseProjectID?.match(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/)) throw new Error("Firebase project ID is invalid.");
    next = upsertAreaResource(next, configurationAreas.identity.collections[0]!, undefined, identity).document;
  }
  next = upsertAreaResource(next, configurationAreas.attestation.collections[0]!, existingPolicy ? policyID : undefined, policy).document;
  next = upsertAreaResource(next, configurationAreas.components.collections[0]!, undefined, component).document;
  const boundFeature = specRecords(next, "features").find((feature) => feature.id === featureID);
  if (!boundFeature) throw new Error("The selected feature disappeared while building the client-access change.");
  boundFeature.attestationPolicy = policyID;
  return next;
}

export interface ClientPlatformReadiness {
  configured: string;
  documentationURL: string;
  key: ClientPlatform;
  label: string;
  missing: string[];
  productionRequirement: string;
  ready: boolean;
  test: string;
}

const clientPlatformFacts: Record<ClientPlatform, Omit<ClientPlatformReadiness, "configured" | "missing" | "ready"> & { providers: string[] }> = {
  ios: {
    documentationURL: "https://docs.latchway.dev/clients/ios/quickstart",
    key: "ios",
    label: "iOS",
    productionRequirement: "App Attest from the exact distribution-signed bundle and a supported physical device.",
    providers: ["app_attest"],
    test: "Send a signed physical-device request, then inspect its App Attest trust and feature decision."
  },
  android: {
    documentationURL: "https://docs.latchway.dev/clients/android/quickstart",
    key: "android",
    label: "Android",
    productionRequirement: "Play Integrity from the exact package, signing certificate, version, cloud project, and Play track.",
    providers: ["play_integrity"],
    test: "Send a Play-installed device request, then inspect its Play Integrity trust and feature decision."
  },
  web: {
    documentationURL: "https://docs.latchway.dev/clients/web/browser-trust",
    key: "web",
    label: "Web",
    productionRequirement: "An exact HTTPS origin plus fresh Firebase App Check or challenge-bound Turnstile evidence.",
    providers: ["firebase_app_check", "turnstile"],
    test: "Send a browser request from an allowed origin, then inspect its browser-risk trust and feature decision."
  },
  react_native_ios: {
    documentationURL: "https://docs.latchway.dev/clients/react-native/ios-native-setup",
    key: "react_native_ios",
    label: "React Native iOS",
    productionRequirement: "The React Native iOS runtime key with App Attest, exact signed entitlements, and a supported physical device.",
    providers: ["app_attest"],
    test: "Send through the native-backed React Native client on iOS and verify the recorded react_native_ios platform."
  },
  react_native_android: {
    documentationURL: "https://docs.latchway.dev/clients/react-native/android-native-setup",
    key: "react_native_android",
    label: "React Native Android",
    productionRequirement: "The React Native Android runtime key with Play Integrity and the exact Play-distributed application.",
    providers: ["play_integrity"],
    test: "Send through the native-backed React Native client on Android and verify the recorded react_native_android platform."
  }
};

function stringValues(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function providerLabel(value: string): string {
  const labels: Record<string, string> = {
    app_attest: "Apple App Attest",
    debug: "Debug evidence",
    firebase_app_check: "Firebase App Check",
    play_integrity: "Google Play Integrity",
    turnstile: "Cloudflare Turnstile"
  };
  return labels[value] ?? value.replaceAll("_", " ");
}

export function clientPlatformReadiness(document: JSONRecord): ClientPlatformReadiness[] {
  const identities = specRecords(document, "identityProviders").map((identity) => String(identity.id ?? "")).filter((id) => identifierPattern.test(id));
  const policies = specRecords(document, "attestationPolicies");
  const policyByID = new Map(policies.map((policy) => [String(policy.id ?? ""), policy]));
  const features = specRecords(document, "features");
  const components = specRecords(document, "componentDefinitions");

  return (Object.keys(clientPlatformFacts) as ClientPlatform[]).map((key) => {
    const { providers: expectedProviders, ...facts } = clientPlatformFacts[key];
    const roots = components.filter((component) => component.platform === key && component.familyRole === "root");
    const platformSelections = policies.flatMap((policy) => {
      const platforms = isJSONRecord(policy.platforms) ? policy.platforms : undefined;
      const selection = platforms && isJSONRecord(platforms[key]) ? platforms[key] : undefined;
      return selection ? [{ policyID: String(policy.id ?? ""), selection }] : [];
    });
    const compatibleSelections = platformSelections.filter(({ selection }) => expectedProviders.includes(String(selection.provider ?? "")) && selection.mode === "required");
    const boundFeatures = new Set<string>();
    for (const component of roots) {
      const attestation = isJSONRecord(component.attestation) ? component.attestation : undefined;
      const provider = String(attestation?.provider ?? "");
      for (const featureID of stringValues(component.allowedFeatures)) {
        const feature = features.find((candidate) => candidate.id === featureID);
        const policy = policyByID.get(String(feature?.attestationPolicy ?? ""));
        const platforms = policy && isJSONRecord(policy.platforms) ? policy.platforms : undefined;
        const selection = platforms && isJSONRecord(platforms[key]) ? platforms[key] : undefined;
        if (attestation?.strategy === "direct" && selection?.mode === "required" && selection.provider === provider && expectedProviders.includes(provider)) boundFeatures.add(featureID);
      }
    }
    const missing: string[] = [];
    if (!identities.length) missing.push("A user-authentication provider");
    if (!roots.length) missing.push(`A root ${facts.label} Component Definition`);
    if (!compatibleSelections.length) missing.push(`A required ${expectedProviders.map(providerLabel).join(" or ")} policy selection at ${key}`);
    if (roots.length && compatibleSelections.length && !boundFeatures.size) missing.push("A feature granted by the root component and bound to the same verification policy");
    const providers = [...new Set(platformSelections.map(({ selection }) => String(selection.provider ?? "")).filter(Boolean))];
    const configured = [
      identities.length ? `Authentication: ${identities.join(", ")}` : "Authentication: none",
      providers.length ? `Verification: ${providers.map(providerLabel).join(", ")}` : "Verification: none",
      roots.length ? `Root: ${roots.map((root) => String(root.id ?? "unnamed")).join(", ")}` : "Root: none",
      boundFeatures.size ? `Features: ${[...boundFeatures].join(", ")}` : "Features: none bound end-to-end"
    ].join(" · ");
    return { ...facts, configured, missing, ready: missing.length === 0 };
  });
}

export interface UsagePlanTaskInput {
  dailyCostUSD: string;
  dailyInputTokens: number;
  dailyLogicalRequests: number;
  dailyOutputTokens: number;
  dailyTotalTokens: number;
  maximumConcurrentRequests: number;
  perRequestInputTokens: number;
  perRequestOutputTokens: number;
  planID: string;
  scope: "environment_feature" | "user" | "user_feature";
  timezone: string;
}

function positiveOrOmit(value: number, label: string): number | undefined {
  if (value === 0) return undefined;
  return requireSafePositive(value, label);
}

export function buildUsagePlanDocument(document: JSONRecord, input: UsagePlanTaskInput): JSONRecord {
  const planID = requireIdentifier(input.planID, "Plan ID");
  const scope = input.scope === "user" ? ["user"] : input.scope === "environment_feature" ? ["environment", "feature"] : ["user", "feature"];
  if (!/^[A-Za-z][A-Za-z0-9._+-]*(\/[A-Za-z0-9][A-Za-z0-9._+-]*)*$/.test(input.timezone) || input.timezone === "Local") throw new Error("Timezone must be a canonical IANA name such as UTC or America/Los_Angeles.");
  const limits: JSONRecord[] = [];
  const calendar = (metric: string, maximum: number | undefined) => { if (maximum) limits.push({ algorithm: "calendar", hard: true, maximum, metric, scope, timezone: input.timezone, window: "1d" }); };
  calendar("logical_requests", positiveOrOmit(input.dailyLogicalRequests, "Daily requests"));
  calendar("input_tokens", positiveOrOmit(input.dailyInputTokens, "Daily input tokens"));
  calendar("output_tokens", positiveOrOmit(input.dailyOutputTokens, "Daily output tokens"));
  calendar("total_tokens", positiveOrOmit(input.dailyTotalTokens, "Daily total tokens"));
  const cost = input.dailyCostUSD.trim() ? usdToNanoUSD(input.dailyCostUSD) : 0;
  calendar("cost_nano_usd", cost || undefined);
  const perRequestInput = positiveOrOmit(input.perRequestInputTokens, "Per-request input tokens");
  if (perRequestInput) limits.push({ algorithm: "per_request", hard: true, metric: "input_tokens", perRequestMaximum: perRequestInput, scope });
  const perRequestOutput = positiveOrOmit(input.perRequestOutputTokens, "Per-request output tokens");
  if (perRequestOutput) limits.push({ algorithm: "per_request", hard: true, metric: "output_tokens", perRequestMaximum: perRequestOutput, scope });
  const concurrency = positiveOrOmit(input.maximumConcurrentRequests, "Concurrent requests");
  if (concurrency) limits.push({ algorithm: "concurrency", hard: true, maximum: concurrency, metric: "concurrent_requests", scope });
  if (!limits.length) throw new Error("Choose at least one enforceable limit.");
  return upsertAreaResource(cloneConfigurationDocument(document), configurationAreas.limits.collections[0]!, undefined, { id: planID, limits }).document;
}

export function describeLimit(limit: JSONRecord): string {
  const metric = String(limit.metric ?? "usage").replaceAll("_", " ");
  const scope = Array.isArray(limit.scope) ? limit.scope.join(" + ").replaceAll("_", " ") : "configured scope";
  if (limit.algorithm === "calendar") return `${Number(limit.maximum).toLocaleString()} ${metric} per ${String(limit.window ?? "window")} (${String(limit.timezone ?? "UTC")}), grouped by ${scope}`;
  if (limit.algorithm === "per_request") return `${Number(limit.perRequestMaximum).toLocaleString()} ${metric} per request, grouped by ${scope}`;
  if (limit.algorithm === "concurrency") return `${Number(limit.maximum).toLocaleString()} simultaneous ${metric}, grouped by ${scope}`;
  if (limit.algorithm === "token_bucket") return `${Number(limit.capacity).toLocaleString()} ${metric} burst with ${String(limit.refillPerSecond)} per second refill, grouped by ${scope}`;
  return `${metric} with an advanced policy`;
}

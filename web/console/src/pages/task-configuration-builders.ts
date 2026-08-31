import {
  cloneConfigurationDocument,
  configurationAreas,
  upsertAreaResource,
  type JSONRecord
} from "./configuration-slice";

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

function taskBaseURL(value: string): { baseUrl: string } {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Connection URL must be an absolute URL.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("Connection URL cannot contain credentials, a query, or a fragment.");
  if (parsed.protocol !== "https:") throw new Error("HTTPS is required in the guided connection flow.");
  return { baseUrl: parsed.href.replace(/\/$/, "") };
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
  const location = taskBaseURL(input.baseURL);
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
  platform: "android" | "ios" | "web";
  webOrigin?: string;
}

export function buildClientAccessDocument(document: JSONRecord, input: ClientAccessTaskInput): JSONRecord {
  const policyID = requireIdentifier(input.attestationPolicyID, "Verification policy ID");
  const componentID = requireIdentifier(input.componentID, "Component ID");
  const featureID = requireIdentifier(input.featureID, "Feature ID");
  const selectedFeature = specRecords(document, "features").find((feature) => feature.id === featureID);
  if (!selectedFeature) throw new Error("Choose a feature from the active configuration.");
  let selection: JSONRecord;
  let component: JSONRecord;
  if (input.platform === "ios") {
    if (!input.appIDPrefix?.match(/^[A-Z0-9]{1,64}$/) || !input.appleBundleID || !input.appleBundleVersion) throw new Error("Enter the exact App ID prefix, bundle ID, and CFBundleVersion.");
    const development = input.environmentKind !== "production";
    const category = input.appleValidationCategory ?? (development ? 3 : 4);
    selection = { appAttest: { allowedBundleVersions: [input.appleBundleVersion], allowedValidationCategories: [category], appIdPrefix: input.appIDPrefix, bundleId: input.appleBundleID, environment: development ? "development" : "production" }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" };
    component = { allowedFeatures: [featureID], attestation: { provider: "app_attest", strategy: "direct" }, familyRole: "root", id: componentID, identifiers: { bundleIdentifiers: [input.appleBundleID] }, kind: "main_app", platform: "ios" };
  } else if (input.platform === "android") {
    if (!input.androidPackageName || !input.androidCertificateDigest?.match(/^[A-Za-z0-9_-]{43}=?$/)) throw new Error("Enter the exact Android package name and signing-certificate digest.");
    const project = requireSafePositive(input.androidCloudProjectNumber ?? 0, "Cloud project number");
    const version = requireSafePositive(input.androidVersionCode ?? 0, "Version code", true);
    selection = { minimumTrustLevel: "app_verified", mode: "required", playIntegrity: { allowTestingResponses: input.environmentKind !== "production", certificateSha256Digests: [input.androidCertificateDigest], cloudProjectNumber: project, credentialSource: "metadata", maximumVersionCode: version, minimumDeviceIntegrity: "device", minimumVersionCode: version, packageName: input.androidPackageName, requireLicensed: input.environmentKind === "production" }, provider: "play_integrity" };
    component = { allowedFeatures: [featureID], attestation: { provider: "play_integrity", strategy: "direct" }, familyRole: "root", id: componentID, identifiers: { packageNames: [input.androidPackageName] }, kind: "android_app", platform: "android" };
  } else {
    let origin: URL;
    try { origin = new URL(input.webOrigin ?? ""); } catch { throw new Error("Enter an exact browser origin."); }
    if (origin.pathname !== "/" || origin.search || origin.hash || (origin.protocol !== "https:" && !(input.environmentKind !== "production" && new Set(["localhost", "127.0.0.1", "[::1]"]).has(origin.hostname)))) throw new Error("Browser origin must be HTTPS, or loopback HTTP outside Production.");
    if (!input.firebaseProjectNumber?.match(/^[1-9][0-9]{0,19}$/) || !input.firebaseAppID) throw new Error("Enter the Firebase project number and exact web app ID.");
    const exactOrigin = origin.origin;
    selection = { allowedOrigins: [exactOrigin], firebaseAppCheck: { allowedAppIds: [input.firebaseAppID], projectNumber: input.firebaseProjectNumber }, minimumTrustLevel: "web_risk_verified", mode: "required", provider: "firebase_app_check" };
    component = { allowedFeatures: [featureID], attestation: { provider: "firebase_app_check", strategy: "direct" }, familyRole: "root", id: componentID, identifiers: { origins: [exactOrigin] }, kind: "browser", platform: "web" };
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

// Feature resources and their client setup, computed from the configuration document only.
import type { JSONRecord } from "../configuration-slice";

export const identifierPattern = /^[a-z][a-z0-9_-]{0,62}$/;
export const protocols = ["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages"] as const;
export const fallbackConditions = ["connect_error", "timeout_before_headers", "first_byte_timeout", "status_429", "status_500", "status_502", "status_503", "status_504"];


export function object(value: unknown): value is JSONRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function specCollection(document: JSONRecord, key: string): JSONRecord[] {
  if (!object(document.spec)) return [];
  const value = document.spec[key];
  return Array.isArray(value) ? value.filter(object) : [];
}

export function identifierValues(document: JSONRecord, key: string): string[] {
  return specCollection(document, key).map((value) => String(value.id ?? "")).filter((value) => identifierPattern.test(value));
}

export function accessSummary(feature: JSONRecord): string {
  if (!object(feature.access)) return "Custom access";
  const expression = String(feature.access.expression ?? "");
  if (expression === "principal.authenticated") return "All authenticated users";
  if (expression === "principal.authenticated && principal.claims.plan == 'premium'") return "Premium users";
  if (expression === "principal.authenticated && principal.claims.internal == true") return "Internal users";
  return "Custom access rule";
}

export function selectedPlan(feature: JSONRecord): string {
  if (!object(feature.limitPlan)) return "Custom plan rule";
  const expression = String(feature.limitPlan.expression ?? "");
  const literal = /^'([a-z][a-z0-9_-]{0,62})'$/.exec(expression);
  return literal?.[1] ?? "Custom plan rule";
}

export function orderedRoutes(feature: JSONRecord): JSONRecord[] {
  return Array.isArray(feature.routes)
    ? feature.routes.filter(object).sort((left, right) => Number(left.priority ?? 0) - Number(right.priority ?? 0))
    : [];
}

type ClientSetupSurface = "android" | "ios" | "react_native" | "web";

export interface FeatureClientSetupSnippet {
  available: boolean;
  code: string;
  documentationURL: string;
  label: string;
  prerequisites: string[];
  status: string;
  surface: ClientSetupSurface;
}

interface FeatureClientSetupInput {
  applicationID?: string;
  document: JSONRecord;
  environmentSlug?: string;
  featureID?: string;
  gatewayURL?: string;
}

const publicApplicationIDPattern = /^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

function safeGatewayOrigin(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const parsed = new URL(value);
    const loopback = new Set(["localhost", "127.0.0.1", "[::1]"]).has(parsed.hostname);
    if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/" || (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback))) return undefined;
    return parsed.origin;
  } catch {
    return undefined;
  }
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function featurePlatformSelection(document: JSONRecord, feature: JSONRecord | undefined, platform: string): JSONRecord | undefined {
  const policyID = String(feature?.attestationPolicy ?? "");
  const policy = specCollection(document, "attestationPolicies").find((candidate) => candidate.id === policyID);
  const platforms = object(policy?.platforms) ? policy.platforms : undefined;
  return platforms && object(platforms[platform]) ? platforms[platform] : undefined;
}

function featurePlatformReady(document: JSONRecord, feature: JSONRecord | undefined, platform: string, providers: string[]): boolean {
  const featureID = String(feature?.id ?? "");
  const selection = featurePlatformSelection(document, feature, platform);
  if (!selection || selection.mode !== "required" || !providers.includes(String(selection.provider ?? ""))) return false;
  return specCollection(document, "componentDefinitions").some((component) => {
    const attestation = object(component.attestation) ? component.attestation : undefined;
    return component.platform === platform && component.familyRole === "root" && attestation?.strategy === "direct" && attestation.provider === selection.provider && strings(component.allowedFeatures).includes(featureID);
  });
}

interface ClientRequestShape {
  body?: string;
  jsonBody?: string;
  method: string;
  path: string;
  unavailablePrerequisite?: string;
}

const opaqueMethods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

function safeStaticOpaquePath(value: unknown): string | undefined {
  if (typeof value !== "string" || !/^\/[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*$/.test(value)) return undefined;
  return value.split("/").slice(1).every((segment) => segment !== "." && segment !== "..") ? value : undefined;
}

function requestShape(feature: JSONRecord | undefined, featureID: string): ClientRequestShape {
  if (feature?.protocol === "openai_chat") return { body: '{ model: "client", messages: [{ role: "user", content: "Hello" }] }', jsonBody: '{"model":"client","messages":[{"role":"user","content":"Hello"}]}', method: "POST", path: "/v1/chat/completions" };
  if (feature?.protocol === "openai_embeddings") return { body: '{ model: "client", input: "Hello" }', jsonBody: '{"model":"client","input":"Hello"}', method: "POST", path: "/v1/embeddings" };
  if (feature?.protocol === "anthropic_messages") return { body: '{ model: "client", max_tokens: 256, messages: [{ role: "user", content: "Hello" }] }', jsonBody: '{"model":"client","max_tokens":256,"messages":[{"role":"user","content":"Hello"}]}', method: "POST", path: "/v1/messages" };
  if (feature?.protocol === "openai_responses") return { body: '{ model: "client", input: "Hello" }', jsonBody: '{"model":"client","input":"Hello"}', method: "POST", path: "/v1/responses" };
  if (feature?.protocol === "opaque_http") {
    const policy = object(feature.opaqueHttp) ? feature.opaqueHttp : undefined;
    const method = strings(policy?.allowedMethods).find((candidate) => opaqueMethods.has(candidate));
    const relativePath = strings(policy?.pathTemplates).map(safeStaticOpaquePath).find(Boolean);
    const missing = [
      ...(!method ? ["an allowed opaque HTTP method"] : []),
      ...(!relativePath ? ["a concrete capture-free allowed opaque proxy path"] : [])
    ];
    const resolvedMethod = method ?? "YOUR_ALLOWED_METHOD";
    return {
      ...(resolvedMethod === "GET" || resolvedMethod === "DELETE" ? {} : { body: "{ /* provider-defined request body */ }", jsonBody: "{}" }),
      method: resolvedMethod,
      path: `/proxy/${featureID}${relativePath ?? "/YOUR_ALLOWED_RELATIVE_PATH"}`,
      ...(missing.length ? { unavailablePrerequisite: missing.join(" and ") } : {})
    };
  }
  return {
    body: '{ model: "client", input: "Hello" }',
    jsonBody: '{"model":"client","input":"Hello"}',
    method: "POST",
    path: "/v1/responses",
    unavailablePrerequisite: "a supported feature protocol"
  };
}

export function buildFeatureClientSetupSnippets(input: FeatureClientSetupInput): FeatureClientSetupSnippet[] {
  const applicationID = input.applicationID?.match(publicApplicationIDPattern) ? input.applicationID : "YOUR_LATCHWAY_APPLICATION_ID";
  const environment = input.environmentSlug?.match(identifierPattern) ? input.environmentSlug : "YOUR_ENVIRONMENT_SLUG";
  const gateway = safeGatewayOrigin(input.gatewayURL) ?? "https://YOUR_LATCHWAY_GATEWAY";
  const feature = specCollection(input.document, "features").find((candidate) => candidate.id === input.featureID);
  const featureID = feature && typeof feature.id === "string" && identifierPattern.test(feature.id) ? feature.id : "YOUR_FEATURE_ID";
  const identity = specCollection(input.document, "identityProviders").map((provider) => String(provider.id ?? "")).find((id) => identifierPattern.test(id));
  const identityProvider = identity ?? "YOUR_IDENTITY_PROVIDER";
  const request = requestShape(feature, featureID);
  const commonMissing = [
    ...(applicationID.startsWith("YOUR_") ? ["application resource ID"] : []),
    ...(environment.startsWith("YOUR_") ? ["environment slug"] : []),
    ...(gateway.includes("YOUR_LATCHWAY_GATEWAY") ? ["canonical HTTPS gateway origin"] : []),
    ...(featureID.startsWith("YOUR_") ? ["active feature"] : []),
    ...(identityProvider.startsWith("YOUR_") ? ["user-authentication provider"] : []),
    ...(request.unavailablePrerequisite ? [request.unavailablePrerequisite] : [])
  ];
  const quoted = (value: string) => JSON.stringify(value);
  const clientFetchMethod = ["latchway", "fetch"].join(".");
  const requestBody = request.body
    ? `\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify(${request.body}),`
    : "";
  const swiftRequestBody = request.jsonBody
    ? `\nrequest.setValue("application/json", forHTTPHeaderField: "Content-Type")\nrequest.httpBody = Data(${quoted(request.jsonBody)}.utf8)`
    : "";
  const androidRequestBody = request.jsonBody
    ? `${quoted(request.jsonBody)}.toRequestBody("application/json".toMediaType())`
    : "null";
  const baseStatus = (serverReady: boolean, platform: string): { available: boolean; status: string } => {
    const missing = [...commonMissing, ...(serverReady ? [] : [`${platform} policy, root component, and feature binding`])];
    return missing.length
      ? { available: false, status: `Unavailable until configured: ${missing.join(", ")}.` }
      : { available: true, status: "Server configuration ready; complete the app-owned prerequisites and verify a real request." };
  };

  const iosReady = featurePlatformReady(input.document, feature, "ios", ["app_attest"]);
  const androidReady = featurePlatformReady(input.document, feature, "android", ["play_integrity"]);
  const reactNativeIOSReady = featurePlatformReady(input.document, feature, "react_native_ios", ["app_attest"]);
  const reactNativeAndroidReady = featurePlatformReady(input.document, feature, "react_native_android", ["play_integrity"]);
  const webSelection = featurePlatformSelection(input.document, feature, "web");
  const webProvider = webSelection?.provider === "turnstile" ? "turnstile" : webSelection?.provider === "firebase_app_check" ? "firebase_app_check" : undefined;
  const webReady = Boolean(webProvider) && featurePlatformReady(input.document, feature, "web", [webProvider!]);
  const androidSelection = featurePlatformSelection(input.document, feature, "android");
  const androidPlay = object(androidSelection?.playIntegrity) ? androidSelection.playIntegrity : undefined;
  const androidProject = Number.isSafeInteger(androidPlay?.cloudProjectNumber) && Number(androidPlay?.cloudProjectNumber) > 0 ? String(androidPlay?.cloudProjectNumber) : "YOUR_GOOGLE_CLOUD_PROJECT_NUMBER";
  const reactNativeAndroidSelection = featurePlatformSelection(input.document, feature, "react_native_android");
  const reactNativePlay = object(reactNativeAndroidSelection?.playIntegrity) ? reactNativeAndroidSelection.playIntegrity : undefined;
  const reactNativeProject = Number.isSafeInteger(reactNativePlay?.cloudProjectNumber) && Number(reactNativePlay?.cloudProjectNumber) > 0 ? String(reactNativePlay?.cloudProjectNumber) : "YOUR_GOOGLE_CLOUD_PROJECT_NUMBER";
  const turnstile = object(webSelection?.turnstile) ? webSelection.turnstile : undefined;
  const turnstileAction = typeof turnstile?.expectedAction === "string" && /^[A-Za-z0-9_-]{1,32}$/.test(turnstile.expectedAction) ? turnstile.expectedAction : "latchway_session";

  const iosStatus = baseStatus(iosReady, "iOS App Attest");
  const androidStatus = baseStatus(androidReady && !androidProject.startsWith("YOUR_"), "Android Play Integrity");
  const webStatus = baseStatus(webReady, "Web App Check or Turnstile");
  const reactNativeAndroidConfigured = reactNativeAndroidReady && !reactNativeProject.startsWith("YOUR_");
  const reactNativeMissing = [
    ...commonMissing,
    ...(!reactNativeIOSReady && !reactNativeAndroidConfigured ? ["React Native iOS or fully configured React Native Android policy, root component, and feature binding"] : [])
  ];
  const reactNativeAvailable = reactNativeMissing.length === 0;
  const reactNativeStatus = reactNativeMissing.length
    ? `Unavailable until configured: ${reactNativeMissing.join(", ")}.`
    : reactNativeIOSReady && reactNativeAndroidConfigured
      ? "Server configuration ready for React Native iOS and React Native Android; verify both native runtimes."
      : `Server configuration ready for ${reactNativeIOSReady ? "React Native iOS" : "React Native Android"} only; the other native runtime remains unavailable.`;

  const webAttestation = webProvider === "turnstile"
    ? `import { createTurnstileProvider } from "@latchway/client/turnstile";\n\nconst browserTrust = createTurnstileProvider({\n  action: ${quoted(turnstileAction)},\n  getToken: ({ challenge }) => runTurnstileForChallenge({\n    action: ${quoted(turnstileAction)},\n    cData: challenge.attestation.client_data_hash,\n  }),\n});`
    : webProvider === "firebase_app_check"
      ? `import { createFirebaseAppCheckProvider } from "@latchway/client/firebase";\n\nconst browserTrust = createFirebaseAppCheckProvider(getAppCheckToken);`
      : "// Configure Firebase App Check or Cloudflare Turnstile before use.\nconst browserTrust = unavailableBrowserTrustProvider;";
  const reactNativeSecurity = [
    ...(reactNativeIOSReady ? ["  apple: {", "    // Read this public group from the app's signed entitlements.", '    rootKeychainAccessGroup: "YOUR_FULLY_RESOLVED_PRIVATE_APP_ID_GROUP",', "  },"] : []),
    ...(reactNativeAndroidConfigured ? ["  android: {", `    playIntegrityCloudProjectNumber: ${quoted(reactNativeProject)},`, "  },"] : [])
  ].join("\n");

  return [
    {
      ...iosStatus,
      code: `import Foundation\nimport Latchway\nimport LatchwayAppAttest\n\nlet rootKeychainAccessGroup = "YOUR_FULLY_RESOLVED_PRIVATE_APP_ID_GROUP"\nlet appAttest = LatchwayAppAttestProvider(\n  applicationID: ${quoted(applicationID)},\n  environment: ${quoted(environment)},\n  rootKeychainAccessGroup: rootKeychainAccessGroup\n)\nlet configuration = LatchwayConfiguration(\n  baseURL: URL(string: ${quoted(gateway)})!,\n  applicationID: ${quoted(applicationID)},\n  environment: ${quoted(environment)},\n  rootKeychainAccessGroup: rootKeychainAccessGroup,\n  identityProvider: ${quoted(identityProvider)},\n  attestationProvider: appAttest\n)\nlet latchway = LatchwayClient(\n  configuration: configuration,\n  identityTokenProvider: identityTokenProvider\n)\nlet feature = ${quoted(featureID)}\nlet endpoint = URL(string: ${quoted(`${gateway}${request.path}`)})!\nvar request = URLRequest(url: endpoint)\nrequest.httpMethod = ${quoted(request.method)}${swiftRequestBody}\nlet response = try await latchway.send(request, feature: feature)\nprecondition((200 ..< 300).contains(response.statusCode))`,
      documentationURL: "https://docs.latchway.dev/clients/ios/quickstart",
      label: "iOS",
      prerequisites: ["Existing identity-token provider", "App Attest entitlement and distribution signing", "Fully resolved private App-ID Keychain group", "Supported physical device"],
      surface: "ios"
    },
    {
      ...androidStatus,
      code: `import dev.latchway.okhttp.LatchwayClient\nimport dev.latchway.okhttp.LatchwayConfiguration\nimport dev.latchway.okhttp.latchwayFeature\nimport dev.latchway.playintegrity.PlayIntegrityAttestationProvider\nimport okhttp3.HttpUrl.Companion.toHttpUrl\nimport okhttp3.MediaType.Companion.toMediaType\nimport okhttp3.OkHttpClient\nimport okhttp3.Request\nimport okhttp3.RequestBody.Companion.toRequestBody\n\nval gateway = ${quoted(`${gateway}/`)}.toHttpUrl()\nval latchway = LatchwayClient(\n  configuration = LatchwayConfiguration(\n    baseUrl = gateway,\n    applicationId = ${quoted(applicationID)},\n    environment = ${quoted(environment)},\n    identityProvider = ${quoted(identityProvider)},\n    defaultFeature = ${quoted(featureID)},\n  ),\n  identityTokenProvider = identityTokenProvider,\n  attestationProvider = PlayIntegrityAttestationProvider(\n    context = applicationContext,\n    cloudProjectNumber = ${androidProject}L,\n  ),\n  context = applicationContext,\n)\nval endpoint = gateway.resolve(${quoted(request.path.slice(1))})!!\nval request = Request.Builder()\n  .url(endpoint)\n  .method(${quoted(request.method)}, ${androidRequestBody})\n  .latchwayFeature(${quoted(featureID)})\n  .build()\nlatchway.buildOkHttpClient(OkHttpClient.Builder()).newCall(request).execute().use { response ->\n  check(response.isSuccessful)\n}`,
      documentationURL: "https://docs.latchway.dev/clients/android/quickstart",
      label: "Android",
      prerequisites: ["Existing identity-token provider", "Exact package and signing certificate", "Google Play cloud project and configured Play track", "Physical Play-installed device"],
      surface: "android"
    },
    {
      ...webStatus,
      code: `import { createLatchwayClient } from "@latchway/client";\n${webAttestation}\n\nconst latchway = createLatchwayClient({\n  baseURL: ${quoted(gateway)},\n  applicationID: ${quoted(applicationID)},\n  environment: ${quoted(environment)},\n  identityProvider: ${quoted(identityProvider)},\n  identityTokenProvider: { getIdentityToken },\n  attestationProviders: [browserTrust],\n});\n\nconst response = await ${clientFetchMethod}(${quoted(request.path)}, {\n  method: ${quoted(request.method)},\n  latchwayFeature: ${quoted(featureID)},${requestBody}\n});`,
      documentationURL: webProvider === "turnstile" ? "https://docs.latchway.dev/clients/web/turnstile" : "https://docs.latchway.dev/clients/web/firebase-app-check",
      label: "Web",
      prerequisites: webProvider === "turnstile" ? ["Existing identity-token callback", "Public Turnstile site key in the browser app", "One challenge-bound widget execution per session challenge", "Exact allowed HTTPS origin"] : ["Existing identity-token callback", "Initialized Firebase App Check instance", "Fresh App Check token callback", "Exact allowed HTTPS origin"],
      surface: "web"
    },
    {
      available: reactNativeAvailable,
      code: `import { createLatchwayClient } from "@latchway/react-native";\n\nconst latchway = createLatchwayClient({\n  baseURL: ${quoted(gateway)},\n  applicationID: ${quoted(applicationID)},\n  environment: ${quoted(environment)},\n  identityProvider: ${quoted(identityProvider)},\n  getIdentityToken,\n${reactNativeSecurity || "  // Configure react_native_ios and/or react_native_android before use."}\n});\n\nconst response = await ${clientFetchMethod}(${quoted(request.path)}, {\n  method: ${quoted(request.method)},\n  latchwayFeature: ${quoted(featureID)},${requestBody}\n});`,
      documentationURL: "https://docs.latchway.dev/clients/react-native/quickstart",
      label: "React Native",
      prerequisites: ["Existing native-consumed identity-token callback", "New Architecture-enabled host app", "App Attest entitlement and private Keychain group on iOS", "Play Integrity cloud project and Play distribution on Android"],
      status: reactNativeStatus,
      surface: "react_native"
    }
  ];
}


import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, useMemo, useState } from "react";

import {
  adminRequest,
  RevisionSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { useConsoleCompatibility } from "../app/console-compatibility-context";
import { FeatureRouteSearchSchema } from "../app/route-search";
import { EnvironmentRequired } from "../app/workspace-context";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import {
  applyConfigurationSliceChange,
  cloneConfigurationDocument,
  configurationAreas,
  listAreaResources,
  upsertAreaResource,
  type JSONRecord
} from "./configuration-slice";

const identifierPattern = /^[a-z][a-z0-9_-]{0,62}$/;
const protocols = ["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages"] as const;
const fallbackConditions = ["connect_error", "timeout_before_headers", "first_byte_timeout", "status_429", "status_500", "status_502", "status_503", "status_504"];

interface StagedFeature {
  etag: string;
  feature: JSONRecord;
  plan?: ConfigurationPlan;
  report: ConfigurationValidation;
  revision: ConfigurationRevision;
}

function object(value: unknown): value is JSONRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function specCollection(document: JSONRecord, key: string): JSONRecord[] {
  if (!object(document.spec)) return [];
  const value = document.spec[key];
  return Array.isArray(value) ? value.filter(object) : [];
}

function identifierValues(document: JSONRecord, key: string): string[] {
  return specCollection(document, key).map((value) => String(value.id ?? "")).filter((value) => identifierPattern.test(value));
}

function accessSummary(feature: JSONRecord): string {
  if (!object(feature.access)) return "Custom access";
  const expression = String(feature.access.expression ?? "");
  if (expression === "principal.authenticated") return "All authenticated users";
  if (expression === "principal.authenticated && principal.claims.plan == 'premium'") return "Premium users";
  if (expression === "principal.authenticated && principal.claims.internal == true") return "Internal users";
  return "Custom access rule";
}

function selectedPlan(feature: JSONRecord): string {
  if (!object(feature.limitPlan)) return "Custom plan rule";
  const expression = String(feature.limitPlan.expression ?? "");
  const literal = /^'([a-z][a-z0-9_-]{0,62})'$/.exec(expression);
  return literal?.[1] ?? "Custom plan rule";
}

function orderedRoutes(feature: JSONRecord): JSONRecord[] {
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

// Exported for fail-closed snippet unit tests; this module otherwise exposes only the page component.
// eslint-disable-next-line react-refresh/only-export-components
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

function CopyableClientSnippet({ snippet }: { snippet: FeatureClientSetupSnippet }) {
  const [copyStatus, setCopyStatus] = useState<string>();

  async function copy(): Promise<void> {
    try {
      if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) throw new Error("clipboard_unavailable");
      await navigator.clipboard.writeText(snippet.code);
      setCopyStatus(`${snippet.label} snippet copied.`);
    } catch {
      setCopyStatus("Copy unavailable. Select the code block and copy it manually.");
    }
  }

  return <article className="task-summary-card" data-client-surface={snippet.surface}>
    <div><strong>{snippet.label}</strong><span className={`state-badge ${snippet.available ? "state-badge--available" : "state-badge--warning"}`}><span aria-hidden="true" className="state-badge__dot" />{snippet.available ? "Configured" : "Unavailable"}</span></div>
    <p>{snippet.status}</p>
    <p><strong>App-owned prerequisites</strong></p><ul>{snippet.prerequisites.map((prerequisite) => <li key={prerequisite}>{prerequisite}</li>)}</ul>
    <pre><code>{snippet.code}</code></pre>
    <div className="button-row"><button className="small-action" onClick={() => void copy()} type="button">Copy {snippet.label} snippet</button><a className="small-action" href={snippet.documentationURL} rel="noreferrer" target="_blank">Open {snippet.label} documentation</a></div>
    {copyStatus ? <p role="status">{copyStatus}</p> : null}
  </article>;
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}{problem.operationId ? ` · Operation: ${problem.operationId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
}

function FeatureWorkspace() {
  const workspace = useOptionalWorkspace();
  const routeSearch = FeatureRouteSearchSchema.parse(workspace?.search ?? {});
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const environment = workspace?.environment;
  const application = workspace?.application;
  const [published, setPublished] = useState<{ data: ConfigurationRevision; etag?: string }>();
  const [staged, setStaged] = useState<StagedFeature>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const configuration = useQuery({
    enabled: Boolean(environment?.id),
    queryFn: async () => adminRequest(`/admin/v1/environments/${environment?.id}/config`, RevisionSchema),
    queryKey: ["environment", environment?.id ?? "none", "active-configuration", "features"],
    retry: false
  });
  const currentResponse = published?.data.environment_id === environment?.id ? published : configuration.data;
  const source = currentResponse?.data;
  const sourceETag = currentResponse?.etag;
  const activeStaged = staged?.revision.environment_id === environment?.id ? staged : undefined;
  const canConfigure = session.data?.mode === "configured"
    && consoleCompatibility.mutationAllowed
    && (session.data.session?.capabilities.includes("activate_configuration") ?? false)
    && application?.status === "active"
    && environment?.status === "active";
  const featureCollection = configurationAreas.features.collections[0];
  const features = useMemo(() => source && featureCollection ? listAreaResources(source.document as JSONRecord, featureCollection).map((resource) => resource.value) : [], [featureCollection, source]);
  const selectedFeature = routeSearch.feature ? features.find((feature) => String(feature.id) === routeSearch.feature) : undefined;
  const models = useMemo(() => source ? identifierValues(source.document as JSONRecord, "models") : [], [source]);
  const plans = useMemo(() => source ? identifierValues(source.document as JSONRecord, "limitPlans") : [], [source]);
  const attestationPolicies = useMemo(() => source ? identifierValues(source.document as JSONRecord, "attestationPolicies") : [], [source]);
  const setupFeature = selectedFeature ?? features[0];
  const clientSetupSnippets = source && application && environment && setupFeature ? buildFeatureClientSetupSnippets({
    applicationID: application.id,
    document: source.document as JSONRecord,
    environmentSlug: environment.slug,
    featureID: String(setupFeature.id),
    gatewayURL: typeof window === "undefined" ? undefined : window.location.origin
  }) : [];

  async function stageFeature(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!canConfigure || !environment || !source || !featureCollection) return;
    const form = new FormData(event.currentTarget);
    const id = String(form.get("id"));
    const protocol = String(form.get("protocol"));
    const accessPreset = String(form.get("access"));
    const customAccess = String(form.get("custom_access"));
    const plan = String(form.get("limit_plan"));
    const primary = String(form.get("primary_model"));
    const fallback = String(form.get("fallback_model"));
    const attestationPolicy = String(form.get("attestation_policy"));
    const defaultMaximumTokens = Number(form.get("default_output_tokens"));
    const absoluteMaximumTokens = Number(form.get("absolute_output_tokens"));
    const accessExpression = accessPreset === "premium"
      ? "principal.authenticated && principal.claims.plan == 'premium'"
      : accessPreset === "internal"
        ? "principal.authenticated && principal.claims.internal == true"
        : accessPreset === "custom"
          ? customAccess
          : "principal.authenticated";
    const feature: JSONRecord = {
      access: { expression: accessExpression },
      attestationPolicy,
      id,
      limitPlan: { expression: `'${plan}'` },
      output: { absoluteMaximumTokens, defaultMaximumTokens },
      protocol,
      routes: [
        { fallbackOn: fallback ? fallbackConditions : [], id: "primary", model: primary, priority: 10, when: "true" },
        ...(fallback ? [{ id: "fallback", model: fallback, priority: 20, when: "true" }] : [])
      ]
    };
    setBusy(true);
    setProblem(undefined);
    setStaged(undefined);
    try {
      if (!identifierPattern.test(id) || features.some((candidate) => candidate.id === id)) throw new Error("feature_id");
      if (!protocols.includes(protocol as typeof protocols[number])) throw new Error("protocol");
      if (!models.includes(primary) || (fallback && (!models.includes(fallback) || fallback === primary))) throw new Error("models");
      if (!plans.includes(plan) || !attestationPolicies.includes(attestationPolicy)) throw new Error("references");
      if (!Number.isSafeInteger(defaultMaximumTokens) || !Number.isSafeInteger(absoluteMaximumTokens) || defaultMaximumTokens < 1 || absoluteMaximumTokens < defaultMaximumTokens) throw new Error("output");
      if (accessPreset === "custom" && (!customAccess.trim() || customAccess.length > 4096)) throw new Error("access");
      const stagedDocument = upsertAreaResource(cloneConfigurationDocument(source.document as JSONRecord), featureCollection, undefined, feature).document;
      const result = await applyConfigurationSliceChange({
        activate: false,
        description: `Admin console create feature ${id}`,
        document: stagedDocument,
        environmentID: environment.id,
        sourceRevisionID: source.id
      });
      setStaged({ etag: result.etag, feature, plan: result.plan, report: result.report, revision: result.revision });
    } catch (error) {
      const details: Record<string, string> = {
        access: "Enter a bounded custom access expression.",
        feature_id: "Choose a unique canonical client feature ID.",
        models: "Choose distinct models from the active configuration.",
        output: "The absolute output maximum must be a safe integer at least as large as the default.",
        protocol: "Choose a supported feature protocol.",
        references: "Choose an active usage plan and app-verification policy."
      };
      const detail = error instanceof Error ? details[error.message] : undefined;
      setProblem(detail ? { code: "request_invalid", detail, retryable: false, status: 0, title: "Feature setup is incomplete" } : problemFromError(error));
    } finally {
      setBusy(false);
    }
  }

  async function publish(): Promise<void> {
    if (!canConfigure || !staged || !staged.report.valid || !environment) return;
    setBusy(true);
    setProblem(undefined);
    try {
      const activated = await adminRequest(`/admin/v1/config-revisions/${staged.revision.id}/activate`, RevisionSchema, { etag: staged.etag, method: "POST" });
      if (activated.data.environment_id !== environment.id) throw new Error("environment_mismatch");
      setPublished({ data: activated.data, ...(activated.etag ? { etag: activated.etag } : {}) });
      setStaged(undefined);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "environment_mismatch" ? { code: "invalid_response", detail: "The activated revision did not match the selected environment.", retryable: true, status: 0, title: "Publish context mismatch" } : problemFromError(error));
    } finally {
      setBusy(false);
    }
  }

  return <div className="control-page feature-workspace">
    <section className="page-heading"><div><p className="eyebrow">Features</p><h1>Create an AI capability.</h1><p>Choose who can use it, its usage plan, and primary/fallback models. The server validates the complete configuration before anything reaches {environment?.kind === "production" ? "Production" : environment?.display_name}.</p></div><button className="secondary-action" disabled={busy || configuration.isFetching || !environment} onClick={() => void configuration.refetch()} type="button">{configuration.isFetching ? "Refreshing…" : "Refresh active configuration"}</button></section>
    {environment ? <section className={`production-context production-context--${environment.kind}`} aria-label="Feature change scope"><strong>{application?.display_name ?? application?.slug} / {environment.display_name}</strong><span>{environment.kind === "production" ? "Production configuration · publishing affects client traffic" : `${environment.kind} configuration`}</span><code>{environment.id}</code></section> : null}
    <ProblemNotice problem={problem ?? (configuration.error ? problemFromError(configuration.error) : undefined)} />
    {!source && !configuration.isPending ? <section className="empty-state"><h2>No active configuration is available.</h2><p>Complete first-run setup or activate a full configuration before adding a feature.</p><Link className="primary-action" search={(previous) => previous} to="/setup">Continue setup</Link></section> : null}
    {source ? <>
      <section className="feature-list" aria-labelledby="feature-list-heading"><div className="detail-card__heading"><div><p className="eyebrow">Active revision {source.version}</p><h2 id="feature-list-heading">Configured features</h2></div><code>{sourceETag}</code></div>{features.length ? <div className="feature-grid">{features.map((feature) => { const routes = orderedRoutes(feature); const featureID = String(feature.id); return <article className="feature-card" key={featureID}><div className="feature-card__heading"><button aria-current={routeSearch.feature === featureID ? "true" : undefined} className="link-button" onClick={() => workspace?.updateSearch({ feature: featureID }, { replace: false })} type="button">{featureID}</button><span className="state-badge state-badge--available"><span className="state-badge__dot" aria-hidden="true" />Active</span></div><dl><div><dt>Protocol</dt><dd>{String(feature.protocol)}</dd></div><div><dt>Who can use it</dt><dd>{accessSummary(feature)}</dd></div><div><dt>Usage plan</dt><dd>{selectedPlan(feature)}</dd></div><div><dt>Primary</dt><dd>{String(routes[0]?.model ?? "—")}</dd></div><div><dt>Fallback</dt><dd>{String(routes[1]?.model ?? "None")}</dd></div></dl><details><summary>Advanced configuration</summary><pre>{JSON.stringify(feature, null, 2)}</pre></details></article>; })}</div> : <p>No features are active.</p>}</section>
      {routeSearch.feature && !selectedFeature ? <section className="control-notice control-notice--error" role="alert"><strong>Selected feature unavailable</strong><span>The active configuration did not contain <code>{routeSearch.feature}</code>. No different feature was selected.</span><button className="small-action" onClick={() => workspace?.updateSearch({ feature: undefined })} type="button">Close selection</button></section> : null}
      {selectedFeature ? <section className="detail-card" aria-labelledby="selected-feature-heading"><div className="detail-card__heading"><div><p className="eyebrow">Selected active feature</p><h2 id="selected-feature-heading">{String(selectedFeature.id)}</h2></div><button className="small-action" onClick={() => workspace?.updateSearch({ feature: undefined })} type="button">Close feature</button></div><dl><div><dt>Protocol</dt><dd>{String(selectedFeature.protocol)}</dd></div><div><dt>Who can use it</dt><dd>{accessSummary(selectedFeature)}</dd></div><div><dt>Usage plan</dt><dd>{selectedPlan(selectedFeature)}</dd></div></dl><details open><summary>Advanced configuration</summary><pre>{JSON.stringify(selectedFeature, null, 2)}</pre></details></section> : null}
      <form className="control-form feature-builder" onSubmit={(event) => void stageFeature(event)}>
        <div><p className="eyebrow">New feature</p><h2>Set the outcome, then review the change.</h2><p>The form writes one canonical feature into a cloned full document; unrelated identity, client-access, pricing, and routing resources are preserved.</p></div>
        <fieldset><legend>1. Name the capability</legend><div className="form-field-grid"><label>Client feature ID<input name="id" pattern="[a-z][a-z0-9_-]{0,62}" placeholder="habit-assistant" required /></label><label>Protocol<select defaultValue="openai_responses" name="protocol">{protocols.map((protocol) => <option key={protocol} value={protocol}>{protocol.replaceAll("_", " ")}</option>)}</select></label></div></fieldset>
        <fieldset><legend>2. Choose where requests go</legend><div className="form-field-grid"><label>Primary model<select name="primary_model" required><option value="">Choose a model</option>{models.map((model) => <option key={model} value={model}>{model}</option>)}</select></label><label>Fallback model<select name="fallback_model"><option value="">No fallback</option>{models.map((model) => <option key={model} value={model}>{model}</option>)}</select></label></div><small>The primary route falls back only for bounded connection, timeout, 429, and 5xx conditions.</small></fieldset>
        <fieldset><legend>3. Choose who and which clients may use it</legend><div className="form-field-grid"><label>User access<select defaultValue="authenticated" name="access"><option value="authenticated">All authenticated users</option><option value="premium">Premium users</option><option value="internal">Internal users</option><option value="custom">Custom rule</option></select></label><label>App verification<select name="attestation_policy" required><option value="">Choose a policy</option>{attestationPolicies.map((policy) => <option key={policy} value={policy}>{policy}</option>)}</select></label></div><label>Custom access rule (used only when selected)<input maxLength={4096} name="custom_access" placeholder="principal.authenticated && …" /></label></fieldset>
        <fieldset><legend>4. Set sensible limits</legend><div className="form-field-grid"><label>Usage plan<select name="limit_plan" required><option value="">Choose a plan</option>{plans.map((plan) => <option key={plan} value={plan}>{plan}</option>)}</select></label><label>Default output tokens<input defaultValue={800} min={1} name="default_output_tokens" type="number" /></label><label>Absolute output tokens<input defaultValue={1500} min={1} name="absolute_output_tokens" type="number" /></label></div></fieldset>
        <div className="button-row"><span>{canConfigure ? "This creates a server-side draft; it does not publish automatically." : application?.status === "disabled" || environment?.status === "disabled" ? "Re-enable both the application and environment before staging or publishing configuration." : "You need the Admin role to stage or publish configuration."}</span><button className="primary-action" disabled={!canConfigure || busy || models.length === 0 || plans.length === 0 || attestationPolicies.length === 0} type="submit">{busy ? "Validating…" : "Review feature change"}</button></div>
      </form>
      {activeStaged ? <section className={`publish-review ${activeStaged.report.valid ? "publish-review--valid" : "publish-review--invalid"}`} aria-labelledby="publish-review-heading"><p className="eyebrow">Draft revision {activeStaged.revision.version}</p><h2 id="publish-review-heading">Publish {String(activeStaged.feature.id)} to {application?.display_name} / {environment?.kind === "production" ? "Production" : environment?.display_name}?</h2><div className="impact-grid"><div><strong>{activeStaged.report.valid ? "Configuration valid" : "Configuration needs changes"}</strong><span>{activeStaged.report.issues.length ? `${activeStaged.report.issues.length} server validation issue(s)` : "All referenced resources resolve"}</span></div><div><strong>{activeStaged.plan?.changes.length ?? 0} planned change(s)</strong><span>{activeStaged.plan?.warnings.length ? `${activeStaged.plan.warnings.length} impact warning(s)` : "No structural warnings"}</span></div><div><strong>{environment?.kind === "production" ? "Production traffic" : `${environment?.kind} traffic`}</strong><span>Activation is atomic and rollback creates a new revision</span></div></div>{activeStaged.report.issues.length ? <ul>{activeStaged.report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code>{issue.path}</code> — {issue.message}</li>)}</ul> : null}{activeStaged.plan?.changes.length ? <ul>{activeStaged.plan.changes.map((change, index) => <li key={`${change.path}-${index}`}><strong>{change.operation}</strong> <code>{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul> : null}<div className="button-row"><button className="secondary-action" disabled={busy} onClick={() => setStaged(undefined)} type="button">Keep draft unpublished</button><button className="primary-action" disabled={busy || !canConfigure || !activeStaged.report.valid} onClick={() => void publish()} type="button">Publish to {environment?.kind === "production" ? "Production" : environment?.display_name}</button></div></section> : null}
      <section className="detail-card client-setup" aria-labelledby="client-setup-heading"><div><p className="eyebrow">Personalized client setup</p><h2 id="client-setup-heading">Use {String(setupFeature?.id ?? "this feature")} from each supported client.</h2><p>Each snippet contains only the public application resource ID, environment slug, same-origin gateway, configured identity-provider name, and client feature ID. Provider credentials, server secret references, identity tokens, and attestation evidence are never rendered.</p><dl><div><dt>Gateway URL</dt><dd><code>{typeof window === "undefined" ? "Unavailable until the browser knows its origin" : window.location.origin}</code></dd></div><div><dt>Application ID</dt><dd><code>{application?.id}</code></dd></div><div><dt>Environment slug</dt><dd><code>{environment?.slug}</code></dd></div><div><dt>Feature</dt><dd><code>{String(setupFeature?.id ?? "Unavailable")}</code></dd></div></dl></div><div className="task-card-list" aria-label="Platform client snippets">{clientSetupSnippets.map((snippet) => <CopyableClientSnippet key={snippet.surface} snippet={snippet} />)}</div></section>
    </> : null}
  </div>;
}

export function FeatureWorkspacePage() {
  return <EnvironmentRequired><FeatureWorkspace /></EnvironmentRequired>;
}

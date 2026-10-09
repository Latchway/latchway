import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCapabilities } from "../app/permissions";
import { type FormEvent, useMemo, useRef, useState } from "react";

import {
  adminRequest,
  RequestPageSchema,
  RevisionSchema,
  SelfTestSchema,
  type ConfigurationRevision,
  type ConfigurationValidation,
  type LogicalRequest,
  type SelfTestRun,
  queryPath
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { latestConfigurationRevisionQueryOptions } from "../api/workspace";
import { SecretResourcePageSchema } from "../api/resources";
import { useConsoleCompatibility } from "../app/console-compatibility-context";
import { useDirtyEditProtection } from "../app/use-dirty-edit-protection";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { Button, buttonClass, Card, cx, EmptyState, Icon, Notice, PageHeader } from "../ui";
import { AccessRequired, ProblemNotice } from "./control-plane-pages";
import {
  requireAndroidPackageName,
  requireAppleBundleID,
  requireAppleBundleVersion,
  requireCanonicalBrowserOrigin,
  requireCloudProjectNumber,
  requireFirebaseProjectNumber,
  requireGuidedUpstreamURL,
  requirePlayCertificateDigest
} from "./client-proof-validation";
import { buildNativeTemplate, type NativeTemplateInput } from "./native-template";
import { ApplePolicyFields, PlayTestingField } from "./attestation-policy-fields";
import { applePolicyFromForm, type AppAttestEnvironment, type AppleValidationCategory } from "./attestation-policy-input";
import { createValidateActivate, findOrCreateApplication, findOrCreateEnvironment } from "./setup-wizard-api";
import { canonicalConfigurationJSON } from "./setup-wizard-state";
import {
  resolveWriteOnlySecret,
  WriteOnlySecretResolutionError,
  type WriteOnlySecretAction,
  type WriteOnlySecretResolution
} from "./write-only-secret";

const setupRequestPageSize = "50";
const selectablePlatformScopes = [
  "ios",
  "android",
  "web",
  "react_native_ios",
  "react_native_android",
  "react_native_both"
] as const;

export type SetupPlatformScope = typeof selectablePlatformScopes[number] | "native_both";

export interface FirstRunTemplateInput extends Omit<
  NativeTemplateInput,
  "appIDPrefix" | "appleDistribution" | "bundleID" | "bundleVersion" | "certificateDigest" |
  "clientSurface" | "cloudProject" | "packageName" | "androidVersionCode" | "playIntegrityCredential"
> {
  androidVersionCode?: number;
  appIDPrefix?: string;
  appleDistribution?: NativeTemplateInput["appleDistribution"];
  bundleID?: string;
  bundleVersion?: string;
  certificateDigest?: string;
  cloudProject?: number;
  firebaseAppID?: string;
  firebaseProjectNumber?: string;
  packageName?: string;
  playIntegrityCredential?: { type: "metadata" } | { type: "service_account"; secretName: string };
  platformScope: SetupPlatformScope;
  webOrigin?: string;
}

interface SetupPageWorkspace {
  applicationID: string;
  applicationSlug: string;
  cloudProjectNumber?: string;
  environmentID: string;
  environmentSlug: string;
  plannedSecretName: string;
  plannedPlayIntegritySecretName?: string;
  playIntegrityCredentialSource?: "metadata" | "service_account";
  platformScope: SetupPlatformScope;
  selfTestMaximumCostNanoUsd: number;
  upstreamAuthentication: "bearer" | "none";
}

interface SetupRequestTarget {
  feature: string;
  protocol: LogicalRequest["protocol"];
}

const platformScopePlatforms: Record<SetupPlatformScope, string[]> = {
  android: ["android"],
  ios: ["ios"],
  native_both: ["ios", "android"],
  react_native_android: ["react_native_android"],
  react_native_both: ["react_native_ios", "react_native_android"],
  react_native_ios: ["react_native_ios"],
  web: ["web"]
};

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.map(record).filter((item): item is Record<string, unknown> => Boolean(item))
    : [];
}

function platformScopeHasApple(scope: SetupPlatformScope): boolean {
  return platformScopePlatforms[scope].some((platform) => platform === "ios" || platform === "react_native_ios");
}

function platformScopeHasAndroid(scope: SetupPlatformScope): boolean {
  return platformScopePlatforms[scope].some((platform) => platform === "android" || platform === "react_native_android");
}

function platformScopeLabel(scope: SetupPlatformScope): string {
  switch (scope) {
    case "ios": return "iOS (Swift)";
    case "android": return "Android (Kotlin)";
    case "web": return "Web (JavaScript)";
    case "react_native_ios": return "React Native on iOS";
    case "react_native_android": return "React Native on Android";
    case "react_native_both": return "React Native on iOS and Android";
    case "native_both": return "native iOS and Android";
  }
}

function distinctUnusedIdentifier(used: string | undefined, fallback: string): string {
  return used === fallback ? `${fallback}.unused` : fallback;
}

/**
 * Produces the bounded first-run document for exactly the selected client
 * surface. The shared template supplies the non-platform configuration; all
 * unselected platform proof is removed before the document is returned.
 */
// This pure builder is exported from its owning page so its security-sensitive
// platform filtering can be tested without widening the implementation surface.
// eslint-disable-next-line react-refresh/only-export-components
export function buildFirstRunTemplate(input: FirstRunTemplateInput): string {
  if (!Object.hasOwn(platformScopePlatforms, input.platformScope)) {
    throw new Error("Choose an exact supported client platform.");
  }
  const apple = platformScopeHasApple(input.platformScope);
  const android = platformScopeHasAndroid(input.platformScope);
  if (apple && !input.appIDPrefix?.match(/^[A-Z0-9]{1,64}$/)) {
    throw new Error("Enter the exact App ID prefix, bundle ID, CFBundleVersion, and distribution method.");
  }
  const bundleID = apple ? requireAppleBundleID(input.bundleID) : undefined;
  const bundleVersion = apple ? requireAppleBundleVersion(input.bundleVersion) : undefined;
  const packageName = android ? requireAndroidPackageName(input.packageName) : undefined;
  const certificateDigest = android ? requirePlayCertificateDigest(input.certificateDigest) : undefined;
  const cloudProject = android ? requireCloudProjectNumber(input.cloudProject) : undefined;
  const androidVersionCode = android && Number.isSafeInteger(input.androidVersionCode) && input.androidVersionCode! >= 1
    ? input.androidVersionCode
    : undefined;
  if (android && !androidVersionCode) throw new Error("Enter the exact positive Android version code.");
  if (android && (!input.playIntegrityCredential ||
    (input.playIntegrityCredential.type === "service_account" && !/^[a-z][a-z0-9_-]{0,62}$/u.test(input.playIntegrityCredential.secretName)))) {
    throw new Error("Choose an exact Play Integrity credential source and secret name when required.");
  }
  const upstreamURL = requireGuidedUpstreamURL(input.upstreamURL);

  const unusedBundle = distinctUnusedIdentifier(input.packageName, "dev.latchway.unused.ios");
  const unusedPackage = distinctUnusedIdentifier(input.bundleID, "dev.latchway.unused.android");
  const base = JSON.parse(buildNativeTemplate({
    ...input,
    appIDPrefix: apple ? input.appIDPrefix! : "UNUSED",
    androidVersionCode: android ? androidVersionCode! : 1,
    appleDistribution: apple ? input.appleDistribution! : "app_store",
    bundleID: apple ? bundleID! : unusedBundle,
    bundleVersion: apple ? bundleVersion! : "1",
    certificateDigest: android ? certificateDigest! : "A".repeat(42) + "Q",
    clientSurface: input.platformScope.startsWith("react_native") ? "react_native" : "native",
    cloudProject: android ? cloudProject! : 1,
    packageName: android ? packageName! : unusedPackage,
    playIntegrityCredential: android ? input.playIntegrityCredential! : { type: "metadata" },
    upstreamURL
  })) as Record<string, unknown>;
  const spec = record(base.spec);
  const policy = records(spec?.attestationPolicies)[0];
  const feature = records(spec?.features)[0];
  if (!spec || !policy || !feature) throw new Error("The shared first-run template is incomplete.");

  if (input.platformScope === "web") {
    const origin = requireCanonicalBrowserOrigin(input.webOrigin, input.environmentKind).origin;
    const projectNumber = requireFirebaseProjectNumber(input.firebaseProjectNumber);
    if (!input.firebaseAppID?.match(/^[!-~]{5,256}$/)) {
      throw new Error("Enter the Firebase project number and exact web app ID.");
    }
    policy.id = "web";
    policy.platforms = {
      web: {
        allowedOrigins: [origin],
        firebaseAppCheck: { allowedAppIds: [input.firebaseAppID], projectNumber },
        minimumTrustLevel: "web_risk_verified",
        mode: "required",
        provider: "firebase_app_check"
      }
    };
    spec.componentDefinitions = [{
      allowedFeatures: ["assistant"],
      attestation: { provider: "firebase_app_check", strategy: "direct" },
      familyRole: "root",
      id: "web-main",
      identifiers: { origins: [origin] },
      kind: "browser",
      platform: "web"
    }];
    feature.attestationPolicy = "web";
  } else {
    const selectedPlatforms = new Set(platformScopePlatforms[input.platformScope]);
    const allPlatforms = record(policy.platforms);
    if (!allPlatforms) throw new Error("The shared first-run platform policy is incomplete.");
    policy.platforms = Object.fromEntries(
      Object.entries(allPlatforms).filter(([platform]) => selectedPlatforms.has(platform))
    );
    spec.componentDefinitions = records(spec.componentDefinitions)
      .filter((definition) => selectedPlatforms.has(String(definition.platform)));
  }

  const metadata = record(base.metadata);
  if (metadata) metadata.description = `${platformScopeLabel(input.platformScope)} ${input.environmentKind} gateway`;
  return JSON.stringify(base, null, 2);
}

function setupPlatformScope(document: unknown): SetupPlatformScope | undefined {
  const spec = record(record(document)?.spec);
  const definitions = records(spec?.componentDefinitions);
  if (definitions.length === 0 || definitions.some((definition) =>
    definition.familyRole !== "root" || !Array.isArray(definition.allowedFeatures) || !definition.allowedFeatures.includes("assistant")
  )) return undefined;
  const platforms = definitions.map((definition) => String(definition.platform)).sort();
  return (Object.entries(platformScopePlatforms) as Array<[SetupPlatformScope, string[]]>).find(([, expected]) =>
    expected.length === platforms.length && [...expected].sort().every((platform, index) => platform === platforms[index])
  )?.[0];
}

function setupRequestTarget(document: string): SetupRequestTarget | undefined {
  try {
    const features = records(record((JSON.parse(document) as Record<string, unknown>).spec)?.features);
    if (features.length !== 1 || typeof features[0]?.id !== "string") return undefined;
    const protocol = features[0].protocol;
    if (protocol !== "openai_responses" && protocol !== "openai_chat" && protocol !== "openai_embeddings" &&
      protocol !== "anthropic_messages" && protocol !== "opaque_http") return undefined;
    return { feature: features[0].id, protocol };
  } catch {
    return undefined;
  }
}

function matchingSetupRequest(
  requests: LogicalRequest[] | undefined,
  environmentID: string,
  target: SetupRequestTarget | undefined,
  revisionID: string | undefined
): LogicalRequest | undefined {
  if (!target || !revisionID) return undefined;
  return requests?.find((request) => request.environment_id === environmentID && request.feature === target.feature &&
    request.protocol === target.protocol && request.config_revision_id === revisionID &&
    request.status === "succeeded" && Boolean(request.completed_at));
}

function requiredString(container: Record<string, unknown> | undefined, key: string): string {
  const value = container?.[key];
  if (typeof value !== "string") throw new Error(`Missing string ${key}.`);
  return value;
}

function requiredSafeInteger(container: Record<string, unknown> | undefined, key: string): number {
  const value = container?.[key];
  if (!Number.isSafeInteger(value)) throw new Error(`Missing safe integer ${key}.`);
  return value as number;
}

function requiredOnlyRecord(value: unknown, label: string): Record<string, unknown> {
  const values = records(value);
  if (values.length !== 1) throw new Error(`Expected one ${label}.`);
  return values[0]!;
}

function requiredOnlyString(value: unknown, label: string): string {
  if (!Array.isArray(value) || value.length !== 1 || typeof value[0] !== "string") {
    throw new Error(`Expected one ${label}.`);
  }
  return value[0];
}

function applePolicyFromSelection(selection: Record<string, unknown>) {
  const appAttest = record(selection.appAttest);
  const categories = appAttest?.allowedValidationCategories;
  const environment = appAttest?.environment;
  if (!Array.isArray(categories) || !categories.length || categories.some((category) => ![2, 3, 4, 5].includes(category as number)) ||
    (environment !== "development" && environment !== "production" && environment !== "any")) throw new Error("Unsupported first-run App Attest policy.");
  return {
    appAttestEnvironment: environment as AppAttestEnvironment,
    appleValidationCategories: categories as AppleValidationCategory[],
    ...(selection.dangerousAllowInProduction === true ? { dangerousAllowInProduction: true } : {})
  };
}

// Exported for exact, fail-closed resume regression tests.
// eslint-disable-next-line react-refresh/only-export-components
export function resumeSetupPageWorkspace(input: {
  applicationID: string;
  applicationSlug: string;
  document: unknown;
  environmentID: string;
  environmentSlug: string;
}): SetupPageWorkspace | undefined {
  try {
    const root = record(input.document);
    const metadata = record(root?.metadata);
    const spec = record(root?.spec);
    const scope = setupPlatformScope(input.document);
    if (root?.apiVersion !== "latchway.dev/v1alpha1" || root.kind !== "EnvironmentConfig" || !metadata || !spec || !scope ||
      metadata.application !== input.applicationSlug || metadata.environment !== input.environmentSlug) return undefined;

    const identity = requiredOnlyRecord(spec.identityProviders, "identity provider");
    const policy = requiredOnlyRecord(spec.attestationPolicies, "attestation policy");
    const upstream = requiredOnlyRecord(spec.upstreams, "upstream");
    const accounting = requiredOnlyRecord(spec.inputAccountingProfiles, "input-accounting profile");
    const pricing = requiredOnlyRecord(spec.pricingCatalogs, "pricing catalog");
    const price = requiredOnlyRecord(pricing.entries, "pricing entry");
    requiredOnlyRecord(spec.models, "model");
    const plan = requiredOnlyRecord(spec.limitPlans, "limit plan");
    const limits = records(plan.limits);
    const feature = requiredOnlyRecord(spec.features, "feature");
    if (identity.id !== "firebase" || identity.type !== "firebase" || feature.id !== "assistant" || limits.length !== 5) return undefined;

    const authentication = record(upstream.authentication);
    if (!authentication || (authentication.type !== "bearer" && authentication.type !== "none")) return undefined;
    let plannedSecretName = "";
    const upstreamAuthentication = authentication.type;
    if (upstreamAuthentication === "bearer") {
      const reference = requiredString(authentication, "secretRef");
      if (!/^secret\/[a-z][a-z0-9_-]{0,62}$/u.test(reference)) return undefined;
      plannedSecretName = reference.slice("secret/".length);
    }

    const platformMap = record(policy.platforms);
    if (!platformMap) return undefined;
    const template: Omit<FirstRunTemplateInput, "environmentKind"> = {
      application: requiredString(metadata, "application"),
      authentication: upstreamAuthentication === "bearer" ? { type: "bearer", secretName: plannedSecretName } : { type: "none" },
      dailyInputTokenMaximum: requiredSafeInteger(limits[1], "maximum"),
      dailyOutputTokenMaximum: requiredSafeInteger(limits[2], "maximum"),
      dailyTotalTokenMaximum: requiredSafeInteger(limits[3], "maximum"),
      environment: requiredString(metadata, "environment"),
      firebaseProject: requiredString(identity, "projectId"),
      inputNanoUsdPerMillion: requiredSafeInteger(price, "inputNanoUsdPerMillion"),
      maximumContextTokens: requiredSafeInteger(accounting, "maximumContextTokens"),
      maximumFramingTokensPerMessage: requiredSafeInteger(accounting, "maximumFramingTokensPerMessage"),
      maximumFramingTokensPerRequest: requiredSafeInteger(accounting, "maximumFramingTokensPerRequest"),
      organization: requiredString(metadata, "organization"),
      outputNanoUsdPerMillion: requiredSafeInteger(price, "outputNanoUsdPerMillion"),
      perRequestInputTokenMaximum: requiredSafeInteger(limits[4], "perRequestMaximum"),
      physicalModel: requiredString(accounting, "physicalModel"),
      platformScope: scope,
      requestNanoUsd: requiredSafeInteger(price, "requestNanoUsd"),
      upstreamURL: requiredString(upstream, "baseUrl")
    };

    let cloudProjectNumber: string | undefined;
    let playIntegrityCredentialSource: "metadata" | "service_account" | undefined;
    let plannedPlayIntegritySecretName: string | undefined;
    if (platformScopeHasApple(scope)) {
      const platform = scope === "ios" || scope === "native_both" ? "ios" : "react_native_ios";
      const selection = record(platformMap[platform]);
      const appAttest = record(selection?.appAttest);
      template.appIDPrefix = requiredString(appAttest, "appIdPrefix");
      Object.assign(template, applePolicyFromSelection(selection ?? {}));
      template.bundleID = requiredString(appAttest, "bundleId");
      template.bundleVersion = requiredOnlyString(appAttest?.allowedBundleVersions, "bundle version");
    }
    if (platformScopeHasAndroid(scope)) {
      const platform = scope === "android" || scope === "native_both" ? "android" : "react_native_android";
      const selection = record(platformMap[platform]);
      const playIntegrity = record(selection?.playIntegrity);
      const project = requireCloudProjectNumber(requiredSafeInteger(playIntegrity, "cloudProjectNumber"));
      const source = requiredString(playIntegrity, "credentialSource");
      if (source !== "metadata" && source !== "service_account") return undefined;
      playIntegrityCredentialSource = source;
      template.androidVersionCode = requiredSafeInteger(playIntegrity, "minimumVersionCode");
      template.certificateDigest = requiredOnlyString(playIntegrity?.certificateSha256Digests, "certificate digest");
      template.cloudProject = project;
      if (typeof playIntegrity?.allowTestingResponses !== "boolean" || typeof playIntegrity.requireLicensed !== "boolean") return undefined;
      template.allowPlayTestingResponses = playIntegrity.allowTestingResponses;
      template.requirePlayLicensed = playIntegrity.requireLicensed;
      template.packageName = requiredString(playIntegrity, "packageName");
      if (source === "service_account") {
        const reference = requiredString(selection, "secretRef");
        if (!/^secret\/[a-z][a-z0-9_-]{0,62}$/u.test(reference)) return undefined;
        plannedPlayIntegritySecretName = reference.slice("secret/".length);
        template.playIntegrityCredential = { type: "service_account", secretName: plannedPlayIntegritySecretName };
      } else {
        template.playIntegrityCredential = { type: "metadata" };
      }
      cloudProjectNumber = String(project);
    }
    if (scope === "web") {
      const selection = record(platformMap.web);
      const firebase = record(selection?.firebaseAppCheck);
      template.firebaseAppID = requiredOnlyString(firebase?.allowedAppIds, "Firebase application ID");
      template.firebaseProjectNumber = requiredString(firebase, "projectNumber");
      template.webOrigin = requiredOnlyString(selection?.allowedOrigins, "browser origin");
    }

    for (const environmentKind of ["development", "staging", "production"] as const) {
      try {
        const rebuilt = JSON.parse(buildFirstRunTemplate({ ...template, environmentKind })) as unknown;
        if (canonicalConfigurationJSON(rebuilt) !== canonicalConfigurationJSON(input.document)) continue;
        return {
          applicationID: input.applicationID,
          applicationSlug: input.applicationSlug,
          ...(cloudProjectNumber ? { cloudProjectNumber } : {}),
          environmentID: input.environmentID,
          environmentSlug: input.environmentSlug,
          plannedSecretName,
          ...(plannedPlayIntegritySecretName ? { plannedPlayIntegritySecretName } : {}),
          ...(playIntegrityCredentialSource ? { playIntegrityCredentialSource } : {}),
          platformScope: scope,
          selfTestMaximumCostNanoUsd: 10_000_000,
          upstreamAuthentication
        };
      } catch {
        // Try the next bounded environment kind; exact canonical equality is authoritative.
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function buildSetupSnippets(workspace: SetupPageWorkspace): Array<{ code: string; label: string }> {
  const base = `baseURL: gatewayURL,\n  applicationID: "${workspace.applicationID}",\n  environment: "${workspace.environmentSlug}"`;
  const fetchMethod = ["latchway", "fetch"].join(".");
  const request = `\n\nconst response = await ${fetchMethod}("/v1/responses", {\n  method: "POST",\n  latchwayFeature: "assistant",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({ model: "client", input: "Hello" }),\n});`;
  if (workspace.platformScope === "ios") return [{ label: "iOS", code: `import Foundation
import Latchway
import LatchwayAppAttest
import LatchwayFirebaseAuth

let rootKeychainAccessGroup = "YOUR_FULLY_RESOLVED_PRIVATE_APP_ID_GROUP"
let appAttest = LatchwayAppAttestProvider(
  applicationID: "${workspace.applicationID}",
  environment: "${workspace.environmentSlug}",
  rootKeychainAccessGroup: rootKeychainAccessGroup
)
let identity = FirebaseLatchwayIdentityTokenProvider(identityToken: getFirebaseIDToken)
let client = LatchwayClient(
  configuration: LatchwayConfiguration(
    baseURL: gatewayURL,
    applicationID: "${workspace.applicationID}",
    environment: "${workspace.environmentSlug}",
    rootKeychainAccessGroup: rootKeychainAccessGroup,
    identityProvider: "firebase",
    attestationProvider: appAttest
  ),
  identityTokenProvider: identity
)
var request = URLRequest(url: gatewayURL.appendingPathComponent("v1/responses"))
request.httpMethod = "POST"
request.setValue("application/json", forHTTPHeaderField: "Content-Type")
request.httpBody = Data(#"{"model":"client","input":"Hello"}"#.utf8)
let response = try await client.send(request, feature: "assistant")` }];
  if (workspace.platformScope === "android") return [{ label: "Android", code: `import dev.latchway.firebaseauth.FirebaseIdentityTokenProvider
import dev.latchway.okhttp.LatchwayClient
import dev.latchway.okhttp.LatchwayConfiguration
import dev.latchway.okhttp.latchwayFeature
import dev.latchway.playintegrity.PlayIntegrityAttestationProvider
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

val client = LatchwayClient(
  configuration = LatchwayConfiguration(
    baseUrl = gatewayUrl,
    applicationId = "${workspace.applicationID}",
    environment = "${workspace.environmentSlug}",
    identityProvider = "firebase",
    defaultFeature = "assistant",
  ),
  identityTokenProvider = FirebaseIdentityTokenProvider(firebaseAuth, forceRefresh = true),
  attestationProvider = PlayIntegrityAttestationProvider(
    context = applicationContext,
    cloudProjectNumber = ${workspace.cloudProjectNumber}L,
  ),
  context = applicationContext,
)
val http = client.buildOkHttpClient(OkHttpClient.Builder())
val request = Request.Builder()
  .url(checkNotNull(gatewayUrl.resolve("v1/responses")))
  .post("""{"model":"client","input":"Hello"}""".toRequestBody("application/json".toMediaType()))
  .latchwayFeature("assistant")
  .build()
http.newCall(request).execute().use { response ->
  check(response.isSuccessful)
}` }];
  if (workspace.platformScope === "native_both") return [
    ...buildSetupSnippets({ ...workspace, platformScope: "ios" }),
    ...buildSetupSnippets({ ...workspace, platformScope: "android" })
  ];
  if (workspace.platformScope === "web") return [{ label: "Web", code: `import { createLatchwayClient } from "@latchway/client";\nimport { createFirebaseAppCheckProvider, createFirebaseIdentityTokenProvider } from "@latchway/client/firebase";\n\nconst latchway = createLatchwayClient({\n  ${base},\n  identityProvider: "firebase",\n  identityTokenProvider: createFirebaseIdentityTokenProvider(getIdentityToken),\n  attestationProviders: [createFirebaseAppCheckProvider(getAppCheckToken)],\n});${request}` }];
  const appleOption = platformScopeHasApple(workspace.platformScope)
    ? `  apple: {\n    rootKeychainAccessGroup: "YOUR_FULLY_RESOLVED_PRIVATE_APP_ID_GROUP",\n  },\n`
    : "";
  const androidOption = platformScopeHasAndroid(workspace.platformScope)
    ? `  android: { playIntegrityCloudProjectNumber: "${workspace.cloudProjectNumber}" },\n`
    : "";
  return [{ label: "React Native", code: `import { createLatchwayClient } from "@latchway/react-native";\n\nconst latchway = createLatchwayClient({\n  ${base},\n  identityProvider: "firebase",\n  getIdentityToken,\n${appleOption}${androidOption}});${request}` }];
}

function safeInteger(form: FormData, name: string, minimum: number): number {
  const value = Number(form.get(name));
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be a safe integer greater than or equal to ${minimum}.`);
  return value;
}

function safeCloudProjectNumber(form: FormData, name: string): number {
  const raw = String(form.get(name));
  if (!/^[1-9][0-9]{5,18}$/.test(raw)) {
    throw new Error(`${name} must contain 6 through 19 canonical decimal digits.`);
  }
  const value = Number(raw);
  try { return requireCloudProjectNumber(value); }
  catch { throw new Error(`${name} exceeds the Console's exact integer range.`); }
}

function setupEvidenceProblem(error: unknown): AdminProblem | undefined {
  if (!(error instanceof Error) || ![
    "The active configuration changed before the bounded self-test started.",
    "The active configuration changed while the bounded self-test was running.",
    "The exact active first-run configuration is no longer available.",
    "The editor no longer matches the exact active first-run configuration.",
    "The active configuration changed while request evidence was being inspected."
  ].includes(error.message)) return undefined;
  return {
    code: "configuration_context_changed",
    detail: error.message,
    retryable: true,
    status: 0,
    title: "Configuration evidence changed"
  };
}

function ValidationResult({ report }: { report?: ConfigurationValidation }) {
  return report ? <Notice title={report.valid ? "Configuration is valid" : "Configuration needs changes"} tone={report.valid ? "success" : "danger"}>
    Checked {new Date(report.checked_at).toLocaleString()}.
    {report.issues.length ? <ul className="lw-issue-items">{report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code className="lw-code-inline">{issue.path}</code> — {issue.message}</li>)}</ul> : " No validation issues."}
  </Notice> : null;
}

const PLAN_STEPS = [
  { detail: "Names, slugs and environment kind", title: "App & environment" },
  { detail: "Sign-in provider and platform proof", title: "Clients" },
  { detail: "Provider endpoint and model", title: "AI connection" },
  { detail: "Prices and hard token limits", title: "Pricing & limits" },
  { detail: "Check and create", title: "Review" }
] as const;

const BUILD_STEPS = [
  { anchor: "setup-credential", detail: "Server-held provider key", title: "Credential" },
  { anchor: "setup-publish", detail: "Validate and activate", title: "Publish" },
  { anchor: "setup-self-test", detail: "One bounded provider call", title: "Self-test" },
  { anchor: "setup-snippets", detail: "SDK configuration", title: "Connect your app" },
  { anchor: "setup-verify", detail: "A real client request", title: "Verify a request" }
] as const;

/** Non-secret form values for the summary column. Secret inputs are never read here. */
interface SetupSummary {
  application?: string;
  environment?: string;
  identity?: string;
  model?: string;
  platform?: string;
  pricing?: string;
  upstream?: string;
}

function readSetupSummary(form: HTMLFormElement): SetupSummary {
  const value = (name: string): string => {
    const element = form.elements.namedItem(name);
    return element instanceof HTMLInputElement || element instanceof HTMLSelectElement ? element.value.trim() : "";
  };
  const upstreamHost = URL.canParse(value("upstream_url")) ? new URL(value("upstream_url")).host : value("upstream_url");
  const kind = value("environment_kind");
  const input = value("input_nano_usd_per_million");
  const output = value("output_nano_usd_per_million");
  return {
    application: value("application_name") ? `${value("application_name")} (${value("application_slug") || "no slug"})` : undefined,
    environment: value("environment_name") ? `${value("environment_name")} · ${kind}` : undefined,
    identity: value("firebase_project") ? `Firebase · ${value("firebase_project")}` : undefined,
    model: value("physical_model") || undefined,
    platform: value("platform_scope") ? platformScopeLabel(value("platform_scope") as SetupPlatformScope) : undefined,
    pricing: input && output ? `${Number(input).toLocaleString()} / ${Number(output).toLocaleString()} nano-USD per 1M in / out` : undefined,
    upstream: upstreamHost ? `${upstreamHost} · ${value("upstream_authentication") === "none" ? "no auth" : "bearer secret"}` : undefined
  };
}

function comparableDocument(text: string): string {
  try {
    return canonicalConfigurationJSON(JSON.parse(text) as unknown);
  } catch {
    return text;
  }
}

export function SetupWizardPage() {
  const selectedWorkspace = useOptionalWorkspace();
  const scope = `${selectedWorkspace?.application?.id ?? "none"}:${selectedWorkspace?.environment?.id ?? "none"}`;
  return <ScopedSetupWizardPage key={scope} />;
}

function ScopedSetupWizardPage() {
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const selectedWorkspace = useOptionalWorkspace();
  const queryClient = useQueryClient();
  const [createdWorkspace, setWorkspace] = useState<SetupPageWorkspace>();
  const [platformScope, setPlatformScope] = useState<(typeof selectablePlatformScopes)[number]>("react_native_both");
  const [environmentKindInput, setEnvironmentKindInput] = useState<NativeTemplateInput["environmentKind"]>(selectedWorkspace?.environment?.kind ?? "production");
  const [playIntegrityCredentialSource, setPlayIntegrityCredentialSource] = useState<"metadata" | "service_account">("metadata");
  const [upstreamAuthenticationMode, setUpstreamAuthenticationMode] = useState<"bearer" | "none">("bearer");
  const [editedDocument, setDocument] = useState<string>(); const [createdSecretName, setSecretName] = useState<string>();
  const [appliedRevision, setRevision] = useState<ConfigurationRevision>(); const [appliedValidation, setValidation] = useState<ConfigurationValidation>(); const [test, setTest] = useState<SelfTestRun>();
  const [createdPlayIntegritySecretName, setPlayIntegritySecretName] = useState<string>(); const [observedRequest, setObservedRequest] = useState<LogicalRequest>();
  const [playIntegritySecretAction, setPlayIntegritySecretAction] = useState<WriteOnlySecretAction>("create");
  const [playIntegritySecretResolution, setPlayIntegritySecretResolution] = useState<WriteOnlySecretResolution>();
  const [upstreamSecretAction, setUpstreamSecretAction] = useState<WriteOnlySecretAction>("create");
  const [upstreamSecretResolution, setUpstreamSecretResolution] = useState<WriteOnlySecretResolution>();
  const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false); const [evidenceBusy, setEvidenceBusy] = useState(false); const [actionResumeNotice, setResumeNotice] = useState<string>(); const [formDirty, setFormDirty] = useState(false); const [persistedDocument, setPersistedDocument] = useState<string>();
  const [step, setStep] = useState(0);
  const [summary, setSummary] = useState<SetupSummary>({});
  const planForm = useRef<HTMLFormElement>(null);
  const organizationID = session.data?.session?.organization_id ?? "";
  const { can } = useCapabilities();
  const canConfigure = consoleCompatibility.mutationAllowed && can("activate_configuration");
  const canManageSecrets = consoleCompatibility.mutationAllowed && can("manage_secrets");
  const canTest = consoleCompatibility.mutationAllowed && can("run_self_tests");
  const canInspect = can("inspect_users");
  const firstRunNeedsSecretCapability = upstreamAuthenticationMode === "bearer" ||
    (platformScopeHasAndroid(platformScope) && playIntegrityCredentialSource === "service_account");
  const latestRevision = useQuery({
    ...latestConfigurationRevisionQueryOptions(selectedWorkspace?.environment?.id ?? ""),
    enabled: session.data?.mode === "configured" && Boolean(selectedWorkspace?.environment?.id)
  });
  const latest = latestRevision.data?.items[0];
  const serverWorkspace = latest && selectedWorkspace?.application && selectedWorkspace.environment
    ? resumeSetupPageWorkspace({
      applicationID: selectedWorkspace.application.id,
      applicationSlug: selectedWorkspace.application.slug,
      document: latest.document,
      environmentID: selectedWorkspace.environment.id,
      environmentSlug: selectedWorkspace.environment.slug
    })
    : undefined;
  const workspace = createdWorkspace ?? serverWorkspace;
  const document = editedDocument ?? (serverWorkspace && latest ? JSON.stringify(latest.document, null, 2) : "");
  const baselineDocument = persistedDocument ?? (serverWorkspace && latest ? canonicalConfigurationJSON(latest.document) : "");
  const documentDirty = Boolean(document) && comparableDocument(document) !== baselineDocument;
  useDirtyEditProtection(formDirty || documentDirty);
  const revision = appliedRevision ?? (serverWorkspace ? latest : undefined);
  const validation = appliedValidation ?? (serverWorkspace ? latest?.validation : undefined);
  const activeConfiguration = useQuery({
    enabled: session.data?.mode === "configured" && Boolean(workspace && revision?.state === "active"),
    queryFn: async () => {
      if (!workspace) throw new Error("Active configuration scope is unavailable.");
      const active = (await adminRequest(`/admin/v1/environments/${workspace.environmentID}/config`, RevisionSchema)).data;
      if (active.environment_id !== workspace.environmentID || active.state !== "active" || !active.activated_at) {
        throw new Error("The Admin API did not return the exact active revision for this environment.");
      }
      return active;
    },
    queryKey: ["environment", workspace?.environmentID ?? "", "setup-wizard", "active-configuration"],
    refetchOnMount: "always",
    retry: false,
    staleTime: 0
  });
  const active = activeConfiguration.data;
  const activeDocumentMatches = Boolean(active && revision && active.id === revision.id &&
    active.environment_id === workspace?.environmentID && canonicalConfigurationJSON(active.document) === comparableDocument(document));
  const activeConfigurationReady = revision?.state === "active" && Boolean(revision.activated_at) && validation?.valid === true &&
    active?.validation?.valid === true && activeDocumentMatches;
  const requestTarget = useMemo(() => active ? setupRequestTarget(JSON.stringify(active.document)) : undefined, [active]);
  const secrets = useQuery({
    enabled: Boolean(workspace?.environmentID) && (workspace?.upstreamAuthentication === "bearer" || workspace?.playIntegrityCredentialSource === "service_account"),
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/secrets", {
      environment_id: workspace?.environmentID ?? "",
      page_size: "200"
    }), SecretResourcePageSchema)).data,
    queryKey: ["environment", workspace?.environmentID ?? "", "setup-wizard", "secrets"],
    retry: false
  });
  const persistedSecretName = serverWorkspace && workspace?.upstreamAuthentication === "bearer"
    && secrets.data?.items.some((secret) => secret.name === workspace.plannedSecretName)
    ? workspace.plannedSecretName
    : undefined;
  const secretName = createdSecretName ?? persistedSecretName;
  const persistedPlayIntegritySecretName = serverWorkspace && workspace?.playIntegrityCredentialSource === "service_account"
    && secrets.data?.items.some((secret) => secret.name === workspace.plannedPlayIntegritySecretName)
    ? workspace.plannedPlayIntegritySecretName
    : undefined;
  const playIntegritySecretName = createdPlayIntegritySecretName ?? persistedPlayIntegritySecretName;
  const resumeNotice = actionResumeNotice ?? (serverWorkspace && latest
    ? `Resumed from server-owned revision ${latest.id}; no credential value was loaded into the browser.`
    : latest && selectedWorkspace?.application && selectedWorkspace.environment
      ? "The selected environment has a custom configuration outside the bounded first-run template. Continue in Configuration history instead of guessing setup values."
      : undefined);
  const credentialReady = (workspace?.upstreamAuthentication === "none" || Boolean(secretName)) &&
    (workspace?.playIntegrityCredentialSource !== "service_account" || Boolean(playIntegritySecretName));
  const verifiedRequest = observedRequest && matchingSetupRequest([observedRequest], workspace?.environmentID ?? "", requestTarget, active?.id);
  const verifiedTest = test?.config_revision_id === active?.id ? test : undefined;
  const snippets = workspace ? buildSetupSnippets(workspace) : [];
  if (session.data?.mode !== "configured") return <AccessRequired />;
  if (!workspace && selectedWorkspace?.environment && latestRevision.isPending) return <div className="lw-page-notice" role="status"><EmptyState icon="spinner" title="Resuming setup…" titleAs="h1">Loading the latest server-owned revision without restoring credential values.</EmptyState></div>;

  async function createWorkspace(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const playIntegritySecretInput = formElement.elements.namedItem("play_integrity_secret_value");
    const playIntegritySecretValue = playIntegritySecretInput instanceof HTMLInputElement ? playIntegritySecretInput.value : "";
    form.delete("play_integrity_secret_value");
    if (playIntegritySecretInput instanceof HTMLInputElement) playIntegritySecretInput.value = "";
    if (!canConfigure) return;
    setBusy(true); setProblem(undefined);
    try {
      const applicationSlug = String(form.get("application_slug")); const environmentSlug = String(form.get("environment_slug"));
      const upstreamAuthenticationValue = String(form.get("upstream_authentication"));
      if (upstreamAuthenticationValue !== "bearer" && upstreamAuthenticationValue !== "none") throw new Error("Choose an explicit upstream authentication mode.");
      const upstreamAuthentication: "bearer" | "none" = upstreamAuthenticationValue;
      const platformScopeValue = String(form.get("platform_scope"));
      if (!selectablePlatformScopes.includes(platformScopeValue as (typeof selectablePlatformScopes)[number])) throw new Error("Choose the exact client platform scope.");
      const selectedPlatformScope = platformScopeValue as (typeof selectablePlatformScopes)[number];
      const includesApple = platformScopeHasApple(selectedPlatformScope);
      const includesAndroid = platformScopeHasAndroid(selectedPlatformScope);
      const environmentKindValue = String(form.get("environment_kind"));
      if (environmentKindValue !== "development" && environmentKindValue !== "staging" && environmentKindValue !== "production") throw new Error("Choose the exact environment kind.");
      const environmentKind: "development" | "staging" | "production" = environmentKindValue;
      const applePolicy = includesApple ? applePolicyFromForm(form) : {};
      const cloudProject = includesAndroid ? safeCloudProjectNumber(form, "cloud_project") : undefined;
      const androidVersionCode = includesAndroid ? safeInteger(form, "android_version_code", 1) : undefined;
      const credentialSourceValue: "metadata" | "service_account" | undefined = includesAndroid
        ? String(form.get("play_integrity_credential_source")) as "metadata" | "service_account"
        : undefined;
      if (includesAndroid && credentialSourceValue !== "metadata" && credentialSourceValue !== "service_account") {
        throw new Error("Choose an exact Play Integrity credential source.");
      }
      const playSecretActionValue = String(form.get("play_integrity_secret_action") ?? "create");
      if (credentialSourceValue === "service_account" && playSecretActionValue !== "create" && playSecretActionValue !== "use_existing") {
        throw new Error("Choose whether to store a new Play Integrity credential or use an existing named secret.");
      }
      const selectedPlaySecretAction = playSecretActionValue as WriteOnlySecretAction;
      if (!canManageSecrets && (upstreamAuthentication === "bearer" || credentialSourceValue === "service_account")) {
        throw new Error("This first-run selection requires manage_secrets to verify exact secret metadata before any application or environment can be created.");
      }
      const plannedPlayIntegritySecretName = credentialSourceValue === "service_account"
        ? String(form.get("play_integrity_secret_name"))
        : undefined;
      const playIntegrityCredential = credentialSourceValue === "service_account"
        ? { type: "service_account" as const, secretName: plannedPlayIntegritySecretName as string }
        : { type: "metadata" as const };
      if (credentialSourceValue === "service_account" && selectedPlaySecretAction === "create" && !playIntegritySecretValue) {
        throw new Error("Enter the write-only Google service-account JSON credential.");
      }
      const plannedSecretName = String(form.get("upstream_secret_name"));
      const selfTestMaximumCostNanoUsd = 10_000_000;
      const template = buildFirstRunTemplate({ organization: String(form.get("organization_slug")), application: applicationSlug, environment: environmentSlug, environmentKind, firebaseProject: String(form.get("firebase_project")), platformScope: selectedPlatformScope, ...(includesApple ? { appIDPrefix: String(form.get("app_id_prefix")), bundleID: String(form.get("bundle_id")), bundleVersion: String(form.get("bundle_version")), ...applePolicy } : {}), ...(includesAndroid ? { packageName: String(form.get("package_name")), cloudProject, certificateDigest: String(form.get("certificate_digest")), androidVersionCode, playIntegrityCredential, allowPlayTestingResponses: form.get("allow_play_testing_responses") === "on" } : {}), ...(selectedPlatformScope === "web" ? { webOrigin: String(form.get("web_origin")), firebaseProjectNumber: String(form.get("firebase_project_number")), firebaseAppID: String(form.get("firebase_app_id")) } : {}), upstreamURL: String(form.get("upstream_url")), physicalModel: String(form.get("physical_model")), maximumFramingTokensPerRequest: safeInteger(form, "maximum_framing_tokens_per_request", 0), maximumFramingTokensPerMessage: safeInteger(form, "maximum_framing_tokens_per_message", 0), maximumContextTokens: safeInteger(form, "maximum_context_tokens", 1), authentication: upstreamAuthentication === "bearer" ? { type: "bearer", secretName: plannedSecretName } : { type: "none" }, inputNanoUsdPerMillion: safeInteger(form, "input_nano_usd_per_million", 0), outputNanoUsdPerMillion: safeInteger(form, "output_nano_usd_per_million", 0), requestNanoUsd: safeInteger(form, "request_nano_usd", 0), dailyInputTokenMaximum: safeInteger(form, "daily_input_token_maximum", 1), dailyOutputTokenMaximum: safeInteger(form, "daily_output_token_maximum", 1), dailyTotalTokenMaximum: safeInteger(form, "daily_total_token_maximum", 1), perRequestInputTokenMaximum: safeInteger(form, "per_request_input_token_maximum", 1) });
      const application = await findOrCreateApplication({ displayName: String(form.get("application_name")), organizationID, slug: applicationSlug });
      const environment = await findOrCreateEnvironment({ applicationID: application.id, displayName: String(form.get("environment_name")), kind: environmentKind, slug: environmentSlug });
      let resolvedPlaySecret: WriteOnlySecretResolution | undefined;
      if (credentialSourceValue === "service_account") {
        resolvedPlaySecret = await resolveWriteOnlySecret({
          action: selectedPlaySecretAction,
          environmentID: environment.id,
          name: plannedPlayIntegritySecretName as string,
          ...(selectedPlaySecretAction === "create" ? { value: playIntegritySecretValue } : {})
        });
      }
      const next: SetupPageWorkspace = { applicationID: application.id, applicationSlug, ...(cloudProject ? { cloudProjectNumber: String(cloudProject) } : {}), environmentID: environment.id, environmentSlug, upstreamAuthentication, plannedSecretName, ...(credentialSourceValue ? { playIntegrityCredentialSource: credentialSourceValue } : {}), ...(plannedPlayIntegritySecretName ? { plannedPlayIntegritySecretName } : {}), platformScope: selectedPlatformScope, selfTestMaximumCostNanoUsd };
      setWorkspace(next);
      setDocument(template);
      setPlayIntegritySecretResolution(resolvedPlaySecret);
      if (resolvedPlaySecret?.outcome === "confirmation_required") {
        setFormDirty(false);
        setResumeNotice(resolvedPlaySecret.reason === "already_exists"
          ? `Application ${application.id} and environment ${environment.id} were resolved. Play Integrity secret metadata already exists and requires explicit use-existing confirmation; no value was read or inferred.`
          : `Application ${application.id} and environment ${environment.id} were resolved. The Play Integrity secret create response was indeterminate, and exact metadata now requires explicit confirmation; no value was read or inferred.`);
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ["organization", organizationID, "applications", "workspace-switcher"] }),
          queryClient.invalidateQueries({ queryKey: ["application", application.id, "environments", "workspace-switcher"] })
        ]);
        return;
      }
      if (resolvedPlaySecret) setPlayIntegritySecretName(resolvedPlaySecret.metadata.name);
      const persisted = await createValidateActivate({ document: JSON.parse(template) as unknown, environmentID: environment.id, activate: false });
      setPersistedDocument(canonicalConfigurationJSON(JSON.parse(template) as unknown));
      setRevision(persisted.revision); setValidation(persisted.report); setObservedRequest(undefined); setTest(undefined);
      setFormDirty(false);
      setResumeNotice(`Application, environment, and resumable revision ${persisted.revision.id} resolved by stable server-owned identifiers.`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["organization", organizationID, "applications", "workspace-switcher"] }),
        queryClient.invalidateQueries({ queryKey: ["application", application.id, "environments", "workspace-switcher"] })
      ]);
      selectedWorkspace?.updateSearch({ application: application.slug, environment: environment.slug });
    } catch (error) { setProblem(error instanceof Error && error.message === "component_identifier_duplicate" ? { code: "component_identifier_duplicate", detail: "Apple bundle IDs and Android package names must be distinct when both root Component Definitions share one environment.", retryable: false, status: 0, title: "Component identifiers overlap" } : error instanceof Error && error.message.startsWith("app_attest_environment_mismatch") ? { code: "app_attest_environment_mismatch", detail: "Production defaults to production Apple App Attest. Accepting development or any requires the explicit dangerous-policy acknowledgment; distribution categories remain a separate selection.", retryable: false, status: 0, title: "App Attest environment mismatch" } : error instanceof Error && error.message === "application_slug_in_use" ? { code: "request_invalid", detail: "That application slug already exists with a different display name. Resume it using its exact server-owned values or choose another slug.", retryable: false, status: 0, title: "Application slug is already in use" } : error instanceof Error && error.message === "environment_slug_in_use" ? { code: "request_invalid", detail: "That environment slug already exists with a different name or kind. Resume it using its exact server-owned values or choose another slug.", retryable: false, status: 0, title: "Environment slug is already in use" } : error instanceof WriteOnlySecretResolutionError ? { code: error.code, detail: error.message, ...(error.operationId ? { operationId: error.operationId } : {}), retryable: error.code === "outcome_unknown", status: 0, title: "Play Integrity credential requires attention" } : problemFromError(error)); } finally { setBusy(false); }
  }

  async function createSecret(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const name = String(data.get("secret_name"));
    const value = String(data.get("secret_value"));
    data.delete("secret_value");
    const field = form.elements.namedItem("secret_value");
    if (field instanceof HTMLInputElement) field.value = "";
    if (!canManageSecrets || !workspace) return;
    setBusy(true); setProblem(undefined);
    try {
      if (upstreamSecretAction === "create" && !value) {
        throw new WriteOnlySecretResolutionError("not_found", "Enter the new write-only upstream credential.");
      }
      const resolved = await resolveWriteOnlySecret({
        action: upstreamSecretAction,
        environmentID: workspace.environmentID,
        name,
        ...(upstreamSecretAction === "create" ? { value } : {})
      });
      setUpstreamSecretResolution(resolved);
      if (resolved.outcome === "confirmation_required") return;
      setSecretName(resolved.metadata.name);
      if (resolved.outcome === "created") setUpstreamSecretAction("use_existing");
      const parsed = JSON.parse(document) as { spec: { upstreams: Array<Record<string, unknown>> } };
      const upstream = parsed.spec.upstreams[0];
      if (!upstream) throw new Error("The configuration has no upstream to receive this credential reference.");
      upstream.authentication = { type: "bearer", secretRef: `secret/${name}` };
      setDocument(JSON.stringify(parsed, null, 2)); setFormDirty(false); form.reset();
      await queryClient.invalidateQueries({ queryKey: ["environment", workspace.environmentID, "setup-wizard", "secrets"] });
    } catch (error) {
      setProblem(error instanceof WriteOnlySecretResolutionError
        ? { code: error.code, detail: error.message, ...(error.operationId ? { operationId: error.operationId } : {}), retryable: error.code === "outcome_unknown", status: 0, title: "Upstream credential requires attention" }
        : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function applyConfiguration(activate: boolean): Promise<void> {
    if (!canConfigure || !workspace || !credentialReady) return; setBusy(true); setProblem(undefined);
    try {
      const parsed = JSON.parse(document) as unknown; const result = await createValidateActivate({ document: parsed, environmentID: workspace.environmentID, activate });
      setRevision(result.revision); setValidation(result.report); setObservedRequest(undefined); setTest(undefined);
      if (activate && result.report.valid && result.revision.state === "active") {
        setDocument(JSON.stringify(result.revision.document, null, 2));
        setPersistedDocument(canonicalConfigurationJSON(result.revision.document));
        setFormDirty(false);
      }
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["environment", workspace.environmentID, "configuration-revisions", "latest"] }),
        queryClient.invalidateQueries({ queryKey: ["environment", workspace.environmentID, "setup-wizard", "active-configuration"] }),
        queryClient.invalidateQueries({ queryKey: ["application", selectedWorkspace?.application?.id ?? "", "environments", "workspace-switcher"] })
      ]);
    } catch (error) { setProblem(error instanceof SyntaxError ? { code: "invalid_json", detail: "The configuration editor must contain exactly one JSON object.", retryable: false, status: 0, title: "Invalid configuration JSON" } : problemFromError(error)); } finally { setBusy(false); }
  }

  async function runSelfTest(): Promise<void> {
    if (!canTest || !workspace || !active || !activeConfigurationReady) return; setBusy(true); setProblem(undefined); setTest(undefined);
    try {
      const before = (await adminRequest(`/admin/v1/environments/${workspace.environmentID}/config`, RevisionSchema)).data;
      if (before.environment_id !== workspace.environmentID || before.id !== active.id || before.state !== "active" ||
        before.validation?.valid !== true || canonicalConfigurationJSON(before.document) !== comparableDocument(document)) {
        throw new Error("The active configuration changed before the bounded self-test started.");
      }
      const result = (await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body: { kind: "upstream", environment_id: workspace.environmentID, config_revision_id: before.id, upstream: "primary", model: "assistant_default", max_cost_nano_usd: workspace.selfTestMaximumCostNanoUsd } })).data;
      if (result.environment_id !== workspace.environmentID || result.config_revision_id !== before.id) {
        throw new Error("The bounded self-test result did not match the exact requested configuration revision.");
      }
      const after = (await adminRequest(`/admin/v1/environments/${workspace.environmentID}/config`, RevisionSchema)).data;
      if (after.environment_id !== workspace.environmentID || after.id !== before.id || after.state !== "active" ||
        canonicalConfigurationJSON(after.document) !== canonicalConfigurationJSON(before.document)) {
        throw new Error("The active configuration changed while the bounded self-test was running.");
      }
      setTest(result);
    }
    catch (error) { setProblem(setupEvidenceProblem(error) ?? problemFromError(error)); } finally { setBusy(false); }
  }

  async function refreshVerifiedRequest(): Promise<void> {
    if (!workspace || !requestTarget || !activeConfigurationReady || !canInspect || !revision) return;
    setProblem(undefined); setEvidenceBusy(true); setObservedRequest(undefined);
    try {
      const readActive = async (): Promise<ConfigurationRevision> => {
        const current = (await adminRequest(`/admin/v1/environments/${workspace.environmentID}/config`, RevisionSchema)).data;
        const exactWorkspace = resumeSetupPageWorkspace({
          applicationID: workspace.applicationID,
          applicationSlug: workspace.applicationSlug,
          document: current.document,
          environmentID: workspace.environmentID,
          environmentSlug: workspace.environmentSlug
        });
        if (current.environment_id !== workspace.environmentID || current.state !== "active" || !current.activated_at ||
          current.validation?.valid !== true || !exactWorkspace) {
          throw new Error("The exact active first-run configuration is no longer available.");
        }
        return current;
      };
      const before = await readActive();
      const target = setupRequestTarget(JSON.stringify(before.document));
      if (!target || canonicalConfigurationJSON(before.document) !== comparableDocument(document)) {
        throw new Error("The editor no longer matches the exact active first-run configuration.");
      }
      const requests = (await adminRequest(queryPath("/admin/v1/requests", {
        environment_id: workspace.environmentID,
        feature: target.feature,
        page_size: setupRequestPageSize,
        sort: "started_at_desc",
        status: "succeeded"
      }), RequestPageSchema)).data;
      const after = await readActive();
      if (after.id !== before.id || canonicalConfigurationJSON(after.document) !== canonicalConfigurationJSON(before.document)) {
        throw new Error("The active configuration changed while request evidence was being inspected.");
      }
      const match = matchingSetupRequest(requests.items, workspace.environmentID, target, after.id);
      if (!match) {
        setProblem({
          code: "resource_not_found",
          detail: `No completed ${target.protocol} request for feature ${target.feature} and active revision ${after.id} is durably visible in this environment yet.`,
          retryable: true,
          status: 0,
          title: "Verified client request not observed"
        });
      } else {
        setObservedRequest(match);
      }
    } catch (error) {
      setProblem(setupEvidenceProblem(error) ?? problemFromError(error));
    } finally {
      setEvidenceBusy(false);
    }
  }

  /** Moves between plan steps. Leaving forward checks the current step's fields; the rail moves freely. */
  function showStep(next: number, validate: boolean): void {
    const form = planForm.current;
    if (validate && form) {
      const current = form.querySelector(`[data-step="${step}"]`);
      const invalid = current ? Array.from(current.querySelectorAll<HTMLInputElement | HTMLSelectElement>("input, select")).find((field) => !field.checkValidity()) : undefined;
      if (invalid) { invalid.reportValidity(); return; }
    }
    setStep(next);
  }

  function submitPlan(event: FormEvent<HTMLFormElement>): void {
    const form = event.currentTarget;
    const firstInvalid = PLAN_STEPS.findIndex((_, index) => Array.from(form.querySelectorAll<HTMLInputElement | HTMLSelectElement>(`[data-step="${index}"] input, [data-step="${index}"] select`)).some((field) => !field.checkValidity()));
    if (firstInvalid >= 0) {
      event.preventDefault();
      setStep(firstInvalid);
      window.setTimeout(() => Array.from(form.querySelectorAll<HTMLInputElement | HTMLSelectElement>(`[data-step="${firstInvalid}"] input, [data-step="${firstInvalid}"] select`)).find((field) => !field.checkValidity())?.reportValidity(), 0);
      return;
    }
    void createWorkspace(event);
  }

  const buildDone = [Boolean(credentialReady), activeConfigurationReady, verifiedTest?.state === "passed", activeConfigurationReady && snippets.length > 0, Boolean(verifiedRequest)];
  const summaryRows: Array<[string, string | undefined]> = workspace
    ? [["Application", workspace.applicationSlug], ["Environment", workspace.environmentSlug], ["Platforms", platformScopeLabel(workspace.platformScope)], ["Credential", workspace.upstreamAuthentication === "none" ? "No authentication" : secretName ? `secret/${secretName}` : undefined], ["Live revision", activeConfigurationReady && revision ? `v${revision.version}` : undefined], ["Self-test", verifiedTest?.state], ["Client request", verifiedRequest?.id]]
    : [["Application", summary.application], ["Environment", summary.environment], ["Sign-in", summary.identity], ["Platforms", summary.platform], ["AI connection", summary.upstream], ["Model", summary.model], ["Pricing", summary.pricing]];

  return <div className="lw-page">
    <PageHeader description="Create an application and environment, connect an AI provider, publish a first configuration and confirm a real client request. Everything goes through the Admin API." title="Set up an application" />
    <div className="lw-setup">
      <nav aria-label="Setup steps" className="lw-setup-steps">
        <h2>Plan</h2>
        <ol aria-label="Setup progress">
          {PLAN_STEPS.map((item, index) => {
            const done = Boolean(workspace);
            return <li data-state={done ? "done" : index === step ? "current" : "todo"} key={item.title}>
              <button aria-current={!workspace && index === step ? "step" : undefined} aria-label={`Step ${index + 1}: ${item.title}`} className={cx("lw-setup-step", !workspace && index === step && "is-current", done && "is-done")} disabled={Boolean(workspace)} onClick={() => showStep(index, false)} type="button">
                <span className="lw-setup-step__n">{done ? <Icon name="check" size={12} /> : index + 1}</span>
                <span className="lw-setup-step__t"><strong>{item.title}</strong><span>{item.detail}</span></span>
              </button>
            </li>;
          })}
        </ol>
        <p className="lw-setup-steps__group">Build</p>
        <ol aria-label="Build progress">
          {BUILD_STEPS.map((item, index) => <li data-state={buildDone[index] ? "done" : "todo"} key={item.title}>
            <a aria-disabled={!workspace} className={cx("lw-setup-step", buildDone[index] && "is-done")} href={workspace ? `#${item.anchor}` : undefined}>
              <span className="lw-setup-step__n">{buildDone[index] ? <Icon name="check" size={12} /> : PLAN_STEPS.length + index + 1}</span>
              <span className="lw-setup-step__t"><strong>{item.title}</strong><span>{item.detail}</span></span>
            </a>
          </li>)}
        </ol>
      </nav>

      <div className="lw-setup-main">
        <ProblemNotice problem={problem} />
        {latestRevision.error ? <ProblemNotice problem={problemFromError(latestRevision.error)} /> : null}
        {activeConfiguration.error ? <ProblemNotice problem={problemFromError(activeConfiguration.error)} /> : null}
        {secrets.error ? <ProblemNotice problem={problemFromError(secrets.error)} /> : null}
        {resumeNotice ? <Notice title="Resumable setup">{resumeNotice}</Notice> : null}
        {!workspace ? canConfigure ? (
          <form className="lw-form lw-setup-form" noValidate onChange={(event) => { setFormDirty(true); setSummary(readSetupSummary(event.currentTarget)); }} onSubmit={submitPlan} ref={planForm}>
            <p className="lw-setup-form__title">Step {step + 1} of {PLAN_STEPS.length} · {PLAN_STEPS[step]?.title}</p>
            <div data-step="0" hidden={step !== 0}>
              <fieldset><legend>Application and environment</legend><p>The owner and organization already exist. Name the application your users install and the environment it talks to.</p>
                <div className="lw-form-grid"><label>Organization slug<input defaultValue={selectedWorkspace?.organization?.slug} name="organization_slug" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Application name<input defaultValue={selectedWorkspace?.application?.display_name} name="application_name" required /></label><label>Application slug<input defaultValue={selectedWorkspace?.application?.slug} name="application_slug" pattern="[a-z][a-z0-9-]{1,62}" required /></label></div>
                <div className="lw-form-grid"><label>Environment name<input defaultValue={selectedWorkspace?.environment?.display_name ?? "Production"} name="environment_name" required /></label><label>Environment slug<input defaultValue={selectedWorkspace?.environment?.slug ?? "production"} name="environment_slug" pattern="[a-z][a-z0-9-]{1,62}" required /></label><label>Environment kind<select value={environmentKindInput} onChange={(event) => setEnvironmentKindInput(event.target.value as NativeTemplateInput["environmentKind"])} name="environment_kind" required><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option></select></label></div>
              </fieldset>
            </div>
            <div data-step="1" hidden={step !== 1}>
              <fieldset><legend>Sign-in and client platforms</legend>
                <div className="lw-form-grid"><label>Firebase project ID<input name="firebase_project" pattern="[a-z][a-z0-9-]{4,28}[a-z0-9]" required /><small>This configures user authentication independently from client proof.</small></label><label>Platform scope<select name="platform_scope" onChange={(event) => setPlatformScope(event.target.value as (typeof selectablePlatformScopes)[number])} required value={platformScope}><option value="ios">iOS only (Swift)</option><option value="android">Android only (Kotlin)</option><option value="web">Web only (JavaScript)</option><option value="react_native_ios">React Native on iOS only</option><option value="react_native_android">React Native on Android only</option><option value="react_native_both">React Native on iOS and Android</option></select><small>The generated policy contains only these runtime platform keys. You can add another surface later through Client Trust.</small></label></div>
              </fieldset>
              {platformScopeHasApple(platformScope) ? <fieldset><legend>Apple App Attest</legend><p>Select accepted Apple attestation environments separately from the build distribution categories.</p><div className="lw-form-grid"><label>App ID prefix<input name="app_id_prefix" pattern="[A-Z0-9]{1,64}" required /></label><label>Bundle ID<input maxLength={255} minLength={3} name="bundle_id" pattern="[A-Za-z0-9](?:[A-Za-z0-9.-]{1,253}[A-Za-z0-9])" required /></label><label>Allowed CFBundleVersion (build number)<input maxLength={128} name="bundle_version" pattern="[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?" placeholder="1" required /><small>Use the exact CFBundleVersion/CURRENT_PROJECT_VERSION, not CFBundleShortVersionString/MARKETING_VERSION.</small></label></div><ApplePolicyFields environmentKind={environmentKindInput} /></fieldset> : null}
              {platformScopeHasAndroid(platformScope) ? <fieldset><legend>Google Play Integrity</legend><PlayTestingField environmentKind={environmentKindInput} /><p>Pin the exact Android build. Use attached Google metadata only on a Google Cloud workload with the Play Integrity scope; Docker Compose and other hosts require a write-only service-account JSON secret.</p><div className="lw-form-grid"><label>Package name<input maxLength={255} minLength={3} name="package_name" pattern="[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+" required /></label><label>Cloud project number<input max={Number.MAX_SAFE_INTEGER} min={100000} name="cloud_project" required type="number" /></label><label>Certificate SHA-256 digest (base64url)<input name="certificate_digest" pattern="[A-Za-z0-9_-]{43}=?" required /></label><label>Exact version code<input min={1} name="android_version_code" required type="number" /></label><label>Server credential source<select name="play_integrity_credential_source" onChange={(event) => setPlayIntegrityCredentialSource(event.target.value as "metadata" | "service_account")} required value={playIntegrityCredentialSource}><option value="metadata">Attached Google Cloud service identity</option><option value="service_account">Write-only service-account JSON secret</option></select></label>{playIntegrityCredentialSource === "service_account" ? <><label>Credential operation<select aria-label="Play credential operation" name="play_integrity_secret_action" onChange={(event) => setPlayIntegritySecretAction(event.target.value as WriteOnlySecretAction)} value={playIntegritySecretAction}><option value="create">Store new service-account JSON</option><option value="use_existing">Use existing named secret</option></select></label><label>Play credential secret name<input defaultValue="play_integrity_service_account" name="play_integrity_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Google service-account JSON (write-only)<input autoComplete="new-password" disabled={playIntegritySecretAction === "use_existing" || !canManageSecrets} name="play_integrity_secret_value" required={playIntegritySecretAction === "create"} type="password" /></label></> : null}</div>{playIntegrityCredentialSource === "service_account" ? <small>Existing-secret mode confirms only exact metadata in the resolved environment; the Console never reads or infers the service-account JSON.</small> : null}</fieldset> : null}
              {platformScope === "web" ? <fieldset><legend>Firebase App Check for Web</legend><p>This establishes browser risk verification, not native hardware-backed device proof.</p><div className="lw-form-grid"><label>Exact browser origin<input defaultValue="https://app.example.com" name="web_origin" required type="url" /></label><label>Firebase project number<input inputMode="numeric" name="firebase_project_number" pattern="[1-9][0-9]{0,19}" required /></label><label>Firebase web app ID<input maxLength={256} minLength={5} name="firebase_app_id" pattern="[!-~]{5,256}" required /></label></div></fieldset> : null}
            </div>
            <div data-step="2" hidden={step !== 2}>
              <fieldset><legend>Upstream target and authentication</legend><p>The production default keeps the provider credential server-side. Select no authentication only for a controlled upstream that genuinely requires none.</p><div className="lw-form-grid"><label>Upstream HTTPS base URL<input defaultValue="https://api.openai.com/v1" name="upstream_url" pattern="https://.*" required type="url" /></label><label>Authentication mode<select name="upstream_authentication" onChange={(event) => setUpstreamAuthenticationMode(event.target.value as "bearer" | "none")} required value={upstreamAuthenticationMode}><option value="bearer">Bearer secret (recommended)</option><option value="none">No authentication (explicit test upstream)</option></select></label><label>Planned secret name<input defaultValue="primary_api_key" name="upstream_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label></div></fieldset>
              <fieldset><legend>Trusted input accounting</legend><p>Review these operator-owned bounds against the exact physical model before activation. The starter route accepts bounded text-only OpenAI Responses requests.</p><div className="lw-form-grid"><label>Physical upstream model<input defaultValue="gpt-5-mini" name="physical_model" required /></label><label>Framing tokens per request<input defaultValue={8} min={0} name="maximum_framing_tokens_per_request" required type="number" /></label><label>Framing tokens per input item<input defaultValue={4} min={0} name="maximum_framing_tokens_per_message" required type="number" /></label><label>Maximum model context tokens<input defaultValue={128000} min={4096} name="maximum_context_tokens" required type="number" /></label></div></fieldset>
            </div>
            <div data-step="3" hidden={step !== 3}>
              <fieldset><legend>Operator-reviewed pricing</legend><p>Enter the current nano-USD rates for the exact physical model. Latchway binds this revision to reservation and settlement evidence; it does not trust client-supplied prices. The first-run self-test uses a fixed 10,000,000 nano-USD ($0.01) maximum total cost.</p><div className="lw-form-grid"><label>Input price (nano-USD per million tokens)<input min={0} name="input_nano_usd_per_million" required type="number" /></label><label>Output price (nano-USD per million tokens)<input min={0} name="output_nano_usd_per_million" required type="number" /></label><label>Per-request price (nano-USD)<input defaultValue={0} min={0} name="request_nano_usd" required type="number" /></label></div></fieldset>
              <fieldset><legend>Hard token limits</legend><p>These limits are enforced from the server-rewritten request and provider-reported settlement. The total-token calendar bound covers input plus output.</p><div className="lw-form-grid"><label>Daily input-token maximum<input defaultValue={100000} min={1} name="daily_input_token_maximum" required type="number" /></label><label>Daily output-token maximum<input defaultValue={100000} min={1} name="daily_output_token_maximum" required type="number" /></label><label>Daily total-token maximum<input defaultValue={200000} min={1} name="daily_total_token_maximum" required type="number" /></label><label>Per-request input-token maximum<input defaultValue={20000} min={1} name="per_request_input_token_maximum" required type="number" /></label></div></fieldset>
            </div>
            <div data-step="4" hidden={step !== 4}>
              <fieldset><legend>Review and create</legend><p>Creating resolves the application and environment by slug (reusing exact matches), stores any Play Integrity credential, and saves a validated draft revision. Nothing goes live until you publish it in the next part.</p>
                <dl className="lw-effective__facts">{summaryRows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? "Not set"}</dd></div>)}</dl>
              </fieldset>
              {!canManageSecrets && firstRunNeedsSecretCapability ? <Notice title="Secret management required" tone="warning">Your current session cannot store the server-held credential required by this selection. Choose an explicit no-auth upstream and attached Google metadata where applicable, or use an administrator with <code className="lw-code-inline">manage_secrets</code>.</Notice> : null}
            </div>
            <div className="lw-form-foot">
              {step > 0 ? <Button key="back" onClick={() => showStep(step - 1, false)}>Back</Button> : <span />}
              <div className="lw-form-foot__end">
                {step < PLAN_STEPS.length - 1
                  ? <Button key="continue" onClick={() => showStep(step + 1, true)} variant="primary">Continue</Button>
                  : <Button key="create" disabled={!canConfigure || (!canManageSecrets && firstRunNeedsSecretCapability)} loading={busy} type="submit" variant="primary">{busy ? "Creating…" : "Create application and environment"}</Button>}
              </div>
            </div>
          </form>
        ) : <Notice icon="lock" title="Read-only safe mode" tone="warning">First-run setup inputs are unavailable until Console compatibility and configuration authority are restored.</Notice> : <>
          <Card description={workspace.upstreamAuthentication === "bearer" ? "The generated upstream requires this server-held secret. A new value is sent once and cleared immediately. Existing-secret mode confirms exact environment/name metadata without reading or inferring its value." : undefined} title={<span id="setup-credential">Write-only upstream credential</span>}>
            {workspace.upstreamAuthentication === "bearer" ? canManageSecrets ? <form className="lw-form" onChange={() => setFormDirty(true)} onSubmit={(event) => void createSecret(event)}><div className="lw-form-grid lw-form-grid--end"><label>Credential operation<select aria-label="Upstream credential operation" name="secret_action" onChange={(event) => setUpstreamSecretAction(event.target.value as WriteOnlySecretAction)} value={upstreamSecretAction}><option value="create">Store new secret value</option><option value="use_existing">Use existing named secret</option></select></label><label>Secret name<input defaultValue={workspace.plannedSecretName} name="secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Secret value<input autoComplete="off" disabled={upstreamSecretAction === "use_existing"} name="secret_value" required={upstreamSecretAction === "create"} type="password" /></label><Button disabled={busy || secrets.isPending || Boolean(secretName)} type="submit" variant="primary">{secretName ? "Credential added" : secrets.isPending ? "Checking credential…" : upstreamSecretAction === "create" ? "Add credential" : "Confirm existing credential"}</Button></div></form> : <Notice title="Secret input unavailable" tone="warning">Write-only credential input is removed until Console compatibility and secret-management authority are restored.</Notice> : <Notice title="No-auth upstream">You explicitly selected a no-auth upstream. Do not use this mode for OpenAI or another target that requires a credential.</Notice>}
          </Card>
          {upstreamSecretResolution?.outcome === "confirmation_required" ? <Notice action={<Button onClick={() => setUpstreamSecretAction("use_existing")} size="sm">Use this existing named upstream secret on next review</Button>} title="Confirm existing upstream credential metadata" tone="warning"><code className="lw-code-inline">secret/{upstreamSecretResolution.metadata.name}</code> exists in environment <code className="lw-code-inline">{upstreamSecretResolution.metadata.environment_id}</code>. The Console cannot read or infer its value. {upstreamSecretResolution.reason === "create_response_indeterminate" ? "The create response was indeterminate. Confirm use only if this is the intended named credential; otherwise rotate it from Secrets." : "The name existed before a new value was sent. Confirm use only if this is the intended credential; otherwise rotate it from Secrets."}{upstreamSecretResolution.operationId ? ` Preserve operation ${upstreamSecretResolution.operationId} for audit correlation.` : ""}</Notice> : null}
          {playIntegritySecretResolution?.outcome === "confirmation_required" ? <Notice action={<Button onClick={() => { setPlayIntegritySecretName(playIntegritySecretResolution.metadata.name); setPlayIntegritySecretResolution({ metadata: playIntegritySecretResolution.metadata, outcome: "existing" }); setResumeNotice(`Explicitly accepted existing Play Integrity metadata secret/${playIntegritySecretResolution.metadata.name}; no value was read or inferred.`); }} size="sm">Use this existing named Play secret</Button>} title="Confirm existing Play Integrity credential metadata" tone="warning"><code className="lw-code-inline">secret/{playIntegritySecretResolution.metadata.name}</code> exists in environment <code className="lw-code-inline">{playIntegritySecretResolution.metadata.environment_id}</code>. The Console cannot read or infer its service-account JSON. {playIntegritySecretResolution.reason === "create_response_indeterminate" ? "The create response was indeterminate. Confirm use only if this is the intended named credential; otherwise rotate it from Secrets." : "The name existed before a new value was sent. Confirm use only if this is the intended credential; otherwise rotate it from Secrets."}{playIntegritySecretResolution.operationId ? ` Preserve operation ${playIntegritySecretResolution.operationId} for audit correlation.` : ""}</Notice> : null}
          <Card description={`The generated document includes only the ${platformScopeLabel(workspace.platformScope)} root Component Definition${platformScopePlatforms[workspace.platformScope].length > 1 ? "s" : ""}, exact platform identifiers, required verification policy, and assistant feature grant. Unselected platform evidence is absent; every area remains server validated.`} footer={<div className="lw-row lw-row--wrap"><Button disabled={!canConfigure || busy || !credentialReady} onClick={() => void applyConfiguration(false)} size="sm">Validate and plan only</Button><Button disabled={!canConfigure || busy || !credentialReady} onClick={() => void applyConfiguration(true)} size="sm" variant="primary">Validate and activate with ETag</Button></div>} title={<span id="setup-publish">Configuration document</span>}>
            <div className="lw-form lw-stack"><textarea aria-label="Full configuration JSON" className="lw-code-editor" onChange={(event) => setDocument(event.target.value)} rows={32} spellCheck={false} value={document} /><ValidationResult report={validation} />{revision ? <p className="lw-note">Revision <code className="lw-code-inline">{revision.id}</code> is <strong>{revision.state}</strong>.</p> : null}</div>
          </Card>
          <Card description="Sends one non-streaming and one streaming Responses request with a one-token clamp, trusted input preflight, an operator cost ceiling and usage reconciliation. The server binds every dispatch and result to the exact active revision." footer={<Button disabled={!canTest || busy || !credentialReady || !activeConfigurationReady} onClick={() => void runSelfTest()} size="sm" variant="primary">Run bounded upstream self-test</Button>} title={<span id="setup-self-test">Bounded upstream self-test</span>}>
            {verifiedTest ? <p className="lw-note">Self-test <code className="lw-code-inline">{verifiedTest.id}</code>: <strong>{verifiedTest.state}</strong></p> : <p className="lw-note lw-secondary">{activeConfigurationReady ? "Ready to run against the active revision." : "Publish the configuration first."}</p>}
          </Card>
          <Card description="These snippets identify only your gateway and client-visible Latchway configuration; they contain no provider key. Use the generated application resource ID shown, not the application slug." title={<span id="setup-snippets">Platform SDK snippets</span>}>
            <div className="lw-stack">{snippets.map((snippet) => <div className="lw-snippet" key={snippet.label}><h3>{snippet.label}</h3><pre>{snippet.code}</pre></div>)}</div>
          </Card>
          <Card description="Completion comes only from a succeeded, completed request in this environment whose feature, protocol and configuration revision match unchanged active-configuration reads before and after the check. The latchway develop sample runner and official SDK requests both create this evidence." footer={<div className="lw-row lw-row--wrap"><Button disabled={!canInspect || !activeConfigurationReady || !requestTarget} loading={evidenceBusy} onClick={() => void refreshVerifiedRequest()} size="sm" variant="primary">{evidenceBusy ? "Checking durable requests…" : "Check durable client request"}</Button><a className={buttonClass({ size: "sm" })} href={`/upstreams${window.location.search}`}>Open AI Connections</a><a className={buttonClass({ size: "sm" })} href={`/requests${window.location.search}`}>Open Requests</a></div>} title={<span id="setup-verify">Send and verify a client request</span>}>
            {!canInspect ? <Notice title="Request inspection unavailable" tone="warning">Your current capability set cannot read durable request metadata, so this step remains incomplete.</Notice> : null}
            {verifiedRequest ? <p className="lw-note">Verified durable request <code className="lw-code-inline">{verifiedRequest.id}</code>: <strong>{verifiedRequest.status}</strong> for {verifiedRequest.feature} via {verifiedRequest.selected_physical_model ?? verifiedRequest.attempts.at(-1)?.model ?? "recorded model"}.</p> : <p className="lw-note lw-secondary">No verified request yet.</p>}
          </Card>
        </>}
      </div>

      <aside aria-label="Setup summary" className="lw-setup-sum">
        <h3>{workspace ? "Your setup" : "So far"}</h3>
        <ul>{summaryRows.map(([label, value]) => <li className={cx("lw-setup-sum__row", value && "is-done")} key={label}><Icon name={value ? "check" : "minus"} size={12} /><span><strong>{label}</strong><br /><span className="lw-secondary">{value ?? "Not set"}</span></span></li>)}</ul>
        <p className="lw-setup-sum__foot">Secret values never appear here. They're sent once and cleared.</p>
      </aside>
    </div>
  </div>;
}

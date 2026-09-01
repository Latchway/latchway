import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useMemo, useState } from "react";

import {
  adminRequest,
  RevisionSchema,
  SecretMetadataSchema,
  SelfTestSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation,
  type SelfTestRun,
  queryPath
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { latestConfigurationRevisionQueryOptions } from "../api/workspace";
import { SecretResourcePageSchema } from "../api/resources";
import { ConfigurationRouteSearchSchema } from "../app/route-search";
import { useDirtyEditProtection } from "../app/use-dirty-edit-protection";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { buildNativeSnippets, buildNativeTemplate } from "./native-template";
import { createValidateActivate, findOrCreateApplication, findOrCreateEnvironment } from "./setup-wizard-api";
import { canonicalConfigurationJSON, resumeSetupWorkspace, type SetupWizardWorkspace } from "./setup-wizard-state";

const environmentPattern = "env_[A-Za-z0-9_-]{16,128}";

function safeInteger(form: FormData, name: string, minimum: number): number {
  const value = Number(form.get(name));
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be a safe integer greater than or equal to ${minimum}.`);
  return value;
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
}

function ValidationResult({ report }: { report?: ConfigurationValidation }) {
  return report ? <section className={`validation-card ${report.valid ? "validation-card--valid" : "validation-card--invalid"}`}>
    <h3>{report.valid ? "Configuration is valid" : "Configuration needs changes"}</h3>
    <p>Checked {new Date(report.checked_at).toLocaleString()}</p>
    {report.issues.length ? <ul>{report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code>{issue.path}</code> — {issue.message}</li>)}</ul> : <p>No validation issues.</p>}
  </section> : null;
}

function comparableDocument(text: string): string {
  try {
    return canonicalConfigurationJSON(JSON.parse(text) as unknown);
  } catch {
    return text;
  }
}

export function SetupWizardPage() {
  const session = useConsoleSession();
  const selectedWorkspace = useOptionalWorkspace();
  const queryClient = useQueryClient();
  const [createdWorkspace, setWorkspace] = useState<SetupWizardWorkspace>();
  const [editedDocument, setDocument] = useState<string>(); const [createdSecretName, setSecretName] = useState<string>();
  const [appliedRevision, setRevision] = useState<ConfigurationRevision>(); const [appliedValidation, setValidation] = useState<ConfigurationValidation>(); const [test, setTest] = useState<SelfTestRun>();
  const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false); const [actionResumeNotice, setResumeNotice] = useState<string>(); const [formDirty, setFormDirty] = useState(false); const [persistedDocument, setPersistedDocument] = useState<string>();
  const organizationID = session.data?.session?.organization_id ?? "";
  const canConfigure = session.data?.session?.capabilities.includes("activate_configuration") ?? false;
  const canManageSecrets = session.data?.session?.capabilities.includes("manage_secrets") ?? false;
  const canTest = session.data?.session?.capabilities.includes("run_self_tests") ?? false;
  const latestRevision = useQuery({
    ...latestConfigurationRevisionQueryOptions(selectedWorkspace?.environment?.id ?? ""),
    enabled: session.data?.mode === "configured" && Boolean(selectedWorkspace?.environment?.id)
  });
  const latest = latestRevision.data?.items[0];
  const serverWorkspace = latest && selectedWorkspace?.application && selectedWorkspace.environment
    ? resumeSetupWorkspace({
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
  const secrets = useQuery({
    enabled: workspace?.upstreamAuthentication === "bearer" && Boolean(workspace.environmentID),
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/secrets", {
      environment_id: workspace?.environmentID ?? "",
      page_size: "200"
    }), SecretResourcePageSchema)).data,
    queryKey: ["environment", workspace?.environmentID ?? "", "setup-wizard", "secrets"],
    retry: false
  });
  const persistedSecretName = workspace?.upstreamAuthentication === "bearer"
    && secrets.data?.items.some((secret) => secret.name === workspace.plannedSecretName)
    ? workspace.plannedSecretName
    : undefined;
  const secretName = createdSecretName ?? persistedSecretName;
  const resumeNotice = actionResumeNotice ?? (serverWorkspace && latest
    ? `Resumed from server-owned revision ${latest.id}; no credential value was loaded into the browser.`
    : latest && selectedWorkspace?.application && selectedWorkspace.environment
      ? "The selected environment has a custom configuration outside the bounded first-run template. Continue in Configuration history instead of guessing setup values."
      : undefined);
  const credentialReady = workspace?.upstreamAuthentication === "none" || Boolean(secretName);
  const completed = useMemo(() => [true, true, Boolean(workspace), Boolean(workspace), Boolean(document), Boolean(document), Boolean(credentialReady), Boolean(document), Boolean(document), Boolean(document), test?.state === "passed", Boolean(revision?.activated_at), false], [credentialReady, document, revision, test, workspace]);
  const snippets = workspace ? buildNativeSnippets(workspace) : undefined;
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to continue setup.</h1></section>;
  if (!workspace && selectedWorkspace?.environment && latestRevision.isPending) return <section className="empty-state" role="status"><h1>Resuming setup…</h1><p>Loading the latest server-owned revision without restoring credential values.</p></section>;

  async function createWorkspace(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const applicationSlug = String(form.get("application_slug")); const environmentSlug = String(form.get("environment_slug"));
      const cloudProject = safeInteger(form, "cloud_project", 1);
      const upstreamAuthenticationValue = String(form.get("upstream_authentication"));
      if (upstreamAuthenticationValue !== "bearer" && upstreamAuthenticationValue !== "none") throw new Error("Choose an explicit upstream authentication mode.");
      const upstreamAuthentication: "bearer" | "none" = upstreamAuthenticationValue;
      const clientSurfaceValue = String(form.get("client_surface"));
      if (clientSurfaceValue !== "native" && clientSurfaceValue !== "react_native") throw new Error("Choose the exact mobile SDK surface.");
      const clientSurface: "native" | "react_native" = clientSurfaceValue;
      const environmentKindValue = String(form.get("environment_kind"));
      if (environmentKindValue !== "development" && environmentKindValue !== "staging" && environmentKindValue !== "production") throw new Error("Choose the exact environment kind.");
      const environmentKind: "development" | "staging" | "production" = environmentKindValue;
      const appleDistributionValue = String(form.get("apple_distribution"));
      if (appleDistributionValue !== "development" && appleDistributionValue !== "testflight" && appleDistributionValue !== "app_store" && appleDistributionValue !== "ad_hoc_enterprise") throw new Error("Choose the exact Apple signing or distribution method.");
      const appleDistribution: "development" | "testflight" | "app_store" | "ad_hoc_enterprise" = appleDistributionValue;
      const plannedSecretName = String(form.get("upstream_secret_name"));
      const selfTestMaximumCostNanoUsd = safeInteger(form, "self_test_maximum_cost_nano_usd", 1);
      const template = buildNativeTemplate({ organization: String(form.get("organization_slug")), application: applicationSlug, environment: environmentSlug, environmentKind, firebaseProject: String(form.get("firebase_project")), appIDPrefix: String(form.get("app_id_prefix")), bundleID: String(form.get("bundle_id")), bundleVersion: String(form.get("bundle_version")), appleDistribution, packageName: String(form.get("package_name")), clientSurface, cloudProject, certificateDigest: String(form.get("certificate_digest")), upstreamURL: String(form.get("upstream_url")), physicalModel: String(form.get("physical_model")), maximumFramingTokensPerRequest: safeInteger(form, "maximum_framing_tokens_per_request", 0), maximumFramingTokensPerMessage: safeInteger(form, "maximum_framing_tokens_per_message", 0), maximumContextTokens: safeInteger(form, "maximum_context_tokens", 1), authentication: upstreamAuthentication === "bearer" ? { type: "bearer", secretName: plannedSecretName } : { type: "none" }, inputNanoUsdPerMillion: safeInteger(form, "input_nano_usd_per_million", 0), outputNanoUsdPerMillion: safeInteger(form, "output_nano_usd_per_million", 0), requestNanoUsd: safeInteger(form, "request_nano_usd", 0), dailyInputTokenMaximum: safeInteger(form, "daily_input_token_maximum", 1), dailyOutputTokenMaximum: safeInteger(form, "daily_output_token_maximum", 1), dailyTotalTokenMaximum: safeInteger(form, "daily_total_token_maximum", 1), perRequestInputTokenMaximum: safeInteger(form, "per_request_input_token_maximum", 1) });
      const application = await findOrCreateApplication({ displayName: String(form.get("application_name")), organizationID, slug: applicationSlug });
      const environment = await findOrCreateEnvironment({ applicationID: application.id, displayName: String(form.get("environment_name")), kind: environmentKind, slug: environmentSlug });
      const next = { applicationID: application.id, applicationSlug, clientSurface, cloudProjectNumber: String(cloudProject), environmentID: environment.id, environmentSlug, upstreamAuthentication, plannedSecretName, selfTestMaximumCostNanoUsd }; setWorkspace(next);
      setDocument(template);
      setFormDirty(false);
      setResumeNotice("Application and environment resolved by stable slugs. Repeating this step reuses the exact matching resources.");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["organization", organizationID, "applications", "workspace-switcher"] }),
        queryClient.invalidateQueries({ queryKey: ["application", application.id, "environments", "workspace-switcher"] })
      ]);
    } catch (error) { setProblem(error instanceof Error && error.message === "component_identifier_duplicate" ? { code: "component_identifier_duplicate", detail: "Apple bundle IDs and Android package names must be distinct when both root Component Definitions share one environment.", retryable: false, status: 0, title: "Component identifiers overlap" } : error instanceof Error && error.message === "app_attest_environment_mismatch" ? { code: "app_attest_environment_mismatch", detail: "A development-signed App Attest build requires a development or staging Latchway environment. Production environments require TestFlight, App Store, ad hoc, or enterprise distribution.", retryable: false, status: 0, title: "App Attest environment mismatch" } : error instanceof Error && error.message === "application_slug_in_use" ? { code: "request_invalid", detail: "That application slug already exists with a different display name. Resume it using its exact server-owned values or choose another slug.", retryable: false, status: 0, title: "Application slug is already in use" } : error instanceof Error && error.message === "environment_slug_in_use" ? { code: "request_invalid", detail: "That environment slug already exists with a different name or kind. Resume it using its exact server-owned values or choose another slug.", retryable: false, status: 0, title: "Environment slug is already in use" } : problemFromError(error)); } finally { setBusy(false); }
  }

  async function createSecret(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!workspace) return; setBusy(true); setProblem(undefined); const form = event.currentTarget; const data = new FormData(form);
    try {
      const name = String(data.get("secret_name"));
      await adminRequest("/admin/v1/secrets", SecretMetadataSchema, { method: "POST", body: { environment_id: workspace.environmentID, name, value: String(data.get("secret_value")) } });
      setSecretName(name);
      const parsed = JSON.parse(document) as { spec: { upstreams: Array<Record<string, unknown>> } };
      const upstream = parsed.spec.upstreams[0];
      if (!upstream) throw new Error("The configuration has no upstream to receive this credential reference.");
      upstream.authentication = { type: "bearer", secretRef: `secret/${name}` };
      setDocument(JSON.stringify(parsed, null, 2)); setFormDirty(false); form.reset();
      await queryClient.invalidateQueries({ queryKey: ["environment", workspace.environmentID, "setup-wizard", "secrets"] });
    } catch (error) { setProblem(problemFromError(error)); const field = form.elements.namedItem("secret_value"); if (field instanceof HTMLInputElement) field.value = ""; } finally { setBusy(false); }
  }

  async function applyConfiguration(activate: boolean): Promise<void> {
    if (!workspace || !credentialReady) return; setBusy(true); setProblem(undefined);
    try {
      const parsed = JSON.parse(document) as unknown; const result = await createValidateActivate({ document: parsed, environmentID: workspace.environmentID, activate });
      setRevision(result.revision); setValidation(result.report);
      if (activate && result.report.valid && result.revision.state === "active") {
        setDocument(JSON.stringify(result.revision.document, null, 2));
        setPersistedDocument(canonicalConfigurationJSON(result.revision.document));
        setFormDirty(false);
      }
      await queryClient.invalidateQueries({ queryKey: ["environment", workspace.environmentID, "configuration-revisions", "latest"] });
    } catch (error) { setProblem(error instanceof SyntaxError ? { code: "invalid_json", detail: "The configuration editor must contain exactly one JSON object.", retryable: false, status: 0, title: "Invalid configuration JSON" } : problemFromError(error)); } finally { setBusy(false); }
  }

  async function runSelfTest(): Promise<void> {
    if (!workspace) return; setBusy(true); setProblem(undefined);
    try { setTest((await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body: { kind: "upstream", environment_id: workspace.environmentID, upstream: "primary", model: "assistant_default", max_cost_nano_usd: workspace.selfTestMaximumCostNanoUsd } })).data); }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="wizard-page">
    <section className="page-heading"><div><p className="eyebrow">First-run workflow</p><h1>Configure React Native, iOS, and Android end to end.</h1><p>Every change below travels through the canonical Admin API. No database or configuration-file access is used.</p></div></section>
    <ol className="wizard-progress" aria-label="Setup progress">{["Create owner", "Create organization", "Create application", "Create environment", "Identity provider", "Attestation & components", "Upstream credential", "Upstream target", "Feature and route", "Limits", "Self-test", "SDK snippets", "Verified sample request"].map((label, index) => <li className={completed[index] ? "wizard-progress__done" : ""} key={label}><span>{completed[index] ? "✓" : index + 1}</span>{label}</li>)}</ol>
    <ProblemNotice problem={problem} />
    {latestRevision.error ? <ProblemNotice problem={problemFromError(latestRevision.error)} /> : null}
    {secrets.error ? <ProblemNotice problem={problemFromError(secrets.error)} /> : null}
    {resumeNotice ? <p className="control-notice"><strong>Resumable setup</strong><span>{resumeNotice}</span></p> : null}
    {!workspace ? <section className="wizard-card"><h2>Application, environment, identity, and native proof</h2><p>The owner and organization were created by secure bootstrap. Define the first application environment and the identifiers the verifiers must pin.</p>
      <form className="control-form" onChange={() => setFormDirty(true)} onSubmit={(event) => void createWorkspace(event)}>
        <div className="form-field-grid"><label>Organization slug<input defaultValue={selectedWorkspace?.organization?.slug} name="organization_slug" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Application name<input defaultValue={selectedWorkspace?.application?.display_name} name="application_name" required /></label><label>Application slug<input defaultValue={selectedWorkspace?.application?.slug} name="application_slug" pattern="[a-z][a-z0-9-]{1,62}" required /></label></div>
        <div className="form-field-grid"><label>Environment name<input defaultValue={selectedWorkspace?.environment?.display_name ?? "Production"} name="environment_name" required /></label><label>Environment slug<input defaultValue={selectedWorkspace?.environment?.slug ?? "production"} name="environment_slug" pattern="[a-z][a-z0-9-]{1,62}" required /></label><label>Environment kind<select defaultValue={selectedWorkspace?.environment?.kind ?? "production"} name="environment_kind" required><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option></select></label><label>Firebase project ID<input name="firebase_project" pattern="[a-z][a-z0-9-]{4,28}[a-z0-9]" required /></label><label>Mobile SDK surface<select defaultValue="react_native" name="client_surface" required><option value="react_native">React Native iOS + Android</option><option value="native">Native Swift + Kotlin</option></select><small>The generated Component Definitions bind the exact runtime platforms; create a separate application environment for a second surface.</small></label></div>
        <fieldset><legend>Apple App Attest</legend><p>The signing or distribution method selects one exact Apple launch-validation category. Development signing is allowed only in a development or staging Latchway environment.</p><div className="form-field-grid"><label>App ID prefix<input name="app_id_prefix" required /></label><label>Bundle ID<input name="bundle_id" required /></label><label>Signing or distribution<select defaultValue="app_store" name="apple_distribution" required><option value="development">Development-signed physical build</option><option value="testflight">TestFlight</option><option value="app_store">App Store</option><option value="ad_hoc_enterprise">Ad hoc or enterprise</option></select></label><label>Allowed CFBundleVersion (build number)<input name="bundle_version" placeholder="1" required /><small>Use the exact CFBundleVersion/CURRENT_PROJECT_VERSION, not CFBundleShortVersionString/MARKETING_VERSION.</small></label></div></fieldset>
        <fieldset><legend>Google Play Integrity</legend><div className="form-field-grid"><label>Package name<input name="package_name" required /><small>Must differ from the Apple bundle ID so each platform identifier has one Component Definition owner.</small></label><label>Cloud project number<input max={Number.MAX_SAFE_INTEGER} min={1} name="cloud_project" required type="number" /></label><label>Certificate SHA-256 digest (base64url)<input name="certificate_digest" pattern="[A-Za-z0-9_-]{43}" required /></label></div></fieldset>
        <fieldset><legend>Upstream target and authentication</legend><p>The production default keeps the provider credential server-side. Select no authentication only for a controlled upstream that genuinely requires none.</p><div className="form-field-grid"><label>Upstream HTTPS base URL<input defaultValue="https://api.openai.com/v1" name="upstream_url" pattern="https://.*" required type="url" /></label><label>Authentication mode<select defaultValue="bearer" name="upstream_authentication" required><option value="bearer">Bearer secret (recommended)</option><option value="none">No authentication (explicit test upstream)</option></select></label><label>Planned secret name<input defaultValue="primary_api_key" name="upstream_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label></div></fieldset>
        <fieldset><legend>Trusted input accounting</legend><p>Review these operator-owned bounds against the exact physical model before activation. The starter route accepts bounded text-only OpenAI Responses requests.</p><div className="form-field-grid"><label>Physical upstream model<input defaultValue="gpt-5-mini" name="physical_model" required /></label><label>Framing tokens per request<input defaultValue={8} min={0} name="maximum_framing_tokens_per_request" required type="number" /></label><label>Framing tokens per input item<input defaultValue={4} min={0} name="maximum_framing_tokens_per_message" required type="number" /></label><label>Maximum model context tokens<input defaultValue={128000} min={4096} name="maximum_context_tokens" required type="number" /></label></div></fieldset>
        <fieldset><legend>Operator-reviewed pricing</legend><p>Enter the current nano-USD rates for the exact physical model. Latchway will bind this revision to reservation and settlement evidence; it does not trust client-supplied prices.</p><div className="form-field-grid"><label>Input price (nano-USD per million tokens)<input min={0} name="input_nano_usd_per_million" required type="number" /></label><label>Output price (nano-USD per million tokens)<input min={0} name="output_nano_usd_per_million" required type="number" /></label><label>Per-request price (nano-USD)<input defaultValue={0} min={0} name="request_nano_usd" required type="number" /></label><label>Self-test maximum total cost (nano-USD)<input defaultValue={10_000_000} max={1_000_000_000} min={1} name="self_test_maximum_cost_nano_usd" required type="number" /></label></div></fieldset>
        <fieldset><legend>Hard token limits</legend><p>These limits are enforced from the server-rewritten request and provider-reported settlement. The total-token calendar bound covers input plus output.</p><div className="form-field-grid"><label>Daily input-token maximum<input defaultValue={100000} min={1} name="daily_input_token_maximum" required type="number" /></label><label>Daily output-token maximum<input defaultValue={100000} min={1} name="daily_output_token_maximum" required type="number" /></label><label>Daily total-token maximum<input defaultValue={200000} min={1} name="daily_total_token_maximum" required type="number" /></label><label>Per-request input-token maximum<input defaultValue={20000} min={1} name="per_request_input_token_maximum" required type="number" /></label></div></fieldset>
        <button className="primary-action" disabled={!canConfigure || busy} type="submit">{busy ? "Creating…" : "Create application and environment"}</button>
      </form></section> : <>
      <section className="wizard-card"><h2>Write-only upstream credential</h2>{workspace.upstreamAuthentication === "bearer" ? <><p>The generated upstream requires this server-held secret. The value is sent once, cleared from the form, and never returned.</p><form className="filter-bar" onChange={() => setFormDirty(true)} onSubmit={(event) => void createSecret(event)}><label>Secret name<input defaultValue={workspace.plannedSecretName} name="secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Secret value<input autoComplete="off" name="secret_value" required type="password" /></label><button className="primary-action" disabled={!canManageSecrets || busy || secrets.isPending || Boolean(secretName)} type="submit">{secretName ? "Credential added" : secrets.isPending ? "Checking credential…" : "Add credential"}</button></form></> : <p className="control-notice">You explicitly selected a no-auth upstream. Do not use this mode for OpenAI or another target that requires no credential.</p>}</section>
      <section className="wizard-card"><h2>Schema-backed full configuration document</h2><p>The generated document includes exact {workspace.clientSurface === "react_native" ? "React Native" : "native Swift and Kotlin"} root Component Definitions, platform identifiers, direct attestation, and the assistant feature grant. All identity, attestation, upstream, model, feature, route, pricing, session, privacy, and limit areas remain server validated.</p><textarea aria-label="Full configuration JSON" className="code-editor" onChange={(event) => setDocument(event.target.value)} rows={32} spellCheck={false} value={document} /><div className="button-row"><button className="secondary-action" disabled={busy || !credentialReady} onClick={() => void applyConfiguration(false)} type="button">Validate and plan only</button><button className="primary-action" disabled={!canConfigure || busy || !credentialReady} onClick={() => void applyConfiguration(true)} type="button">Validate and activate with ETag</button></div><ValidationResult report={validation} />{revision ? <p className="resource-result">Revision <code>{revision.id}</code> is <strong>{revision.state}</strong>.</p> : null}</section>
      <section className="wizard-card"><h2>Bounded upstream self-test</h2><p>This sends one non-streaming and one streaming Responses request with a one-token server clamp, trusted input preflight, operator cost ceiling, provider usage reconciliation, and safe error normalization.</p><button className="primary-action" disabled={!canTest || busy || !credentialReady || revision?.state !== "active"} onClick={() => void runSelfTest()} type="button">Run bounded upstream self-test</button>{test ? <p className="resource-result">Self-test <code>{test.id}</code>: <strong>{test.state}</strong></p> : null}</section>
      <section className="wizard-card"><h2>Platform SDK snippets</h2><p>These snippets identify only your gateway and client-visible Latchway configuration; they contain no provider key. Use the generated application resource ID shown below, not the application slug.</p>{workspace.clientSurface === "react_native" ? <><h3>React Native</h3><pre>{snippets?.reactNative}</pre></> : <><h3>iOS</h3><pre>{snippets?.ios}</pre><h3>Android</h3><pre>{snippets?.android}</pre></>}</section>
      <section className="wizard-card"><h2>Send and verify a client request</h2><p>Finish setup in AI connections. An isolated <code>latchway develop</code> environment can run a bounded synthetic client and read back its exact durable request entirely through the Console. Other environments require an official SDK request with the configured platform proof.</p><a className="primary-action" href={`/upstreams${typeof window === "undefined" ? "" : window.location.search}`}>Open AI connections</a></section>
    </>}
  </div>;
}

interface ConfigurationEditorPageProps {
  areaDescription?: string;
  areaTitle?: string;
  canonicalPaths?: string[];
}

export function ConfigurationEditorPage({
  areaDescription = "Pull, edit, validate, diff, and activate every configuration area through immutable revisions and strong ETags.",
  areaTitle = "Full-document editor",
  canonicalPaths = []
}: ConfigurationEditorPageProps = {}) {
  const session = useConsoleSession(); const workspace = useOptionalWorkspace(); const routeSearch = ConfigurationRouteSearchSchema.parse(workspace?.search ?? {}); const routeEnvironment = routeSearch.environment_id; const [environment, setEnvironment] = useState(routeEnvironment ?? ""); const [document, setDocument] = useState(""); const [baselineDocument, setBaselineDocument] = useState(""); const [active, setActive] = useState<ConfigurationRevision>(); const [validation, setValidation] = useState<ConfigurationValidation>(); const [plan, setPlan] = useState<ConfigurationPlan>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  const dirty = Boolean(document) && comparableDocument(document) !== baselineDocument;
  const activeMatchesEnvironment = !active || active.environment_id === environment;
  useDirtyEditProtection(dirty);
  const canConfigure = session.data?.session?.capabilities.includes("activate_configuration") ?? false;
  async function pull(targetEnvironment = environment): Promise<void> { setBusy(true); setProblem(undefined); try { const response = await adminRequest(`/admin/v1/environments/${targetEnvironment}/config`, RevisionSchema); if (response.data.environment_id !== targetEnvironment) throw new Error("The active revision did not match the selected environment."); const serialized = JSON.stringify(response.data.document, null, 2); setEnvironment(targetEnvironment); setActive(response.data); setDocument(serialized); setBaselineDocument(canonicalConfigurationJSON(response.data.document)); } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); } }
  function selectEnvironment(): void { if (!new RegExp(`^${environmentPattern}$`, "u").test(environment)) { setProblem({ code: "request_invalid", detail: "Enter a canonical environment ID before loading configuration.", retryable: false, status: 0, title: "Invalid environment" }); return; } if (workspace && routeEnvironment !== environment) { workspace.updateSearch({ environment_id: environment }); return; } void pull(environment); }
  async function apply(activate: boolean): Promise<void> { if (!activeMatchesEnvironment) return; setBusy(true); setProblem(undefined); setPlan(undefined); try { const result = await createValidateActivate({ document: JSON.parse(document) as unknown, environmentID: environment, activate }); setActive(result.revision); setValidation(result.report); setPlan(result.plan); if (activate && result.report.valid && result.revision.state === "active") { setDocument(JSON.stringify(result.revision.document, null, 2)); setBaselineDocument(canonicalConfigurationJSON(result.revision.document)); } } catch (error) { setProblem(error instanceof SyntaxError ? { code: "invalid_json", detail: "The editor must contain exactly one JSON object.", retryable: false, status: 0, title: "Invalid JSON" } : problemFromError(error)); } finally { setBusy(false); } }
  useEffect(() => {
    if (session.data?.mode !== "configured" || !routeEnvironment) return;
    // A validated deep link restores the exact environment revision.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setEnvironment(routeEnvironment);
    void pull(routeEnvironment);
    // Pulling is intentionally keyed only by canonical route state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routeEnvironment, session.data?.mode]);
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to edit configuration.</h1></section>;
  return <div className="control-page"><section className="page-heading"><div><p className="eyebrow">AI Configuration</p><h1>{areaTitle}</h1><p>{areaDescription}</p></div></section>{canonicalPaths.length ? <p className="resource-result">Canonical document area: {canonicalPaths.map((path, index) => <span key={path}>{index ? ", " : ""}<code>{path}</code></span>)}</p> : null}<div className="filter-bar"><label>Environment ID<input pattern={environmentPattern} required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></label><button className="secondary-action" disabled={busy || !environment} onClick={selectEnvironment} type="button">Pull active revision</button></div><ProblemNotice problem={problem} />{!activeMatchesEnvironment ? <p className="control-notice" role="status"><strong>Environment selection changed</strong><span>Pull the newly selected environment before validating or applying this document.</span></p> : null}<textarea aria-label="Configuration document JSON" className="code-editor" onChange={(event) => setDocument(event.target.value)} placeholder="Pull an active revision or paste one complete EnvironmentConfig JSON object." rows={34} spellCheck={false} value={document} /><div className="button-row"><button className="secondary-action" disabled={busy || !document || !environment || !activeMatchesEnvironment} onClick={() => void apply(false)} type="button">Dry-run validate and diff</button><button className="primary-action" disabled={!canConfigure || busy || !document || !environment || !activeMatchesEnvironment} onClick={() => void apply(true)} type="button">Apply with ETag</button></div><ValidationResult report={validation} />{plan ? <section className="detail-card"><h2>Redacted structural diff</h2><ul>{plan.changes.map((change, index) => <li key={`${change.path}-${index}`}><strong>{change.operation}</strong> <code>{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul></section> : null}{active ? <p className="resource-result">Revision <code>{active.id}</code> is <strong>{active.state}</strong>.</p> : null}</div>;
}

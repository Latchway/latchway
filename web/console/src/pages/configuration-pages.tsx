import { type FormEvent, useMemo, useState } from "react";

import {
  adminRequest,
  ApplicationSchema,
  ConfigurationPlanSchema,
  EnvironmentSchema,
  RevisionSchema,
  SecretMetadataSchema,
  SelfTestSchema,
  ValidationSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation,
  type SelfTestRun
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { buildNativeSnippets, buildNativeTemplate } from "./native-template";

const environmentPattern = "env_[A-Za-z0-9_-]{16,128}";

function safeInteger(form: FormData, name: string, minimum: number): number {
  const value = Number(form.get(name));
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be a safe integer greater than or equal to ${minimum}.`);
  return value;
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}</small></div> : null;
}

function ValidationResult({ report }: { report?: ConfigurationValidation }) {
  return report ? <section className={`validation-card ${report.valid ? "validation-card--valid" : "validation-card--invalid"}`}>
    <h3>{report.valid ? "Configuration is valid" : "Configuration needs changes"}</h3>
    <p>Checked {new Date(report.checked_at).toLocaleString()}</p>
    {report.issues.length ? <ul>{report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code>{issue.path}</code> — {issue.message}</li>)}</ul> : <p>No validation issues.</p>}
  </section> : null;
}

async function createValidateActivate(input: {
  document: unknown;
  environmentID: string;
  activate: boolean;
}): Promise<{ revision: ConfigurationRevision; report: ConfigurationValidation; plan?: ConfigurationPlan }> {
  const created = await adminRequest(`/admin/v1/environments/${input.environmentID}/config-revisions`, RevisionSchema, {
    method: "POST", body: { document: input.document, description: "Admin console full-document apply" }
  });
  if (!created.etag) throw new Error("The Admin API omitted the activation ETag.");
  const report = (await adminRequest(`/admin/v1/config-revisions/${created.data.id}/validate`, ValidationSchema, { method: "POST" })).data;
  let plan: ConfigurationPlan | undefined;
  if (report.valid) {
    try { plan = (await adminRequest(`/admin/v1/config-revisions/${created.data.id}/plan`, ConfigurationPlanSchema, { method: "POST" })).data; }
    catch (error) { if (problemFromError(error).code !== "resource_not_found") throw error; }
  }
  if (!report.valid || !input.activate) return { revision: created.data, report, ...(plan ? { plan } : {}) };
  const activated = await adminRequest(`/admin/v1/config-revisions/${created.data.id}/activate`, RevisionSchema, { method: "POST", etag: created.etag });
  return { revision: activated.data, report, ...(plan ? { plan } : {}) };
}

export function SetupWizardPage() {
  const session = useConsoleSession();
  const [workspace, setWorkspace] = useState<{ applicationID: string; applicationSlug: string; cloudProjectNumber: string; environmentID: string; environmentSlug: string; upstreamAuthentication: "bearer" | "none"; plannedSecretName: string; selfTestMaximumCostNanoUsd: number }>();
  const [document, setDocument] = useState(""); const [secretName, setSecretName] = useState<string>();
  const [revision, setRevision] = useState<ConfigurationRevision>(); const [validation, setValidation] = useState<ConfigurationValidation>(); const [test, setTest] = useState<SelfTestRun>();
  const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  const organizationID = session.data?.session?.organization_id ?? "";
  const canConfigure = session.data?.session?.capabilities.includes("activate_configuration") ?? false;
  const canManageSecrets = session.data?.session?.capabilities.includes("manage_secrets") ?? false;
  const canTest = session.data?.session?.capabilities.includes("run_self_tests") ?? false;
  const credentialReady = workspace?.upstreamAuthentication === "none" || Boolean(secretName);
  const completed = useMemo(() => [true, true, Boolean(workspace), Boolean(workspace), Boolean(document), Boolean(document), Boolean(credentialReady), Boolean(document), Boolean(document), Boolean(document), test?.state === "passed", Boolean(revision?.activated_at)], [credentialReady, document, revision, test, workspace]);
  const snippets = workspace ? buildNativeSnippets(workspace) : undefined;
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to continue setup.</h1></section>;

  async function createWorkspace(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const applicationSlug = String(form.get("application_slug")); const environmentSlug = String(form.get("environment_slug"));
      const cloudProject = safeInteger(form, "cloud_project", 1);
      const upstreamAuthenticationValue = String(form.get("upstream_authentication"));
      if (upstreamAuthenticationValue !== "bearer" && upstreamAuthenticationValue !== "none") throw new Error("Choose an explicit upstream authentication mode.");
      const upstreamAuthentication: "bearer" | "none" = upstreamAuthenticationValue;
      const plannedSecretName = String(form.get("upstream_secret_name"));
      const selfTestMaximumCostNanoUsd = safeInteger(form, "self_test_maximum_cost_nano_usd", 1);
      const application = (await adminRequest("/admin/v1/applications", ApplicationSchema, { method: "POST", body: { organization_id: organizationID, slug: applicationSlug, display_name: String(form.get("application_name")) } })).data;
      const environment = (await adminRequest(`/admin/v1/applications/${application.id}/environments`, EnvironmentSchema, { method: "POST", body: { slug: environmentSlug, display_name: String(form.get("environment_name")), kind: "production" } })).data;
      const next = { applicationID: application.id, applicationSlug, cloudProjectNumber: String(cloudProject), environmentID: environment.id, environmentSlug, upstreamAuthentication, plannedSecretName, selfTestMaximumCostNanoUsd }; setWorkspace(next);
      setDocument(buildNativeTemplate({ organization: String(form.get("organization_slug")), application: applicationSlug, environment: environmentSlug, firebaseProject: String(form.get("firebase_project")), appIDPrefix: String(form.get("app_id_prefix")), bundleID: String(form.get("bundle_id")), bundleVersion: String(form.get("bundle_version")), packageName: String(form.get("package_name")), cloudProject, certificateDigest: String(form.get("certificate_digest")), upstreamURL: String(form.get("upstream_url")), physicalModel: String(form.get("physical_model")), maximumFramingTokensPerRequest: safeInteger(form, "maximum_framing_tokens_per_request", 0), maximumFramingTokensPerMessage: safeInteger(form, "maximum_framing_tokens_per_message", 0), maximumContextTokens: safeInteger(form, "maximum_context_tokens", 1), authentication: upstreamAuthentication === "bearer" ? { type: "bearer", secretName: plannedSecretName } : { type: "none" }, inputNanoUsdPerMillion: safeInteger(form, "input_nano_usd_per_million", 0), outputNanoUsdPerMillion: safeInteger(form, "output_nano_usd_per_million", 0), requestNanoUsd: safeInteger(form, "request_nano_usd", 0), dailyInputTokenMaximum: safeInteger(form, "daily_input_token_maximum", 1), dailyOutputTokenMaximum: safeInteger(form, "daily_output_token_maximum", 1), dailyTotalTokenMaximum: safeInteger(form, "daily_total_token_maximum", 1), perRequestInputTokenMaximum: safeInteger(form, "per_request_input_token_maximum", 1) }));
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
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
      setDocument(JSON.stringify(parsed, null, 2)); form.reset();
    } catch (error) { setProblem(problemFromError(error)); const field = form.elements.namedItem("secret_value"); if (field instanceof HTMLInputElement) field.value = ""; } finally { setBusy(false); }
  }

  async function applyConfiguration(activate: boolean): Promise<void> {
    if (!workspace || !credentialReady) return; setBusy(true); setProblem(undefined);
    try {
      const parsed = JSON.parse(document) as unknown; const result = await createValidateActivate({ document: parsed, environmentID: workspace.environmentID, activate });
      setRevision(result.revision); setValidation(result.report);
    } catch (error) { setProblem(error instanceof SyntaxError ? { code: "invalid_json", detail: "The configuration editor must contain exactly one JSON object.", retryable: false, status: 0, title: "Invalid configuration JSON" } : problemFromError(error)); } finally { setBusy(false); }
  }

  async function runSelfTest(): Promise<void> {
    if (!workspace) return; setBusy(true); setProblem(undefined);
    try { setTest((await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body: { kind: "upstream", environment_id: workspace.environmentID, upstream: "primary", model: "assistant_default", max_cost_nano_usd: workspace.selfTestMaximumCostNanoUsd } })).data); }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="wizard-page">
    <section className="page-heading"><div><p className="eyebrow">First-run workflow</p><h1>Configure React Native, iOS, and Android end to end.</h1><p>Every change below travels through the canonical Admin API. No database or configuration-file access is used.</p></div></section>
    <ol className="wizard-progress" aria-label="Setup progress">{["Create owner", "Create organization", "Create application", "Create environment", "Identity provider", "Attestation", "Upstream credential", "Upstream target", "Feature and route", "Limits", "Self-test", "SDK snippets"].map((label, index) => <li className={completed[index] ? "wizard-progress__done" : ""} key={label}><span>{completed[index] ? "✓" : index + 1}</span>{label}</li>)}</ol>
    <ProblemNotice problem={problem} />
    {!workspace ? <section className="wizard-card"><h2>Application, environment, identity, and native proof</h2><p>The owner and organization were created by secure bootstrap. Define the first production application and the identifiers the verifiers must pin.</p>
      <form className="control-form" onSubmit={(event) => void createWorkspace(event)}>
        <div className="form-field-grid"><label>Organization slug<input name="organization_slug" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Application name<input name="application_name" required /></label><label>Application slug<input name="application_slug" pattern="[a-z][a-z0-9-]{1,62}" required /></label></div>
        <div className="form-field-grid"><label>Environment name<input defaultValue="Production" name="environment_name" required /></label><label>Environment slug<input defaultValue="production" name="environment_slug" pattern="[a-z][a-z0-9-]{1,62}" required /></label><label>Firebase project ID<input name="firebase_project" pattern="[a-z][a-z0-9-]{4,28}[a-z0-9]" required /></label></div>
        <fieldset><legend>Apple App Attest</legend><div className="form-field-grid"><label>App ID prefix<input name="app_id_prefix" required /></label><label>Bundle ID<input name="bundle_id" required /></label><label>Allowed bundle version<input name="bundle_version" placeholder="1.0.0" required /></label></div></fieldset>
        <fieldset><legend>Google Play Integrity</legend><div className="form-field-grid"><label>Package name<input name="package_name" required /></label><label>Cloud project number<input max={Number.MAX_SAFE_INTEGER} min={1} name="cloud_project" required type="number" /></label><label>Certificate SHA-256 digest (base64url)<input name="certificate_digest" pattern="[A-Za-z0-9_-]{43}" required /></label></div></fieldset>
        <fieldset><legend>Upstream target and authentication</legend><p>The production default keeps the provider credential server-side. Select no authentication only for a controlled upstream that genuinely requires none.</p><div className="form-field-grid"><label>Upstream HTTPS base URL<input defaultValue="https://api.openai.com/v1" name="upstream_url" pattern="https://.*" required type="url" /></label><label>Authentication mode<select defaultValue="bearer" name="upstream_authentication" required><option value="bearer">Bearer secret (recommended)</option><option value="none">No authentication (explicit test upstream)</option></select></label><label>Planned secret name<input defaultValue="primary_api_key" name="upstream_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label></div></fieldset>
        <fieldset><legend>Trusted input accounting</legend><p>Review these operator-owned bounds against the exact physical model before activation. The starter route accepts bounded text-only OpenAI Responses requests.</p><div className="form-field-grid"><label>Physical upstream model<input defaultValue="gpt-5-mini" name="physical_model" required /></label><label>Framing tokens per request<input defaultValue={8} min={0} name="maximum_framing_tokens_per_request" required type="number" /></label><label>Framing tokens per input item<input defaultValue={4} min={0} name="maximum_framing_tokens_per_message" required type="number" /></label><label>Maximum model context tokens<input defaultValue={128000} min={4096} name="maximum_context_tokens" required type="number" /></label></div></fieldset>
        <fieldset><legend>Operator-reviewed pricing</legend><p>Enter the current nano-USD rates for the exact physical model. Latchway will bind this revision to reservation and settlement evidence; it does not trust client-supplied prices.</p><div className="form-field-grid"><label>Input price (nano-USD per million tokens)<input min={0} name="input_nano_usd_per_million" required type="number" /></label><label>Output price (nano-USD per million tokens)<input min={0} name="output_nano_usd_per_million" required type="number" /></label><label>Per-request price (nano-USD)<input defaultValue={0} min={0} name="request_nano_usd" required type="number" /></label><label>Self-test maximum total cost (nano-USD)<input defaultValue={10_000_000} max={1_000_000_000} min={1} name="self_test_maximum_cost_nano_usd" required type="number" /></label></div></fieldset>
        <fieldset><legend>Hard production token limits</legend><p>These limits are enforced from the server-rewritten request and provider-reported settlement. The total-token calendar bound covers input plus output.</p><div className="form-field-grid"><label>Daily input-token maximum<input defaultValue={100000} min={1} name="daily_input_token_maximum" required type="number" /></label><label>Daily output-token maximum<input defaultValue={100000} min={1} name="daily_output_token_maximum" required type="number" /></label><label>Daily total-token maximum<input defaultValue={200000} min={1} name="daily_total_token_maximum" required type="number" /></label><label>Per-request input-token maximum<input defaultValue={20000} min={1} name="per_request_input_token_maximum" required type="number" /></label></div></fieldset>
        <button className="primary-action" disabled={!canConfigure || busy} type="submit">{busy ? "Creating…" : "Create application and environment"}</button>
      </form></section> : <>
      <section className="wizard-card"><h2>Write-only upstream credential</h2>{workspace.upstreamAuthentication === "bearer" ? <><p>The generated upstream requires this server-held secret. The value is sent once, cleared from the form, and never returned.</p><form className="filter-bar" onSubmit={(event) => void createSecret(event)}><label>Secret name<input defaultValue={workspace.plannedSecretName} name="secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Secret value<input autoComplete="off" name="secret_value" required type="password" /></label><button className="primary-action" disabled={!canManageSecrets || busy || Boolean(secretName)} type="submit">{secretName ? "Credential added" : "Add credential"}</button></form></> : <p className="control-notice">You explicitly selected a no-auth upstream. Do not use this mode for OpenAI or another target that requires a credential.</p>}</section>
      <section className="wizard-card"><h2>Schema-backed full configuration document</h2><p>All identity, attestation, upstream, model, feature, route, pricing, session, privacy, and limit areas can be represented in this complete v1 document. Server validation is authoritative.</p><textarea aria-label="Full configuration JSON" className="code-editor" onChange={(event) => setDocument(event.target.value)} rows={32} spellCheck={false} value={document} /><div className="button-row"><button className="secondary-action" disabled={busy || !credentialReady} onClick={() => void applyConfiguration(false)} type="button">Validate and plan only</button><button className="primary-action" disabled={!canConfigure || busy || !credentialReady} onClick={() => void applyConfiguration(true)} type="button">Validate and activate with ETag</button></div><ValidationResult report={validation} />{revision ? <p className="resource-result">Revision <code>{revision.id}</code> is <strong>{revision.state}</strong>.</p> : null}</section>
      <section className="wizard-card"><h2>Bounded upstream self-test</h2><p>This sends one non-streaming and one streaming Responses request with a one-token server clamp, trusted input preflight, operator cost ceiling, provider usage reconciliation, and safe error normalization.</p><button className="primary-action" disabled={!canTest || busy || !credentialReady || revision?.state !== "active"} onClick={() => void runSelfTest()} type="button">Run bounded upstream self-test</button>{test ? <p className="resource-result">Self-test <code>{test.id}</code>: <strong>{test.state}</strong></p> : null}</section>
      <section className="wizard-card"><h2>Platform SDK snippets</h2><p>These snippets identify only your gateway and client-visible Latchway configuration; they contain no provider key. Use the generated application resource ID shown below, not the application slug.</p><h3>React Native</h3><pre>{snippets?.reactNative}</pre><h3>iOS</h3><pre>{snippets?.ios}</pre><h3>Android</h3><pre>{snippets?.android}</pre></section>
    </>}
  </div>;
}

export function ConfigurationEditorPage() {
  const session = useConsoleSession(); const [environment, setEnvironment] = useState(""); const [document, setDocument] = useState(""); const [active, setActive] = useState<ConfigurationRevision>(); const [validation, setValidation] = useState<ConfigurationValidation>(); const [plan, setPlan] = useState<ConfigurationPlan>(); const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to edit configuration.</h1></section>;
  const canConfigure = session.data.session?.capabilities.includes("activate_configuration") ?? false;
  async function pull(): Promise<void> { setBusy(true); setProblem(undefined); try { const response = await adminRequest(`/admin/v1/environments/${environment}/config`, RevisionSchema); setActive(response.data); setDocument(JSON.stringify(response.data.document, null, 2)); } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); } }
  async function apply(activate: boolean): Promise<void> { setBusy(true); setProblem(undefined); setPlan(undefined); try { const result = await createValidateActivate({ document: JSON.parse(document) as unknown, environmentID: environment, activate }); setActive(result.revision); setValidation(result.report); setPlan(result.plan); } catch (error) { setProblem(error instanceof SyntaxError ? { code: "invalid_json", detail: "The editor must contain exactly one JSON object.", retryable: false, status: 0, title: "Invalid JSON" } : problemFromError(error)); } finally { setBusy(false); } }
  return <div className="control-page"><section className="page-heading"><div><p className="eyebrow">AI configuration</p><h1>Full-document editor</h1><p>Pull, edit, validate, diff, and activate every configuration area through immutable revisions and strong ETags.</p></div></section><div className="filter-bar"><label>Environment ID<input pattern={environmentPattern} required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></label><button className="secondary-action" disabled={busy || !environment} onClick={() => void pull()} type="button">Pull active revision</button></div><ProblemNotice problem={problem} /><textarea aria-label="Configuration document JSON" className="code-editor" onChange={(event) => setDocument(event.target.value)} placeholder="Pull an active revision or paste one complete EnvironmentConfig JSON object." rows={34} spellCheck={false} value={document} /><div className="button-row"><button className="secondary-action" disabled={busy || !document || !environment} onClick={() => void apply(false)} type="button">Dry-run validate and diff</button><button className="primary-action" disabled={!canConfigure || busy || !document || !environment} onClick={() => void apply(true)} type="button">Apply with ETag</button></div><ValidationResult report={validation} />{plan ? <section className="detail-card"><h2>Redacted structural diff</h2><ul>{plan.changes.map((change, index) => <li key={`${change.path}-${index}`}><strong>{change.operation}</strong> <code>{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul></section> : null}{active ? <p className="resource-result">Revision <code>{active.id}</code> is <strong>{active.state}</strong>.</p> : null}</div>;
}

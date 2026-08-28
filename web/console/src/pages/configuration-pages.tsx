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

const environmentPattern = "env_[A-Za-z0-9_-]{16,128}";

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

function buildNativeTemplate(input: {
  application: string;
  environment: string;
  organization: string;
  firebaseProject: string;
  appIDPrefix: string;
  bundleID: string;
  packageName: string;
  cloudProject: number;
  certificateDigest: string;
  upstreamURL: string;
  secretName?: string;
}): string {
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
          react_native_ios: {
            provider: "app_attest", mode: "required",
            appAttest: { appIdPrefix: input.appIDPrefix, bundleId: input.bundleID, environment: "production", allowedValidationCategories: [1], allowedBundleVersions: ["1.0"] }
          },
          react_native_android: {
            provider: "play_integrity", mode: "required",
            playIntegrity: { packageName: input.packageName, cloudProjectNumber: input.cloudProject, certificateSha256Digests: [input.certificateDigest], minimumDeviceIntegrity: "device", requireLicensed: true, allowTestingResponses: false, minimumVersionCode: 1, maximumVersionCode: 0, credentialSource: "metadata" }
          }
        }
      }],
      upstreams: [{
        id: "primary", type: "openai_compatible", baseUrl: input.upstreamURL,
        authentication: input.secretName ? { type: "bearer", secretRef: `secret/${input.secretName}` } : { type: "none" }
      }],
      models: [{ id: "assistant_default", upstream: "primary", upstreamModel: "gpt-5-mini" }],
      limitPlans: [{ id: "standard", limits: [
        { metric: "logical_requests", scope: ["user", "feature"], window: "1d", maximum: 100 },
        { metric: "output_tokens", scope: ["user", "feature"], window: "1d", maximum: 100000 },
        { metric: "input_tokens", scope: ["user", "feature"], perRequestMaximum: 20000 }
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
  const [workspace, setWorkspace] = useState<{ applicationID: string; applicationSlug: string; environmentID: string; environmentSlug: string }>();
  const [document, setDocument] = useState(""); const [secretName, setSecretName] = useState<string>();
  const [revision, setRevision] = useState<ConfigurationRevision>(); const [validation, setValidation] = useState<ConfigurationValidation>(); const [test, setTest] = useState<SelfTestRun>();
  const [problem, setProblem] = useState<AdminProblem>(); const [busy, setBusy] = useState(false);
  const organizationID = session.data?.session?.organization_id ?? "";
  const canConfigure = session.data?.session?.capabilities.includes("activate_configuration") ?? false;
  const canManageSecrets = session.data?.session?.capabilities.includes("manage_secrets") ?? false;
  const canTest = session.data?.session?.capabilities.includes("run_self_tests") ?? false;
  const completed = useMemo(() => [true, true, Boolean(workspace), Boolean(workspace), Boolean(document), Boolean(document), Boolean(secretName), Boolean(document), Boolean(document), Boolean(document), test?.state === "passed", Boolean(revision?.activated_at)], [document, revision, secretName, test, workspace]);
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to continue setup.</h1></section>;

  async function createWorkspace(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = new FormData(event.currentTarget);
    try {
      const applicationSlug = String(form.get("application_slug")); const environmentSlug = String(form.get("environment_slug"));
      const application = (await adminRequest("/admin/v1/applications", ApplicationSchema, { method: "POST", body: { organization_id: organizationID, slug: applicationSlug, display_name: String(form.get("application_name")) } })).data;
      const environment = (await adminRequest(`/admin/v1/applications/${application.id}/environments`, EnvironmentSchema, { method: "POST", body: { slug: environmentSlug, display_name: String(form.get("environment_name")), kind: "production" } })).data;
      const next = { applicationID: application.id, applicationSlug, environmentID: environment.id, environmentSlug }; setWorkspace(next);
      setDocument(buildNativeTemplate({ organization: String(form.get("organization_slug")), application: applicationSlug, environment: environmentSlug, firebaseProject: String(form.get("firebase_project")), appIDPrefix: String(form.get("app_id_prefix")), bundleID: String(form.get("bundle_id")), packageName: String(form.get("package_name")), cloudProject: Number(form.get("cloud_project")), certificateDigest: String(form.get("certificate_digest")), upstreamURL: String(form.get("upstream_url")) }));
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
    if (!workspace) return; setBusy(true); setProblem(undefined);
    try {
      const parsed = JSON.parse(document) as unknown; const result = await createValidateActivate({ document: parsed, environmentID: workspace.environmentID, activate });
      setRevision(result.revision); setValidation(result.report);
    } catch (error) { setProblem(error instanceof SyntaxError ? { code: "invalid_json", detail: "The configuration editor must contain exactly one JSON object.", retryable: false, status: 0, title: "Invalid configuration JSON" } : problemFromError(error)); } finally { setBusy(false); }
  }

  async function runSelfTest(): Promise<void> {
    if (!workspace) return; setBusy(true); setProblem(undefined);
    try { setTest((await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body: { kind: "local", environment_id: workspace.environmentID } })).data); }
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
        <fieldset><legend>Apple App Attest</legend><div className="form-field-grid"><label>App ID prefix<input name="app_id_prefix" required /></label><label>Bundle ID<input name="bundle_id" required /></label></div></fieldset>
        <fieldset><legend>Google Play Integrity</legend><div className="form-field-grid"><label>Package name<input name="package_name" required /></label><label>Cloud project number<input min={1} name="cloud_project" required type="number" /></label><label>Certificate SHA-256 digest (base64url)<input name="certificate_digest" pattern="[A-Za-z0-9_-]{43}" required /></label></div></fieldset>
        <label>Upstream HTTPS base URL<input defaultValue="https://api.openai.com/v1" name="upstream_url" pattern="https://.*" required type="url" /></label>
        <button className="primary-action" disabled={!canConfigure || busy} type="submit">{busy ? "Creating…" : "Create application and environment"}</button>
      </form></section> : <>
      <section className="wizard-card"><h2>Write-only upstream credential</h2><p>Optional for a no-auth test upstream. The value is sent once, cleared from the form, and never returned.</p><form className="filter-bar" onSubmit={(event) => void createSecret(event)}><label>Secret name<input defaultValue="primary_api_key" name="secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Secret value<input autoComplete="off" name="secret_value" required type="password" /></label><button className="primary-action" disabled={!canManageSecrets || busy || Boolean(secretName)} type="submit">{secretName ? "Credential added" : "Add credential"}</button></form></section>
      <section className="wizard-card"><h2>Schema-backed full configuration document</h2><p>All identity, attestation, upstream, model, feature, route, pricing, session, privacy, and limit areas can be represented in this complete v1 document. Server validation is authoritative.</p><textarea aria-label="Full configuration JSON" className="code-editor" onChange={(event) => setDocument(event.target.value)} rows={32} spellCheck={false} value={document} /><div className="button-row"><button className="secondary-action" disabled={busy} onClick={() => void applyConfiguration(false)} type="button">Validate and plan only</button><button className="primary-action" disabled={!canConfigure || busy} onClick={() => void applyConfiguration(true)} type="button">Validate and activate with ETag</button></div><ValidationResult report={validation} />{revision ? <p className="resource-result">Revision <code>{revision.id}</code> is <strong>{revision.state}</strong>.</p> : null}</section>
      <section className="wizard-card"><h2>Local self-test</h2><p>This verifies durable database, schema, and active configuration state without spending upstream tokens.</p><button className="primary-action" disabled={!canTest || busy || revision?.state !== "active"} onClick={() => void runSelfTest()} type="button">Run local self-test</button>{test ? <p className="resource-result">Self-test <code>{test.id}</code>: <strong>{test.state}</strong></p> : null}</section>
      <section className="wizard-card"><h2>Platform SDK snippets</h2><p>These snippets identify only your gateway and client-visible Latchway configuration; they contain no provider key.</p><h3>React Native</h3><pre>{`const latchway = createLatchwayClient({\n  baseURL: window.location.origin,\n  applicationID: "${workspace.applicationSlug}",\n  environment: "${workspace.environmentSlug}",\n  getIdentityToken,\n});`}</pre><h3>iOS</h3><pre>{`LatchwayConfiguration(\n  baseURL: gatewayURL,\n  applicationID: "${workspace.applicationSlug}",\n  environment: "${workspace.environmentSlug}",\n  identityProvider: "firebase"\n)`}</pre><h3>Android</h3><pre>{`LatchwayConfiguration(\n  baseUrl = gatewayUrl,\n  applicationId = "${workspace.applicationSlug}",\n  environment = "${workspace.environmentSlug}",\n  defaultFeature = "assistant",\n)`}</pre></section>
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

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

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
}

function FeatureWorkspace() {
  const workspace = useOptionalWorkspace();
  const routeSearch = FeatureRouteSearchSchema.parse(workspace?.search ?? {});
  const session = useConsoleSession();
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
    && (session.data.session?.capabilities.includes("activate_configuration") ?? false)
    && application?.status === "active"
    && environment?.status === "active";
  const featureCollection = configurationAreas.features.collections[0];
  const features = useMemo(() => source && featureCollection ? listAreaResources(source.document as JSONRecord, featureCollection).map((resource) => resource.value) : [], [featureCollection, source]);
  const selectedFeature = routeSearch.feature ? features.find((feature) => String(feature.id) === routeSearch.feature) : undefined;
  const models = useMemo(() => source ? identifierValues(source.document as JSONRecord, "models") : [], [source]);
  const plans = useMemo(() => source ? identifierValues(source.document as JSONRecord, "limitPlans") : [], [source]);
  const attestationPolicies = useMemo(() => source ? identifierValues(source.document as JSONRecord, "attestationPolicies") : [], [source]);

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
      <section className="detail-card client-setup"><div><p className="eyebrow">Client setup</p><h2>Values for this environment</h2><p>Use an official Latchway SDK to establish the DPoP-bound session. Provider credentials never appear in client setup.</p></div><dl><div><dt>Gateway URL</dt><dd><code>{typeof window === "undefined" ? "same-origin gateway" : window.location.origin}</code></dd></div><div><dt>Environment</dt><dd><code>{environment?.id}</code></dd></div><div><dt>Feature header</dt><dd><code>X-Latchway-Feature: &lt;feature-id&gt;</code></dd></div></dl></section>
    </> : null}
  </div>;
}

export function FeatureWorkspacePage() {
  return <EnvironmentRequired><FeatureWorkspace /></EnvironmentRequired>;
}

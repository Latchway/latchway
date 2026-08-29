import { useMemo, useState } from "react";

import { adminRequest, RevisionSchema, type ConfigurationPlan, type ConfigurationRevision, type ConfigurationValidation } from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import {
  applyConfigurationSliceChange,
  cloneConfigurationDocument,
  configurationAreas,
  deleteAreaResource,
  listAreaResources,
  upsertAreaResource,
  validStrongETag,
  type AreaResource,
  type ConfigurationAreaDefinition,
  type JSONRecord
} from "./configuration-slice";

const environmentPattern = /^env_[A-Za-z0-9_-]{16,128}$/;

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}</small></div> : null;
}

function localProblem(detail: string, title = "Resource edit is invalid"): AdminProblem {
  return { code: "request_invalid", detail, retryable: false, status: 0, title };
}

function ValidationResult({ report }: { report?: ConfigurationValidation }) {
  return report ? <section className={`validation-card ${report.valid ? "validation-card--valid" : "validation-card--invalid"}`}><h3>{report.valid ? "Configuration is valid" : "Configuration needs changes"}</h3>{report.issues.length ? <ul>{report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code>{issue.path}</code> — {issue.message}</li>)}</ul> : <p>No validation issues.</p>}</section> : null;
}

function PlanResult({ plan }: { plan?: ConfigurationPlan }) {
  return plan ? <section className="detail-card"><h2>Server structural plan</h2>{plan.changes.length ? <ul>{plan.changes.map((change, index) => <li key={`${change.path}-${index}`}><strong>{change.operation}</strong> <code>{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul> : <p>The server found no structural changes.</p>}</section> : null;
}

function ConfigurationAreaEditor({ definition }: { definition: ConfigurationAreaDefinition }) {
  const session = useConsoleSession();
  const [environmentID, setEnvironmentID] = useState("");
  const [source, setSource] = useState<ConfigurationRevision>();
  const [sourceETag, setSourceETag] = useState<string>();
  const [document, setDocument] = useState<JSONRecord>();
  const [collectionKey, setCollectionKey] = useState(definition.collections[0]?.key ?? "");
  const [editorKey, setEditorKey] = useState<string>();
  const [editorValue, setEditorValue] = useState("");
  const [deletionTarget, setDeletionTarget] = useState<AreaResource>();
  const [deletionConfirmation, setDeletionConfirmation] = useState("");
  const [validation, setValidation] = useState<ConfigurationValidation>();
  const [plan, setPlan] = useState<ConfigurationPlan>();
  const [result, setResult] = useState<ConfigurationRevision>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const collection = definition.collections.find((candidate) => candidate.key === collectionKey) ?? definition.collections[0];
  const resources = useMemo(() => document && collection ? listAreaResources(document, collection) : [], [collection, document]);
  const changed = Boolean(source && document && JSON.stringify(source.document) !== JSON.stringify(document));
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to edit {definition.title.toLowerCase()}.</h1></section>;
  const canConfigure = session.data.session?.capabilities.includes("activate_configuration") ?? false;

  function clearTransient(): void {
    setEditorKey(undefined); setEditorValue(""); setDeletionTarget(undefined); setDeletionConfirmation(""); setValidation(undefined); setPlan(undefined); setResult(undefined);
  }

  async function load(): Promise<void> {
    if (!environmentPattern.test(environmentID)) { setProblem(localProblem("Enter a canonical environment ID before loading configuration.")); return; }
    setBusy(true); setProblem(undefined);
    try {
      const active = await adminRequest(`/admin/v1/environments/${environmentID}/config`, RevisionSchema);
      if (!validStrongETag(active.etag)) throw new Error("The Admin API omitted the active strong ETag required for safe editing.");
      const copied = cloneConfigurationDocument(active.data.document);
      setSource(active.data); setSourceETag(active.etag); setDocument(copied); clearTransient();
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  function edit(resource: AreaResource): void {
    setEditorKey(resource.key); setEditorValue(JSON.stringify(resource.value, null, 2)); setDeletionTarget(undefined); setDeletionConfirmation(""); setProblem(undefined);
  }

  function add(): void {
    if (!collection || collection.kind === "feature-fields") return;
    setEditorKey(""); setEditorValue(JSON.stringify(collection.template, null, 2)); setDeletionTarget(undefined); setDeletionConfirmation(""); setProblem(undefined);
  }

  function stageResource(): void {
    if (!document || !collection || editorKey === undefined) return;
    try {
      const parsed = JSON.parse(editorValue) as unknown;
      const updated = upsertAreaResource(document, collection, editorKey || undefined, parsed);
      setDocument(updated.document); setEditorKey(undefined); setEditorValue(""); setProblem(undefined); setValidation(undefined); setPlan(undefined); setResult(undefined);
    } catch (error) {
      setProblem(localProblem(error instanceof Error ? error.message : "The resource JSON is invalid."));
    }
  }

  function stageDelete(): void {
    if (!document || !collection || !deletionTarget || deletionConfirmation !== deletionTarget.key) return;
    const current = listAreaResources(document, collection).find((resource) => resource.key === deletionTarget.key);
    if (!current || JSON.stringify(current.value) !== JSON.stringify(deletionTarget.value)) {
      setProblem(localProblem("The staged resource changed before deletion. Reopen the exact current resource and confirm again."));
      setDeletionTarget(undefined); setDeletionConfirmation(""); return;
    }
    try {
      setDocument(deleteAreaResource(document, collection, deletionTarget.key));
      setDeletionTarget(undefined); setDeletionConfirmation(""); setValidation(undefined); setPlan(undefined); setResult(undefined);
    } catch (error) { setProblem(localProblem(error instanceof Error ? error.message : "The resource cannot be deleted.")); }
  }

  function discard(): void {
    if (!source) return;
    setDocument(cloneConfigurationDocument(source.document)); clearTransient(); setProblem(undefined);
  }

  async function submit(activate: boolean): Promise<void> {
    if (!source || !document || !collection || !changed) return;
    setBusy(true); setProblem(undefined); setValidation(undefined); setPlan(undefined); setResult(undefined);
    try {
      const applied = await applyConfigurationSliceChange({ activate, description: `Admin console ${definition.title} targeted edit`, document, environmentID, sourceRevisionID: source.id });
      setValidation(applied.report); setPlan(applied.plan); setResult(applied.revision);
      if (activate && applied.report.valid) {
        setSource(applied.revision); setSourceETag(applied.etag); setDocument(cloneConfigurationDocument(applied.revision.document)); clearTransient(); setResult(applied.revision); setValidation(applied.report); setPlan(applied.plan);
      }
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="control-page">
    <section className="page-heading"><div><p className="eyebrow">AI Configuration</p><h1>{definition.title}</h1><p>{definition.description}</p></div></section>
    <div className="filter-bar"><label>Environment ID<input pattern="env_[A-Za-z0-9_-]{16,128}" required value={environmentID} onChange={(event) => { setEnvironmentID(event.target.value); setSource(undefined); setSourceETag(undefined); setDocument(undefined); clearTransient(); }} /></label><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Load active configuration</button></div>
    <ProblemNotice problem={problem} />
    {source && document && collection ? <>
      <section className="resource-context"><span>Source revision <code>{source.id}</code></span><span>Version {source.version}</span><span>Strong ETag <code>{sourceETag}</code></span><span>{changed ? "Staged changes" : "No staged changes"}</span></section>
      {definition.collections.length > 1 ? <label className="collection-selector">Resource collection<select value={collection.key} onChange={(event) => { setCollectionKey(event.target.value); clearTransient(); }}>{definition.collections.map((candidate) => <option key={candidate.key} value={candidate.key}>{candidate.label}</option>)}</select></label> : null}
      <section className="detail-card"><div className="detail-card__heading"><div><h2>{collection.label}</h2><p>{collection.description}</p><p>Canonical slice: <code>{collection.canonicalPath}</code></p></div>{collection.kind !== "feature-fields" ? <button className="secondary-action" disabled={busy} onClick={add} type="button">Add resource</button> : null}</div>
        <div className="resource-list">{resources.length ? resources.map((resource) => <article className="resource-list__item" key={resource.key}><div><strong>{resource.label}</strong><small>{collection.canonicalPath}</small></div><div className="resource-actions"><button className="small-action" disabled={busy} onClick={() => edit(resource)} type="button">Edit {resource.label}</button>{collection.deletable ? <button className="small-action small-action--danger" disabled={busy} onClick={() => { setDeletionTarget(resource); setDeletionConfirmation(""); setEditorKey(undefined); setEditorValue(""); }} type="button">Delete {resource.label}</button> : null}</div></article>) : <p>No resources in this canonical slice.</p>}</div>
      </section>
      {editorKey !== undefined ? <section className="control-form"><h2>{editorKey ? `Edit ${editorKey}` : `Add ${collection.label.toLowerCase()} resource`}</h2><p>Only this resource wrapper is editable here. The rest of the active immutable document remains represented in the staged clone.</p><textarea aria-label="Resource JSON" className="code-editor" maxLength={1_048_576} onChange={(event) => setEditorValue(event.target.value)} rows={22} spellCheck={false} value={editorValue} /><div className="button-row"><button className="primary-action" disabled={busy || !editorValue} onClick={stageResource} type="button">Stage resource</button><button className="secondary-action" disabled={busy} onClick={() => { setEditorKey(undefined); setEditorValue(""); }} type="button">Cancel edit</button></div></section> : null}
      {deletionTarget ? <section className="control-form destructive-confirmation"><h2>Stage deletion of {deletionTarget.label}</h2><p>This removes only <code>{deletionTarget.key}</code> from <code>{collection.canonicalPath}</code>. Server validation and activation are still required.</p><label>Type <strong>{deletionTarget.key}</strong> to confirm<input autoComplete="off" maxLength={128} value={deletionConfirmation} onChange={(event) => setDeletionConfirmation(event.target.value)} /></label><div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || deletionConfirmation !== deletionTarget.key} onClick={stageDelete} type="button">Stage resource deletion</button><button className="secondary-action" disabled={busy} onClick={() => { setDeletionTarget(undefined); setDeletionConfirmation(""); }} type="button">Cancel deletion</button></div></section> : null}
      <section className="control-form"><h2>Validate and activate the targeted merge</h2><p>The console clones exact active revision <code>{source.id}</code> on the server. A stale base is rejected. The full preserved document is then replaced on that draft with its strong ETag, validated, planned, and optionally activated with the newest strong ETag.</p><div className="button-row"><button className="secondary-action" disabled={busy || !changed} onClick={discard} type="button">Discard staged changes</button><button className="secondary-action" disabled={!canConfigure || busy || !changed} onClick={() => void submit(false)} type="button">Validate and plan</button><button className="primary-action" disabled={!canConfigure || busy || !changed} onClick={() => void submit(true)} type="button">Validate and activate</button></div>{!canConfigure ? <small>The activate_configuration capability is required to create, validate, or activate a revision.</small> : null}</section>
      <ValidationResult report={validation} /><PlanResult plan={plan} />{result ? <p className="resource-result">Revision <code>{result.id}</code> is <strong>{result.state}</strong>.</p> : null}
    </> : null}
  </div>;
}

export function AuthenticationProvidersPage() { return <ConfigurationAreaEditor definition={configurationAreas.identity} />; }
export function AttestationConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.attestation} />; }
export function FeaturesConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.features} />; }
export function RoutesConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.routes} />; }
export function UpstreamsConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.upstreams} />; }
export function ModelsPricingConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.modelsPricing} />; }
export function AccessPoliciesConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.access} />; }
export function LimitPlansConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.limits} />; }
export function AbuseControlsConfigurationPage() { return <ConfigurationAreaEditor definition={configurationAreas.abuse} />; }

export { ConfigurationAreaEditor };

import { type FormEvent, type ReactNode, useState } from "react";
import { z } from "zod";

import { adminRequest, queryPath } from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import {
  ApplicationResourcePageSchema,
  ApplicationResourceSchema,
  EnvironmentResourceListSchema,
  EnvironmentResourceSchema,
  SecretResourcePageSchema,
  SecretResourceSchema,
  type ApplicationResource,
  type ApplicationResourcePage,
  type EnvironmentResource,
  type SecretResource,
  type SecretResourcePage
} from "../api/resources";
import { useConsoleSession } from "../api/session";
import { useConsoleCompatibility } from "../app/console-compatibility-context";

const applicationIDPattern = /^app_[A-Za-z0-9_-]{16,128}$/;
const environmentIDPattern = /^env_[A-Za-z0-9_-]{16,128}$/;
const resourceSlugPattern = "[a-z][a-z0-9-]{1,62}";
const resourceIdentifierPattern = "[a-z][a-z0-9_-]{0,62}";

function PageHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return <section className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{children}</p></div></section>;
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}{problem.operationId ? ` · Operation: ${problem.operationId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
}

function AccessRequired({ resource }: { resource: string }) {
  return <section className="empty-state"><h1>Sign in to manage {resource}.</h1></section>;
}

function Table({ headers, rows }: { headers: string[]; rows: ReactNode[][] }) {
  return <div className="data-table-wrap"><table className="data-table"><thead><tr>{headers.map((header) => <th key={header} scope="col">{header}</th>)}</tr></thead><tbody>{rows.length === 0 ? <tr><td colSpan={headers.length}>No matching records.</td></tr> : rows.map((row, rowIndex) => <tr key={rowIndex}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>)}</tbody></table></div>;
}

function displayInstant(value?: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function invalidResourceProblem(detail: string): AdminProblem {
  return { code: "request_invalid", detail, retryable: false, status: 0, title: "Request is invalid" };
}

function paginationButton(label: string, busy: boolean, action: () => void) {
  return <button className="secondary-action" disabled={busy} onClick={action} type="button">{label}</button>;
}

export function ApplicationsPage() {
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const [page, setPage] = useState<ApplicationResourcePage>();
  const [lifecycleTarget, setLifecycleTarget] = useState<ApplicationResource>();
  const [lifecycleReason, setLifecycleReason] = useState("");
  const [lifecycleAcknowledged, setLifecycleAcknowledged] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired resource="applications" />;
  const organizationID = session.data.session?.organization_id ?? "";
  const canConfigure = consoleCompatibility.mutationAllowed && (session.data.session?.capabilities.includes("activate_configuration") ?? false);

  async function load(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined); setLifecycleTarget(undefined); setLifecycleReason(""); setLifecycleAcknowledged(false);
    try {
      setPage((await adminRequest(queryPath("/admin/v1/applications", { organization_id: organizationID, page_size: "50", cursor }), ApplicationResourcePageSchema)).data);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!canConfigure) return; setBusy(true); setProblem(undefined);
    const form = event.currentTarget; const data = new FormData(form);
    try {
      const created = (await adminRequest("/admin/v1/applications", ApplicationResourceSchema, { method: "POST", body: {
        organization_id: organizationID,
        slug: String(data.get("slug")),
        display_name: String(data.get("display_name"))
      } })).data;
      setPage((current) => current ? { ...current, items: [created, ...current.items.filter((item) => item.id !== created.id)] } : { items: [created], page: { has_more: false } });
      form.reset();
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  function selectApplicationLifecycle(item?: ApplicationResource): void {
    setLifecycleTarget(item); setLifecycleReason(""); setLifecycleAcknowledged(false); setProblem(undefined);
  }

  async function setApplicationEnabled(item: ApplicationResource, enabled: boolean): Promise<void> {
    if (!canConfigure) return;
    const reason = lifecycleReason.trim();
    if (!enabled && (!lifecycleAcknowledged || reason.length < 1 || reason.length > 500)) {
      setProblem(invalidResourceProblem("A bounded reason and explicit credential-revocation acknowledgement are required."));
      return;
    }
    setBusy(true); setProblem(undefined);
    try {
      const updated = (await adminRequest(
        `/admin/v1/applications/${item.id}/${enabled ? "enable" : "disable"}`,
        ApplicationResourceSchema,
        enabled ? { method: "POST" } : { method: "POST", body: { reason } }
      )).data;
      setPage((current) => current ? { ...current, items: current.items.map((candidate) => candidate.id === updated.id ? updated : candidate) } : current);
      selectApplicationLifecycle();
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="control-page">
    <PageHeading eyebrow="Workspace" title="Applications">Browse tenant-scoped applications, create resources, and control whether application traffic is eligible.</PageHeading>
    {canConfigure ? <form className="control-form" onSubmit={(event) => void create(event)}><h2>Create application</h2><div className="form-field-grid"><label>Display name<input maxLength={200} name="display_name" required /></label><label>Slug<input maxLength={63} name="slug" pattern={resourceSlugPattern} required /></label></div><button className="primary-action" disabled={busy} type="submit">{busy ? "Working…" : "Create application"}</button></form> : <div className="control-notice"><strong>Read-only session</strong><span>The activate_configuration capability is required to create applications.</span></div>}
    <div className="button-row"><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Load applications</button></div>
    {lifecycleTarget ? <form className="control-form destructive-confirmation" onSubmit={(event) => { event.preventDefault(); void setApplicationEnabled(lifecycleTarget, false); }}><h2>Disable {lifecycleTarget.display_name}</h2><p>Disabling this application denies its traffic immediately and revokes active legacy and component session and refresh credentials in every environment. Re-enabling later restores future eligibility only; revoked credentials stay revoked.</p><p>Application ID: <code>{lifecycleTarget.id}</code></p><label>Reason<textarea maxLength={500} required rows={3} value={lifecycleReason} onChange={(event) => setLifecycleReason(event.target.value)} /></label><label className="check-field"><input checked={lifecycleAcknowledged} onChange={(event) => setLifecycleAcknowledged(event.target.checked)} type="checkbox" />I understand active credentials in this application will be revoked.</label><div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || !canConfigure || !lifecycleAcknowledged || lifecycleReason.trim().length === 0} type="submit">Disable application</button><button className="secondary-action" disabled={busy} onClick={() => selectApplicationLifecycle()} type="button">Cancel</button></div></form> : null}
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Application", "Status", "Slug", "Created", "Actions"]} rows={page.items.map((item) => [<><strong>{item.display_name}</strong><br /><small>{item.id}</small></>, <><span className="state-badge">{item.status}</span>{item.status === "disabled" ? <><br /><small>{displayInstant(item.disabled_at)}</small></> : null}</>, item.slug, displayInstant(item.created_at), item.status === "disabled" ? <button className="small-action" disabled={busy || !canConfigure} onClick={() => void setApplicationEnabled(item, true)} type="button">Enable</button> : <button className="small-action small-action--danger" disabled={busy || !canConfigure} onClick={() => selectApplicationLifecycle(item)} type="button">Disable</button>])} />{page.page.has_more && page.page.next_cursor ? paginationButton("Next page", busy, () => void load(page.page.next_cursor)) : null}</> : null}
  </div>;
}

export function EnvironmentsPage() {
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const [applicationID, setApplicationID] = useState("");
  const [items, setItems] = useState<EnvironmentResource[]>();
  const [lifecycleTarget, setLifecycleTarget] = useState<EnvironmentResource>();
  const [lifecycleReason, setLifecycleReason] = useState("");
  const [lifecycleAcknowledged, setLifecycleAcknowledged] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired resource="environments" />;
  const canConfigure = consoleCompatibility.mutationAllowed && (session.data.session?.capabilities.includes("activate_configuration") ?? false);

  function validApplication(): boolean {
    if (applicationIDPattern.test(applicationID)) return true;
    setProblem(invalidResourceProblem("Enter a canonical application ID before continuing."));
    return false;
  }

  async function load(): Promise<void> {
    if (!validApplication()) return;
    setBusy(true); setProblem(undefined); setLifecycleTarget(undefined); setLifecycleReason(""); setLifecycleAcknowledged(false);
    try { setItems((await adminRequest(`/admin/v1/applications/${applicationID}/environments`, EnvironmentResourceListSchema)).data.items); }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!canConfigure || !validApplication()) return;
    setBusy(true); setProblem(undefined); const form = event.currentTarget; const data = new FormData(form);
    try {
      const created = (await adminRequest(`/admin/v1/applications/${applicationID}/environments`, EnvironmentResourceSchema, { method: "POST", body: {
        display_name: String(data.get("display_name")), kind: String(data.get("kind")), slug: String(data.get("slug"))
      } })).data;
      setItems((current) => [created, ...(current ?? []).filter((item) => item.id !== created.id)]); form.reset();
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  function selectEnvironmentLifecycle(item?: EnvironmentResource): void {
    setLifecycleTarget(item); setLifecycleReason(""); setLifecycleAcknowledged(false); setProblem(undefined);
  }

  async function setEnvironmentEnabled(item: EnvironmentResource, enabled: boolean): Promise<void> {
    if (!canConfigure) return;
    const reason = lifecycleReason.trim();
    if (!enabled && (!lifecycleAcknowledged || reason.length < 1 || reason.length > 500)) {
      setProblem(invalidResourceProblem("A bounded reason and explicit credential-revocation acknowledgement are required."));
      return;
    }
    setBusy(true); setProblem(undefined);
    try {
      const updated = (await adminRequest(
        `/admin/v1/environments/${item.id}/${enabled ? "enable" : "disable"}`,
        EnvironmentResourceSchema,
        enabled ? { method: "POST" } : { method: "POST", body: { reason } }
      )).data;
      setItems((current) => current?.map((candidate) => candidate.id === updated.id ? updated : candidate));
      selectEnvironmentLifecycle();
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="control-page">
    <PageHeading eyebrow="Workspace" title="Environments">Browse application environments, create deployment scopes, and control traffic eligibility independently.</PageHeading>
    <div className="filter-bar"><label>Application ID<input pattern="app_[A-Za-z0-9_-]{16,128}" required value={applicationID} onChange={(event) => { setApplicationID(event.target.value); setItems(undefined); selectEnvironmentLifecycle(); }} /></label><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Load environments</button></div>
    {canConfigure ? <form className="control-form" onSubmit={(event) => void create(event)}><h2>Create environment</h2><div className="form-field-grid"><label>Display name<input maxLength={200} name="display_name" required /></label><label>Slug<input maxLength={63} name="slug" pattern={resourceSlugPattern} required /></label><label>Kind<select defaultValue="production" name="kind"><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option></select></label></div><button className="primary-action" disabled={busy || !applicationIDPattern.test(applicationID)} type="submit">{busy ? "Working…" : "Create environment"}</button></form> : <div className="control-notice"><strong>Read-only session</strong><span>The activate_configuration capability is required to create environments.</span></div>}
    {lifecycleTarget ? <form className="control-form destructive-confirmation" onSubmit={(event) => { event.preventDefault(); void setEnvironmentEnabled(lifecycleTarget, false); }}><h2>Disable {lifecycleTarget.display_name}</h2><p>Disabling this environment denies its traffic immediately and revokes active legacy and component session and refresh credentials in this environment. Re-enabling later does not restore those credentials.</p><p>Environment ID: <code>{lifecycleTarget.id}</code></p><label>Reason<textarea maxLength={500} required rows={3} value={lifecycleReason} onChange={(event) => setLifecycleReason(event.target.value)} /></label><label className="check-field"><input checked={lifecycleAcknowledged} onChange={(event) => setLifecycleAcknowledged(event.target.checked)} type="checkbox" />I understand active credentials in this environment will be revoked.</label><div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || !canConfigure || !lifecycleAcknowledged || lifecycleReason.trim().length === 0} type="submit">Disable environment</button><button className="secondary-action" disabled={busy} onClick={() => selectEnvironmentLifecycle()} type="button">Cancel</button></div></form> : null}
    <ProblemNotice problem={problem} />
    {items ? <Table headers={["Environment", "Status", "Kind", "Created", "Actions"]} rows={items.map((item) => [<><strong>{item.display_name}</strong><br /><small>{item.id}</small></>, <><span className="state-badge">{item.status}</span>{item.status === "disabled" ? <><br /><small>{displayInstant(item.disabled_at)}</small></> : null}</>, item.kind, displayInstant(item.created_at), item.status === "disabled" ? <button className="small-action" disabled={busy || !canConfigure} onClick={() => void setEnvironmentEnabled(item, true)} type="button">Enable</button> : <button className="small-action small-action--danger" disabled={busy || !canConfigure} onClick={() => selectEnvironmentLifecycle(item)} type="button">Disable</button>])} /> : null}
  </div>;
}

export function SecretsPage() {
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const [environmentID, setEnvironmentID] = useState("");
  const [page, setPage] = useState<SecretResourcePage>();
  const [rotationTarget, setRotationTarget] = useState<SecretResource>();
  const [deletionTarget, setDeletionTarget] = useState<SecretResource>();
  const [deletionConfirmation, setDeletionConfirmation] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired resource="secrets" />;
  const canInspect = session.data.session?.capabilities.includes("manage_secrets") ?? false;
  const canManage = consoleCompatibility.mutationAllowed && canInspect;

  function validEnvironment(): boolean {
    if (environmentIDPattern.test(environmentID)) return true;
    setProblem(invalidResourceProblem("Enter a canonical environment ID before continuing."));
    return false;
  }

  async function load(cursor?: string): Promise<void> {
    if (!validEnvironment()) return;
    setBusy(true); setProblem(undefined); setRotationTarget(undefined); setDeletionTarget(undefined); setDeletionConfirmation("");
    try { setPage((await adminRequest(queryPath("/admin/v1/secrets", { environment_id: environmentID, page_size: "50", cursor }), SecretResourcePageSchema)).data); }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!canManage || !validEnvironment()) return;
    const form = event.currentTarget; const data = new FormData(form); const valueField = form.elements.namedItem("value");
    const name = String(data.get("name")); const value = String(data.get("value"));
    if (valueField instanceof HTMLInputElement) valueField.value = "";
    setBusy(true); setProblem(undefined);
    try {
      const created = (await adminRequest("/admin/v1/secrets", SecretResourceSchema, { method: "POST", body: { environment_id: environmentID, name, value } })).data;
      setPage((current) => current ? { ...current, items: [created, ...current.items.filter((item) => item.id !== created.id)] } : { items: [created], page: { has_more: false } });
      form.reset();
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function rotate(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!canManage || !rotationTarget) return;
    const form = event.currentTarget; const data = new FormData(form); const valueField = form.elements.namedItem("rotation_value");
    const value = String(data.get("rotation_value"));
    if (valueField instanceof HTMLInputElement) valueField.value = "";
    setBusy(true); setProblem(undefined);
    try {
      const rotated = (await adminRequest(`/admin/v1/secrets/${rotationTarget.id}/rotate`, SecretResourceSchema, { method: "POST", body: { value } })).data;
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === rotationTarget.id ? rotated : item) } : current);
      setRotationTarget(undefined); setDeletionTarget(undefined); setDeletionConfirmation(""); form.reset();
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function destroy(): Promise<void> {
    if (!canManage || !deletionTarget || deletionConfirmation !== deletionTarget.name) return;
    const currentSecret = page?.items.find((secret) => secret.name === deletionTarget.name);
    if (!currentSecret || currentSecret.id !== deletionTarget.id) {
      setDeletionTarget(undefined); setDeletionConfirmation("");
      setProblem(invalidResourceProblem("Secret metadata changed before deletion. Reload metadata and confirm the exact current version again."));
      return;
    }
    setBusy(true); setProblem(undefined);
    try {
      await adminRequest(`/admin/v1/secrets/${currentSecret.id}`, z.undefined(), { method: "DELETE" });
      setPage((current) => current ? { ...current, items: current.items.filter((item) => item.id !== currentSecret.id) } : current);
      if (rotationTarget?.id === currentSecret.id) setRotationTarget(undefined);
      setDeletionTarget(undefined); setDeletionConfirmation("");
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="control-page">
    <PageHeading eyebrow="AI Configuration" title="Secrets">Manage encrypted provider-secret metadata. Plaintext is accepted only by a password input, never persisted in browser storage, and cleared from the form before the request completes.</PageHeading>
    {!canInspect ? <div className="control-notice"><strong>Capability required</strong><span>The manage_secrets capability is required to list or mutate secret metadata.</span></div> : <>
      <div className="filter-bar"><label>Environment ID<input pattern="env_[A-Za-z0-9_-]{16,128}" required value={environmentID} onChange={(event) => { setEnvironmentID(event.target.value); setPage(undefined); setRotationTarget(undefined); setDeletionTarget(undefined); setDeletionConfirmation(""); }} /></label><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Load secret metadata</button></div>
      {canManage ? <form className="control-form" onSubmit={(event) => void create(event)}><h2>Create write-only secret</h2><div className="form-field-grid"><label>Secret name<input autoComplete="off" maxLength={63} name="name" pattern={resourceIdentifierPattern} required /></label><label>Secret value<input autoComplete="new-password" maxLength={1_048_576} name="value" required type="password" /></label></div><button className="primary-action" disabled={busy || !environmentIDPattern.test(environmentID)} type="submit">{busy ? "Working…" : "Create secret"}</button></form> : null}
    </>}
    <ProblemNotice problem={problem} />
    {rotationTarget && canManage ? <form className="control-form" onSubmit={(event) => void rotate(event)}><h2>Rotate {rotationTarget.name}</h2><p>The current version ID is checked by the server. The replacement value is write-only and this input is cleared immediately on submission.</p><label>Replacement secret value<input autoComplete="new-password" maxLength={1_048_576} name="rotation_value" required type="password" /></label><div className="button-row"><button className="primary-action" disabled={busy || !canManage} type="submit">Rotate secret</button><button className="secondary-action" disabled={busy} onClick={() => setRotationTarget(undefined)} type="button">Cancel</button></div></form> : null}
    {deletionTarget ? <section className="control-form destructive-confirmation" aria-labelledby="secret-deletion-title"><h2 id="secret-deletion-title">Permanently delete {deletionTarget.name}</h2><p>This tombstones every version of the logical secret. The name cannot be reused, and deletion succeeds only when the exact current version is unreferenced.</p><p>Current secret ID: <code>{deletionTarget.id}</code></p><label>Type <strong>{deletionTarget.name}</strong> to confirm<input autoComplete="off" maxLength={63} value={deletionConfirmation} onChange={(event) => setDeletionConfirmation(event.target.value)} /></label><div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || !canManage || deletionConfirmation !== deletionTarget.name} onClick={() => void destroy()} type="button">Permanently delete secret</button><button className="secondary-action" disabled={busy} onClick={() => { setDeletionTarget(undefined); setDeletionConfirmation(""); }} type="button">Cancel deletion</button></div></section> : null}
    {page ? <><Table headers={["Name", "Version", "Algorithm", "Created", "Rotated", "Actions"]} rows={page.items.map((secret) => [<><strong>{secret.name}</strong><br /><small>{secret.id}</small></>, secret.version, secret.algorithm, displayInstant(secret.created_at), displayInstant(secret.rotated_at), <div className="resource-actions"><button className="small-action" disabled={busy || !canManage} onClick={() => { setRotationTarget(secret); setDeletionTarget(undefined); setDeletionConfirmation(""); }} type="button">Rotate</button><button className="small-action small-action--danger" disabled={busy || !canManage} onClick={() => { setDeletionTarget(secret); setDeletionConfirmation(""); setRotationTarget(undefined); }} type="button">Delete unreferenced</button></div>])} />{page.page.has_more && page.page.next_cursor ? paginationButton("Next page", busy, () => void load(page.page.next_cursor)) : null}</> : null}
  </div>;
}

import { type FormEvent, type ReactNode, useEffect, useState } from "react";
import { z } from "zod";

import { adminRequest, queryPath } from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import {
  ApplicationResourcePageSchema,
  ApplicationResourceSchema,
  ConfigurationRevisionResourcePageSchema,
  ConfigurationRevisionResourceSchema,
  EnvironmentResourceListSchema,
  EnvironmentResourceSchema,
  SecretResourcePageSchema,
  SecretResourceSchema,
  UserOverrideResourceSchema,
  type ApplicationResource,
  type ApplicationResourcePage,
  type ConfigurationRevisionResource,
  type ConfigurationRevisionResourcePage,
  type EnvironmentResource,
  type SecretResource,
  type SecretResourcePage,
  type UserOverrideResource
} from "../api/resources";
import { useConsoleSession } from "../api/session";
import { useOptionalWorkspace } from "../app/workspace-context-value";

const applicationIDPattern = /^app_[A-Za-z0-9_-]{16,128}$/;
const environmentIDPattern = /^env_[A-Za-z0-9_-]{16,128}$/;
const userIDPattern = /^usr_[A-Za-z0-9_-]{16,128}$/;
const resourceSlugPattern = "[a-z][a-z0-9-]{1,62}";
const resourceIdentifierPattern = "[a-z][a-z0-9_-]{0,62}";

function PageHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return <section className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{children}</p></div></section>;
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
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
  const [page, setPage] = useState<ApplicationResourcePage>();
  const [lifecycleTarget, setLifecycleTarget] = useState<ApplicationResource>();
  const [lifecycleReason, setLifecycleReason] = useState("");
  const [lifecycleAcknowledged, setLifecycleAcknowledged] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired resource="applications" />;
  const organizationID = session.data.session?.organization_id ?? "";
  const canConfigure = session.data.session?.capabilities.includes("activate_configuration") ?? false;

  async function load(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined); setLifecycleTarget(undefined); setLifecycleReason(""); setLifecycleAcknowledged(false);
    try {
      setPage((await adminRequest(queryPath("/admin/v1/applications", { organization_id: organizationID, page_size: "50", cursor }), ApplicationResourcePageSchema)).data);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined);
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
    {lifecycleTarget ? <form className="control-form destructive-confirmation" onSubmit={(event) => { event.preventDefault(); void setApplicationEnabled(lifecycleTarget, false); }}><h2>Disable {lifecycleTarget.display_name}</h2><p>Disabling this application denies its traffic immediately and revokes active legacy and component session and refresh credentials in every environment. Re-enabling later restores future eligibility only; revoked credentials stay revoked.</p><p>Application ID: <code>{lifecycleTarget.id}</code></p><label>Reason<textarea maxLength={500} required rows={3} value={lifecycleReason} onChange={(event) => setLifecycleReason(event.target.value)} /></label><label className="check-field"><input checked={lifecycleAcknowledged} onChange={(event) => setLifecycleAcknowledged(event.target.checked)} type="checkbox" />I understand active credentials in this application will be revoked.</label><div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || !lifecycleAcknowledged || lifecycleReason.trim().length === 0} type="submit">Disable application</button><button className="secondary-action" disabled={busy} onClick={() => selectApplicationLifecycle()} type="button">Cancel</button></div></form> : null}
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Application", "Status", "Slug", "Created", "Actions"]} rows={page.items.map((item) => [<><strong>{item.display_name}</strong><br /><small>{item.id}</small></>, <><span className="state-badge">{item.status}</span>{item.status === "disabled" ? <><br /><small>{displayInstant(item.disabled_at)}</small></> : null}</>, item.slug, displayInstant(item.created_at), item.status === "disabled" ? <button className="small-action" disabled={busy || !canConfigure} onClick={() => void setApplicationEnabled(item, true)} type="button">Enable</button> : <button className="small-action small-action--danger" disabled={busy || !canConfigure} onClick={() => selectApplicationLifecycle(item)} type="button">Disable</button>])} />{page.page.has_more && page.page.next_cursor ? paginationButton("Next page", busy, () => void load(page.page.next_cursor)) : null}</> : null}
  </div>;
}

export function EnvironmentsPage() {
  const session = useConsoleSession();
  const [applicationID, setApplicationID] = useState("");
  const [items, setItems] = useState<EnvironmentResource[]>();
  const [lifecycleTarget, setLifecycleTarget] = useState<EnvironmentResource>();
  const [lifecycleReason, setLifecycleReason] = useState("");
  const [lifecycleAcknowledged, setLifecycleAcknowledged] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired resource="environments" />;
  const canConfigure = session.data.session?.capabilities.includes("activate_configuration") ?? false;

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
    event.preventDefault(); if (!validApplication()) return;
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
    {lifecycleTarget ? <form className="control-form destructive-confirmation" onSubmit={(event) => { event.preventDefault(); void setEnvironmentEnabled(lifecycleTarget, false); }}><h2>Disable {lifecycleTarget.display_name}</h2><p>Disabling this environment denies its traffic immediately and revokes active legacy and component session and refresh credentials in this environment. Re-enabling later does not restore those credentials.</p><p>Environment ID: <code>{lifecycleTarget.id}</code></p><label>Reason<textarea maxLength={500} required rows={3} value={lifecycleReason} onChange={(event) => setLifecycleReason(event.target.value)} /></label><label className="check-field"><input checked={lifecycleAcknowledged} onChange={(event) => setLifecycleAcknowledged(event.target.checked)} type="checkbox" />I understand active credentials in this environment will be revoked.</label><div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || !lifecycleAcknowledged || lifecycleReason.trim().length === 0} type="submit">Disable environment</button><button className="secondary-action" disabled={busy} onClick={() => selectEnvironmentLifecycle()} type="button">Cancel</button></div></form> : null}
    <ProblemNotice problem={problem} />
    {items ? <Table headers={["Environment", "Status", "Kind", "Created", "Actions"]} rows={items.map((item) => [<><strong>{item.display_name}</strong><br /><small>{item.id}</small></>, <><span className="state-badge">{item.status}</span>{item.status === "disabled" ? <><br /><small>{displayInstant(item.disabled_at)}</small></> : null}</>, item.kind, displayInstant(item.created_at), item.status === "disabled" ? <button className="small-action" disabled={busy || !canConfigure} onClick={() => void setEnvironmentEnabled(item, true)} type="button">Enable</button> : <button className="small-action small-action--danger" disabled={busy || !canConfigure} onClick={() => selectEnvironmentLifecycle(item)} type="button">Disable</button>])} /> : null}
  </div>;
}

export function SecretsPage() {
  const session = useConsoleSession();
  const [environmentID, setEnvironmentID] = useState("");
  const [page, setPage] = useState<SecretResourcePage>();
  const [rotationTarget, setRotationTarget] = useState<SecretResource>();
  const [deletionTarget, setDeletionTarget] = useState<SecretResource>();
  const [deletionConfirmation, setDeletionConfirmation] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired resource="secrets" />;
  const canManage = session.data.session?.capabilities.includes("manage_secrets") ?? false;

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
    event.preventDefault(); if (!validEnvironment()) return;
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
    event.preventDefault(); if (!rotationTarget) return;
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
    if (!deletionTarget || deletionConfirmation !== deletionTarget.name) return;
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
    {!canManage ? <div className="control-notice"><strong>Capability required</strong><span>The manage_secrets capability is required to list or mutate secret metadata.</span></div> : <>
      <div className="filter-bar"><label>Environment ID<input pattern="env_[A-Za-z0-9_-]{16,128}" required value={environmentID} onChange={(event) => { setEnvironmentID(event.target.value); setPage(undefined); setRotationTarget(undefined); setDeletionTarget(undefined); setDeletionConfirmation(""); }} /></label><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Load secret metadata</button></div>
      <form className="control-form" onSubmit={(event) => void create(event)}><h2>Create write-only secret</h2><div className="form-field-grid"><label>Secret name<input autoComplete="off" maxLength={63} name="name" pattern={resourceIdentifierPattern} required /></label><label>Secret value<input autoComplete="new-password" maxLength={1_048_576} name="value" required type="password" /></label></div><button className="primary-action" disabled={busy || !environmentIDPattern.test(environmentID)} type="submit">{busy ? "Working…" : "Create secret"}</button></form>
    </>}
    <ProblemNotice problem={problem} />
    {rotationTarget ? <form className="control-form" onSubmit={(event) => void rotate(event)}><h2>Rotate {rotationTarget.name}</h2><p>The current version ID is checked by the server. The replacement value is write-only and this input is cleared immediately on submission.</p><label>Replacement secret value<input autoComplete="new-password" maxLength={1_048_576} name="rotation_value" required type="password" /></label><div className="button-row"><button className="primary-action" disabled={busy} type="submit">Rotate secret</button><button className="secondary-action" disabled={busy} onClick={() => setRotationTarget(undefined)} type="button">Cancel</button></div></form> : null}
    {deletionTarget ? <section className="control-form destructive-confirmation" aria-labelledby="secret-deletion-title"><h2 id="secret-deletion-title">Permanently delete {deletionTarget.name}</h2><p>This tombstones every version of the logical secret. The name cannot be reused, and deletion succeeds only when the exact current version is unreferenced.</p><p>Current secret ID: <code>{deletionTarget.id}</code></p><label>Type <strong>{deletionTarget.name}</strong> to confirm<input autoComplete="off" maxLength={63} value={deletionConfirmation} onChange={(event) => setDeletionConfirmation(event.target.value)} /></label><div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || deletionConfirmation !== deletionTarget.name} onClick={() => void destroy()} type="button">Permanently delete secret</button><button className="secondary-action" disabled={busy} onClick={() => { setDeletionTarget(undefined); setDeletionConfirmation(""); }} type="button">Cancel deletion</button></div></section> : null}
    {page ? <><Table headers={["Name", "Version", "Algorithm", "Created", "Rotated", "Actions"]} rows={page.items.map((secret) => [<><strong>{secret.name}</strong><br /><small>{secret.id}</small></>, secret.version, secret.algorithm, displayInstant(secret.created_at), displayInstant(secret.rotated_at), <div className="resource-actions"><button className="small-action" disabled={busy || !canManage} onClick={() => { setRotationTarget(secret); setDeletionTarget(undefined); setDeletionConfirmation(""); }} type="button">Rotate</button><button className="small-action small-action--danger" disabled={busy || !canManage} onClick={() => { setDeletionTarget(secret); setDeletionConfirmation(""); setRotationTarget(undefined); }} type="button">Delete unreferenced</button></div>])} />{page.page.has_more && page.page.next_cursor ? paginationButton("Next page", busy, () => void load(page.page.next_cursor)) : null}</> : null}
  </div>;
}

export function UserOverridesPage() {
  const session = useConsoleSession();
  const [environmentID, setEnvironmentID] = useState("");
  const [userID, setUserID] = useState("");
  const [user, setUser] = useState<UserOverrideResource>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <AccessRequired resource="user overrides" />;
  const canInspect = session.data.session?.capabilities.includes("inspect_users") ?? false;
  const canConfigure = session.data.session?.capabilities.includes("activate_configuration") ?? false;

  function identifiersValid(): boolean {
    if (environmentIDPattern.test(environmentID) && userIDPattern.test(userID)) return true;
    setProblem(invalidResourceProblem("Enter canonical environment and application-user IDs before continuing."));
    return false;
  }

  async function inspect(): Promise<void> {
    if (!identifiersValid()) return;
    setBusy(true); setProblem(undefined);
    try { setUser((await adminRequest(queryPath(`/admin/v1/users/${userID}`, { environment_id: environmentID }), UserOverrideResourceSchema)).data); }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function replace(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!identifiersValid()) return;
    const data = new FormData(event.currentTarget); const localExpiry = String(data.get("expires_at") ?? "");
    const body: { expires_at?: string; limit_plan: string; reason: string } = { limit_plan: String(data.get("limit_plan")), reason: String(data.get("reason")) };
    if (localExpiry) {
      const expiry = new Date(localExpiry);
      if (Number.isNaN(expiry.getTime())) { setProblem(invalidResourceProblem("Choose a valid override expiration date and time.")); return; }
      body.expires_at = expiry.toISOString();
    }
    setBusy(true); setProblem(undefined);
    try { setUser((await adminRequest(queryPath(`/admin/v1/users/${userID}/limit-override`, { environment_id: environmentID }), UserOverrideResourceSchema, { method: "PUT", body })).data); }
    catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function clear(): Promise<void> {
    if (!identifiersValid()) return;
    setBusy(true); setProblem(undefined);
    try {
      await adminRequest(queryPath(`/admin/v1/users/${userID}/limit-override`, { environment_id: environmentID }), z.undefined(), { method: "DELETE" });
      setUser((current) => {
        if (!current) return current;
        const withoutOverride = { ...current };
        delete withoutOverride.limit_plan_override;
        return withoutOverride;
      });
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  return <div className="control-page">
    <PageHeading eyebrow="Governance" title="User overrides">Inspect one pseudonymous user and replace or clear only that user's server-validated limit-plan selection.</PageHeading>
    <div className="filter-bar"><label>Environment ID<input pattern="env_[A-Za-z0-9_-]{16,128}" required value={environmentID} onChange={(event) => { setEnvironmentID(event.target.value); setUser(undefined); }} /></label><label>User ID<input pattern="usr_[A-Za-z0-9_-]{16,128}" required value={userID} onChange={(event) => { setUserID(event.target.value); setUser(undefined); }} /></label><button className="secondary-action" disabled={busy || !canInspect} onClick={() => void inspect()} type="button">Inspect override</button></div>
    {!canInspect ? <div className="control-notice"><strong>Capability required</strong><span>The inspect_users capability is required to inspect this user.</span></div> : null}
    <ProblemNotice problem={problem} />
    {user ? <><section className="detail-card"><h2>User and active override</h2><dl><div><dt>User</dt><dd>{user.id}</dd></div><div><dt>Status</dt><dd>{user.status}</dd></div><div><dt>Limit plan</dt><dd>{user.limit_plan_override?.limit_plan ?? "No override"}</dd></div><div><dt>Expires</dt><dd>{displayInstant(user.limit_plan_override?.expires_at)}</dd></div></dl>{user.limit_plan_override ? <p>Reason: {user.limit_plan_override.reason}</p> : null}<h3>Normalized safe claims</h3><pre>{JSON.stringify(user.normalized_claims, null, 2)}</pre></section>
      {canConfigure ? <form className="control-form" onSubmit={(event) => void replace(event)}><h2>Replace limit-plan override</h2><div className="form-field-grid"><label>Limit plan<input maxLength={63} name="limit_plan" pattern={resourceIdentifierPattern} required /></label><label>Expiration (optional)<input name="expires_at" type="datetime-local" /></label></div><label>Reason<textarea maxLength={500} name="reason" required rows={3} /></label><div className="button-row"><button className="primary-action" disabled={busy} type="submit">Set override</button><button className="secondary-action" disabled={busy || !user.limit_plan_override} onClick={() => void clear()} type="button">Clear override</button></div></form> : <div className="control-notice"><strong>Read-only override</strong><span>The activate_configuration capability is required to replace or clear an override.</span></div>}
    </> : null}
  </div>;
}

function validStrongETag(value: string | undefined): value is string {
  return Boolean(value && value.startsWith('"') && value.endsWith('"') && !value.startsWith("W/") && !value.includes("\n") && !value.includes("\r"));
}

function structuralDiffPaths(before: unknown, after: unknown, path = "$"): string[] {
  if (Object.is(before, after)) return [];
  if (Array.isArray(before) && Array.isArray(after)) {
    const paths: string[] = [];
    for (let index = 0; index < Math.max(before.length, after.length); index += 1) {
      if (index >= before.length || index >= after.length) paths.push(`${path}[${index}]`);
      else paths.push(...structuralDiffPaths(before[index], after[index], `${path}[${index}]`));
    }
    return paths;
  }
  if (before && after && typeof before === "object" && typeof after === "object") {
    const left = before as Record<string, unknown>;
    const right = after as Record<string, unknown>;
    const paths: string[] = [];
    for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()) {
      const childPath = `${path}.${key}`;
      if (!(key in left) || !(key in right)) paths.push(childPath);
      else paths.push(...structuralDiffPaths(left[key], right[key], childPath));
    }
    return paths;
  }
  return [path];
}

export function ConfigurationRevisionsPage() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  const [environmentID, setEnvironmentID] = useState("");
  const [page, setPage] = useState<ConfigurationRevisionResourcePage>();
  const [active, setActive] = useState<ConfigurationRevisionResource>();
  const [activeETag, setActiveETag] = useState<string>();
  const [rollbackTarget, setRollbackTarget] = useState<ConfigurationRevisionResource>();
  const [rollbackReason, setRollbackReason] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const canConfigure = session.data?.mode === "configured"
    && (session.data.session?.capabilities.includes("activate_configuration") ?? false)
    && workspace?.application?.status !== "disabled"
    && workspace?.environment?.status !== "disabled";
  const selectedEnvironmentID = workspace?.environment?.id;
  const effectiveEnvironmentID = selectedEnvironmentID ?? environmentID;

  function validEnvironment(): boolean {
    if (environmentIDPattern.test(effectiveEnvironmentID)) return true;
    setProblem(invalidResourceProblem("Enter a canonical environment ID before continuing."));
    return false;
  }

  async function load(cursor?: string, selectedEnvironment = effectiveEnvironmentID): Promise<void> {
    if (!validEnvironment()) return;
    setBusy(true); setProblem(undefined);
    try {
      const history = await adminRequest(queryPath(`/admin/v1/environments/${selectedEnvironment}/config-revisions`, { page_size: "1", cursor }), ConfigurationRevisionResourcePageSchema);
      setPage(history.data); setRollbackTarget(undefined); setRollbackReason("");
      try {
        const current = await adminRequest(`/admin/v1/environments/${selectedEnvironment}/config`, ConfigurationRevisionResourceSchema);
        setActive(current.data); setActiveETag(current.etag);
      } catch (error) {
        const activeProblem = problemFromError(error);
        if (activeProblem.code !== "resource_not_found") throw error;
        setActive(undefined); setActiveETag(undefined);
      }
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function rollback(target: ConfigurationRevisionResource, reason: string): Promise<void> {
    const trimmedReason = reason.trim();
    if (!trimmedReason || trimmedReason.length > 500 || /[\r\n\0]/.test(trimmedReason)) {
      setProblem(invalidResourceProblem("Provide a 1-500 character rollback reason without line breaks."));
      return;
    }
    setBusy(true); setProblem(undefined);
    try {
      const current = await adminRequest(`/admin/v1/environments/${effectiveEnvironmentID}/config`, ConfigurationRevisionResourceSchema);
      if (!validStrongETag(current.etag)) {
        setProblem({ code: "etag_required", detail: "The server omitted the strong ETag required for safe rollback.", retryable: true, status: 0, title: "Rollback precondition unavailable" });
        return;
      }
      const rolledBack = (await adminRequest(`/admin/v1/environments/${effectiveEnvironmentID}/rollback`, ConfigurationRevisionResourceSchema, { method: "POST", etag: current.etag, body: { revision_id: target.id, reason: trimmedReason } })).data;
      setActive(rolledBack); setActiveETag(undefined);
      setRollbackTarget(undefined); setRollbackReason("");
      setPage((currentPage) => currentPage ? { ...currentPage, items: currentPage.items.map((item) => item.id === rolledBack.id ? rolledBack : item) } : currentPage);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  const item = page?.items[0];
  const unpublished = Boolean(item && ["draft", "valid", "invalid"].includes(item.state));
  const rollbackAllowed = Boolean(canConfigure && active && item?.activated_at && item.id !== active.id && validStrongETag(activeETag));
  const rollbackPaths = active && rollbackTarget ? structuralDiffPaths(active.document, rollbackTarget.document) : [];
  useEffect(() => {
    if (!selectedEnvironmentID) return;
    let cancelled = false;
    void Promise.resolve().then(() => {
      if (!cancelled) void load(undefined, selectedEnvironmentID);
    });
    return () => { cancelled = true; };
    // The selected environment is the canonical trigger; load intentionally reads its current helpers.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEnvironmentID]);
  if (session.data?.mode !== "configured") return <AccessRequired resource="configuration revisions" />;
  return <div className="control-page">
    <PageHeading eyebrow="Operations" title="Configuration revisions">Inspect immutable redaction-safe history one full document at a time and atomically reactivate a previously activated revision.</PageHeading>
    {workspace?.environment ? <section className={`production-context production-context--${workspace.environment.kind}`}><strong>{workspace.application?.display_name} / {workspace.environment.display_name}</strong><span>Newest server revision · one full document per page</span><code>{workspace.environment.id}</code><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Refresh revisions</button></section> : <div className="filter-bar"><label>Environment ID<input pattern="env_[A-Za-z0-9_-]{16,128}" required value={environmentID} onChange={(event) => { setEnvironmentID(event.target.value); setPage(undefined); setActive(undefined); setActiveETag(undefined); }} /></label><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Load newest revision</button></div>}
    <ProblemNotice problem={problem} />
    {active ? <p className="resource-result">Active revision: <code>{active.id}</code> (version {active.version})</p> : page ? <div className="control-notice"><strong>No active revision</strong><span>History can be inspected, but rollback requires an active ETag precondition.</span></div> : null}
    {item ? <section className="detail-card"><div className="detail-card__heading"><div><h2>Revision {item.version}</h2><p><code>{item.id}</code></p></div><span className="state-badge">{item.id === active?.id ? "active" : item.state}</span></div><dl><div><dt>Created</dt><dd>{displayInstant(item.created_at)}</dd></div><div><dt>Created by</dt><dd>{item.created_by}</dd></div><div><dt>First activated</dt><dd>{displayInstant(item.activated_at)}</dd></div><div><dt>Validation</dt><dd>{item.validation ? item.validation.valid ? "valid" : "invalid" : "not recorded"}</dd></div></dl>{unpublished ? <div className="control-notice"><strong>Unpublished server revision</strong><span>It does not affect traffic. The Admin API has no abandon/delete operation, so this audited revision cannot be removed from the console.</span><button className="small-action" disabled type="button">Abandon unavailable</button></div> : null}<details><summary>Inspect redaction-safe configuration document</summary><pre>{JSON.stringify(item.document, null, 2)}</pre></details><div className="button-row"><button className="primary-action" disabled={busy || !rollbackAllowed} onClick={() => { setRollbackTarget(item); setRollbackReason(""); }} type="button">Review rollback</button>{!canConfigure ? <small>The activate_configuration capability is required.</small> : !item.activated_at ? <small>Only a previously activated valid revision can be restored.</small> : item.id === active?.id ? <small>This revision is already active.</small> : !validStrongETag(activeETag) ? <small>A strong active-revision ETag is required.</small> : null}</div></section> : page ? <div className="control-notice"><strong>No revisions</strong><span>This environment has no configuration history.</span></div> : null}
    {rollbackTarget && active ? <section aria-labelledby="rollback-review-heading" className="publish-review publish-review--valid"><p className="eyebrow">Rollback review</p><h2 id="rollback-review-heading">Replace active revision {active.version} with revision {rollbackTarget.version}?</h2><div className="impact-grid"><div><strong>Traffic changes atomically</strong><span>The target document becomes active after a fresh strong-ETag check.</span></div><div><strong>{rollbackPaths.length} structural path change(s)</strong><span>Values remain hidden from this review; inspect both redaction-safe documents above if needed.</span></div><div><strong>Rollback creates new activation evidence</strong><span>Revoked credentials and external side effects are not restored.</span></div></div>{rollbackPaths.length ? <ul>{rollbackPaths.slice(0, 100).map((path) => <li key={path}><code>{path}</code></li>)}</ul> : <p>No document field changes were detected; only revision identity would change.</p>}{rollbackPaths.length > 100 ? <p>Showing the first 100 changed paths.</p> : null}<label>Operator reason<textarea maxLength={500} onChange={(event) => setRollbackReason(event.target.value)} required rows={3} value={rollbackReason} /></label><div className="button-row"><button className="secondary-action" disabled={busy} onClick={() => { setRollbackTarget(undefined); setRollbackReason(""); }} type="button">Cancel rollback</button><button className="primary-action primary-action--danger" disabled={busy || !rollbackReason.trim()} onClick={() => void rollback(rollbackTarget, rollbackReason)} type="button">Confirm rollback to revision {rollbackTarget.version}</button></div></section> : null}
    {page ? <div className="button-row">{paginationButton("Newest", busy, () => void load())}{page.page.has_more && page.page.next_cursor ? paginationButton("Next older revision", busy, () => void load(page.page.next_cursor)) : null}</div> : null}
  </div>;
}

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  AdminSessionMetadataPageSchema,
  adminRequest,
  DoctorReportSchema,
  NoContentSchema,
  queryPath,
  RevisionSchema,
  type AdminSessionMetadata,
  type AdminSessionMetadataPage,
  type DoctorReport
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { useConsoleCompatibility } from "../app/console-compatibility-context";
import { useDirtyEditProtection } from "../app/use-dirty-edit-protection";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import {
  ConfigurationTransferError,
  activateConfigurationImport,
  readConfigurationFile,
  redactionSafeConfigurationYAML,
  stageConfigurationImport,
  type ConfigurationDocument,
  type ConfigurationTransferResult
} from "./configuration-transfer";
import {
  consoleContractVersion,
  consoleProtocolVersion,
  evaluateSettingsCompatibility
} from "./settings-compatibility";

function displayInstant(value?: string): string {
  return value ? new Date(value).toLocaleString() : "None retained";
}

function localProblem(error: unknown): AdminProblem {
  if (error instanceof ConfigurationTransferError) {
    return {
      code: "configuration_import_invalid",
      detail: error.message,
      retryable: false,
      status: 0,
      title: "Configuration import rejected"
    };
  }
  return problemFromError(error);
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert">
    <strong>{problem.title}</strong><span>{problem.detail}</span>
    <small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}{problem.operationId ? ` · Operation: ${problem.operationId}` : ""}</small>
    {problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}
  </div> : null;
}

function downloadText(contents: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: "application/yaml;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function SettingsPage() {
  const consoleSession = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const refreshCompatibility = consoleCompatibility.refresh;
  const workspace = useOptionalWorkspace();
  const [doctor, setDoctor] = useState<DoctorReport>();
  const [sessions, setSessions] = useState<AdminSessionMetadataPage>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [notice, setNotice] = useState<string>();
  const [busy, setBusy] = useState<"load" | "export" | "parse" | "stage" | "activate" | "revoke">();
  const [importDocument, setImportDocument] = useState<ConfigurationDocument>();
  const [importEnvironmentID, setImportEnvironmentID] = useState<string>();
  const [importName, setImportName] = useState<string>();
  const [staged, setStaged] = useState<ConfigurationTransferResult>();
  const [reviewed, setReviewed] = useState(false);
  const [activationPhrase, setActivationPhrase] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<AdminSessionMetadata>();
  const [revokePhrase, setRevokePhrase] = useState("");

  const configured = consoleSession.data?.mode === "configured";
  const canManageOwners = consoleSession.data?.session?.capabilities.includes("manage_owners") ?? false;
  const canActivateConfiguration = consoleSession.data?.session?.capabilities.includes("activate_configuration") ?? false;
  const environment = workspace?.environment;
  const environmentID = environment?.id;
  const status = consoleCompatibility.status;
  const compatibility = useMemo(
    () => status ? evaluateSettingsCompatibility(status) : undefined,
    [status]
  );
  const expectedActivationPhrase = environment ? `ACTIVATE ${environment.slug}` : "";
  const expectedRevokePhrase = revokeTarget ? `REVOKE ${revokeTarget.id}` : "";
  const importMatchesEnvironment = Boolean(environmentID && importEnvironmentID === environmentID);
  const currentImportDocument = importMatchesEnvironment ? importDocument : undefined;
  const currentImportName = importMatchesEnvironment ? importName : undefined;
  const currentStaged = importMatchesEnvironment ? staged : undefined;
  const importPending = Boolean(currentImportDocument && currentStaged?.revision.state !== "active");
  useDirtyEditProtection(importPending);

  const refresh = useCallback(async (signal?: AbortSignal): Promise<void> => {
    if (!configured) return;
    setBusy("load");
    setProblem(undefined);
    setNotice(undefined);
    try {
      const nextStatus = await refreshCompatibility();
      if (!nextStatus) return;
      if (signal?.aborted) return;
      const doctorRequest = adminRequest("/admin/v1/system/doctor", DoctorReportSchema, { signal });
      const sessionRequest = canManageOwners && nextStatus.server_capabilities.includes("admin_session_management")
        ? adminRequest(
          queryPath("/admin/v1/admin-sessions", { page_size: "100" }),
          AdminSessionMetadataPageSchema,
          { signal }
        )
        : Promise.resolve(undefined);
      const [doctorResult, sessionResult] = await Promise.allSettled([doctorRequest, sessionRequest]);
      if (signal?.aborted) return;
      if (doctorResult.status === "fulfilled") setDoctor(doctorResult.value.data);
      if (sessionResult.status === "fulfilled") setSessions(sessionResult.value?.data);
      const failure = doctorResult.status === "rejected"
        ? doctorResult.reason
        : sessionResult.status === "rejected"
          ? sessionResult.reason
          : undefined;
      if (failure) {
        setProblem(problemFromError(failure));
      }
    } catch (error) {
      if (!signal?.aborted) setProblem(problemFromError(error));
    } finally {
      if (!signal?.aborted) setBusy(undefined);
    }
  }, [canManageOwners, configured, refreshCompatibility]);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => void refresh(controller.signal), 0);
    return () => { window.clearTimeout(timeout); controller.abort(); };
  }, [refresh]);

  async function loadSessionPage(cursor?: string): Promise<void> {
    setBusy("load"); setProblem(undefined); setNotice(undefined);
    try {
      setSessions((await adminRequest(queryPath("/admin/v1/admin-sessions", {
        cursor,
        page_size: "100"
      }), AdminSessionMetadataPageSchema)).data);
    } catch (error) { setProblem(problemFromError(error)); }
    finally { setBusy(undefined); }
  }

  async function exportConfiguration(): Promise<void> {
    if (!environmentID || !environment) return;
    setBusy("export"); setProblem(undefined); setNotice(undefined);
    try {
      const active = (await adminRequest(`/admin/v1/environments/${environmentID}/config`, RevisionSchema)).data;
      const yaml = redactionSafeConfigurationYAML(active.document);
      downloadText(yaml, `latchway-${environment.slug}-configuration.yaml`);
      setNotice(`Downloaded redaction-safe YAML for ${environment.display_name}.`);
    } catch (error) { setProblem(localProblem(error)); }
    finally { setBusy(undefined); }
  }

  async function chooseImport(file?: File): Promise<void> {
    setProblem(undefined); setNotice(undefined); setImportDocument(undefined); setImportEnvironmentID(undefined); setImportName(undefined);
    setStaged(undefined); setReviewed(false); setActivationPhrase("");
    if (!file) return;
    setBusy("parse");
    try {
      setImportDocument(await readConfigurationFile(file));
      setImportEnvironmentID(environmentID);
      setImportName(file.name);
      setNotice(`${file.name} passed local bounded YAML/JSON checks. Nothing has been sent to the server.`);
    } catch (error) { setProblem(localProblem(error)); }
    finally { setBusy(undefined); }
  }

  async function stageImport(): Promise<void> {
    if (!consoleCompatibility.mutationAllowed || !currentImportDocument || !environmentID) return;
    setBusy("stage"); setProblem(undefined); setNotice(undefined);
    try {
      const result = await stageConfigurationImport({ document: currentImportDocument, environmentID });
      setStaged(result); setReviewed(false); setActivationPhrase("");
      setNotice(result.report.valid
        ? "The immutable draft is valid and its redacted server plan is ready for explicit review."
        : "The server rejected the immutable draft. It was not activated.");
    } catch (error) { setProblem(localProblem(error)); }
    finally { setBusy(undefined); }
  }

  async function activateImport(): Promise<void> {
    if (!consoleCompatibility.mutationAllowed || !currentImportDocument || !environmentID || !reviewed || activationPhrase !== expectedActivationPhrase) return;
    setBusy("activate"); setProblem(undefined); setNotice(undefined);
    try {
      if (!currentStaged) return;
      const result = await activateConfigurationImport({
        document: currentImportDocument,
        environmentID,
        staged: currentStaged
      });
      setStaged(result);
      if (result.revision.state === "active") {
        setNotice(`Revision ${result.revision.id} is active. The server accepted its exact strong ETag.`);
      } else {
        setReviewed(false);
        setNotice("Server validation changed before activation. Review the updated report and plan; nothing was activated.");
      }
    } catch (error) { setProblem(localProblem(error)); }
    finally { setBusy(undefined); }
  }

  async function revokeSession(): Promise<void> {
    if (!consoleCompatibility.mutationAllowed || !revokeTarget || revokePhrase !== expectedRevokePhrase) return;
    setBusy("revoke"); setProblem(undefined); setNotice(undefined);
    try {
      await adminRequest(`/admin/v1/admin-sessions/${revokeTarget.id}/revoke`, NoContentSchema, { method: "POST" });
      setSessions((current) => current ? {
        ...current,
        items: current.items.map((item) => item.id === revokeTarget.id ? { ...item, status: "revoked" } : item)
      } : current);
      setNotice(revokeTarget.current
        ? "The current administrator session was revoked. Sign in again before another protected action."
        : `Session ${revokeTarget.id} was revoked immediately.`);
      setRevokeTarget(undefined); setRevokePhrase("");
    } catch (error) { setProblem(problemFromError(error)); }
    finally { setBusy(undefined); }
  }

  if (!configured) return <section className="empty-state"><h1>Sign in to inspect instance settings.</h1></section>;

  const mutationAllowed = consoleCompatibility.mutationAllowed;
  const importAllowed = mutationAllowed && canActivateConfiguration && environment?.status === "active";
  const sessionMutationAllowed = mutationAllowed && canManageOwners
    && status?.server_capabilities.includes("admin_session_management") === true;

  return <div className="control-page">
    <section className="page-heading" aria-labelledby="settings-heading"><div>
      <p className="eyebrow">Administration</p><h1 id="settings-heading">Settings and compatibility</h1>
      <p>Inspect the running contract, privacy posture, configuration transfer workflow, and credential-free administrator sessions through the canonical Admin API.</p>
    </div><button className="secondary-action" disabled={Boolean(busy) || consoleCompatibility.isFetching} onClick={() => void refresh()} type="button">{busy === "load" || consoleCompatibility.isFetching ? "Refreshing…" : "Refresh settings"}</button></section>

    <ProblemNotice problem={problem} />
    {notice ? <div className="control-notice" role="status"><strong>Settings update</strong><span>{notice}</span></div> : null}

    {compatibility ? <section aria-labelledby="compatibility-heading" className="detail-card">
      <div className="detail-card__heading"><div><p className="eyebrow">Negotiated compatibility</p><h2 id="compatibility-heading">Server and console contract</h2></div><span className={`state-badge state-badge--${compatibility.readOnlySafeMode ? "degraded" : "available"}`}>{compatibility.readOnlySafeMode ? "read-only safe mode" : "compatible"}</span></div>
      {compatibility.readOnlySafeMode ? <div className="control-notice control-notice--error" role="status"><strong>Read-only safe mode is active</strong><span>Configuration activation and session revocation are disabled. Reads and redaction-safe export remain available.</span><ul>{compatibility.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></div> : <div className="control-notice" role="status"><strong>Mutation compatibility confirmed</strong><span>Contract {consoleContractVersion}, protocol {consoleProtocolVersion}, administrative database/schema readiness, and all required v1 server capabilities are present.</span></div>}
      <dl className="system-status-grid">
        <div><dt>Server build</dt><dd>{status?.server_version}</dd></div><div><dt>Console contract</dt><dd>{consoleContractVersion}</dd></div>
        <div><dt>Server contract</dt><dd>{status?.contract_version}</dd></div><div><dt>Protocols</dt><dd>{status?.protocol_versions.join(", ")}</dd></div>
        <div><dt>Required protocol</dt><dd>{consoleProtocolVersion}</dd></div><div><dt>Database schema</dt><dd>{status?.database_schema_version}</dd></div>
        <div><dt>Process role</dt><dd>{status?.role}</dd></div><div><dt>Admin mutations ready</dt><dd>{status?.mutation_ready ? "Yes" : "No"}</dd></div>
        <div><dt>Traffic ready</dt><dd>{status?.ready ? "Yes" : "No"}</dd></div>
        <div><dt>Live refresh hints</dt><dd>{status?.server_capabilities.includes("admin_event_stream") ? "SSE capability negotiated" : "Polling and manual refresh fallback"}</dd></div>
      </dl>
      <h3>Negotiated server capabilities</h3><ul aria-label="Negotiated server capabilities" className="tag-list">{status?.server_capabilities.map((capability) => <li key={capability}><code>{capability}</code></li>)}</ul>
    </section> : <section className="detail-card" aria-busy={busy === "load"}><h2>Compatibility unavailable</h2><p>The console keeps mutations closed until authenticated system status is loaded and validated.</p></section>}

    <section aria-labelledby="privacy-heading" className="detail-card">
      <div className="detail-card__heading"><div><p className="eyebrow">Retention and privacy</p><h2 id="privacy-heading">Authoritative operational posture</h2></div></div>
      <div className="endpoint-grid">
        <article className="endpoint-card"><h3>Request and response bodies</h3><p><strong>Unavailable and off in v1.</strong> There is no browser toggle and this console does not display production body content.</p></article>
        <article className="endpoint-card"><h3>Process OpenTelemetry</h3><p><strong>Deployment-configured.</strong> Operators configure process OTEL outside the browser; Settings does not pretend to mutate it.</p></article>
        <article className="endpoint-card"><h3>Anonymous product telemetry</h3><p><strong>None.</strong> The Console does not emit anonymous product analytics.</p></article>
      </div>
      {doctor ? <dl className="system-status-grid">
        <div><dt>Retention policy</dt><dd>{doctor.facts.retention.policy_mode.replaceAll("_", " ")}</dd></div>
        <div><dt>Admin sessions</dt><dd>{doctor.facts.retention.admin_session_retention_hours} hours</dd></div>
        <div><dt>Job history</dt><dd>{doctor.facts.retention.job_history_retention_hours} hours</dd></div>
        <div><dt>Runtime instances</dt><dd>{doctor.facts.retention.runtime_instance_retention_hours} hours</dd></div>
        <div><dt>Oldest audit event</dt><dd>{displayInstant(doctor.facts.retention.oldest_audit_at)}</dd></div>
        <div><dt>Oldest request record</dt><dd>{displayInstant(doctor.facts.retention.oldest_request_at)}</dd></div>
        <div><dt>Oldest usage record</dt><dd>{displayInstant(doctor.facts.retention.oldest_usage_at)}</dd></div>
        <div><dt>Doctor generated</dt><dd>{displayInstant(doctor.generated_at)}</dd></div>
      </dl> : <p>Doctor retention facts will appear after the canonical report loads.</p>}
    </section>

    <section aria-labelledby="transfer-heading" className="detail-card">
      <div className="detail-card__heading"><div><p className="eyebrow">Configuration transfer</p><h2 id="transfer-heading">Export, validate, review, activate</h2><p>{environment ? <>Active environment: <strong>{environment.display_name}</strong> (<code>{environment.id}</code>)</> : "Select an environment in the workspace header."}</p></div><button className="secondary-action" disabled={!environmentID || Boolean(busy)} onClick={() => void exportConfiguration()} type="button">{busy === "export" ? "Exporting…" : "Download redaction-safe YAML"}</button></div>
      <label>YAML or JSON configuration file (maximum 1 MiB)<input accept=".json,.yaml,.yml,application/json,application/yaml,text/yaml" aria-describedby="configuration-file-help" disabled={!importAllowed || Boolean(busy)} onChange={(event) => void chooseImport(event.currentTarget.files?.[0])} type="file" /></label>
      <small id="configuration-file-help">One top-level object only. Aliases, anchors, merge keys, custom tags, duplicate keys, non-finite values, and prototype-bearing objects are rejected locally.</small>
      {currentImportName ? <div className="control-notice"><strong>Local file ready</strong><span>{currentImportName}</span><button className="secondary-action" disabled={!importAllowed || Boolean(busy)} onClick={() => void stageImport()} type="button">{busy === "stage" ? "Validating…" : "Create immutable draft and show plan"}</button></div> : null}
      {!canActivateConfiguration ? <div className="control-notice"><strong>Capability required</strong><span>The activate_configuration administrator capability is required to stage or activate imports.</span></div> : null}
      {environment?.status === "disabled" ? <div className="control-notice"><strong>Environment disabled</strong><span>Import mutations remain closed until the environment is enabled. Redaction-safe export remains available.</span></div> : null}
      {compatibility?.readOnlySafeMode ? <div className="control-notice"><strong>Safe-mode restriction</strong><span>Resolve compatibility before importing or activating configuration.</span></div> : null}
      {currentStaged ? <div className="configuration-review">
        <h3>Server validation</h3><p><strong>{currentStaged.report.valid ? "Valid" : "Invalid"}</strong> · immutable revision <code>{currentStaged.revision.id}</code> · state {currentStaged.revision.state}</p>
        {currentStaged.report.issues.length > 0 ? <ul aria-label="Server validation issues">{currentStaged.report.issues.map((issue, index) => <li key={`${issue.code}-${issue.path}-${index}`}><strong>{issue.severity}: {issue.code}</strong> at <code>{issue.path}</code> — {issue.message}</li>)}</ul> : <p>No server validation issues.</p>}
        <h3>Redacted structural plan</h3>
        {currentStaged.plan ? <><ul aria-label="Redacted configuration plan">{currentStaged.plan.changes.map((change, index) => <li key={`${change.operation}-${change.path}-${index}`}><strong>{change.operation}</strong> <code>{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul>{currentStaged.plan.warnings.length > 0 ? <ul aria-label="Configuration plan warnings">{currentStaged.plan.warnings.map((warning, index) => <li key={`${warning.code}-${warning.path}-${index}`}>{warning.code} at <code>{warning.path}</code>: {warning.message}</li>)}</ul> : null}</> : <p>No active base revision exists, so the server has no comparison plan.</p>}
        {currentStaged.report.valid && currentStaged.revision.state !== "active" ? <form aria-labelledby="activation-review-heading" className="control-form" onSubmit={(event) => { event.preventDefault(); void activateImport(); }}>
          <h3 id="activation-review-heading">Explicit activation review</h3><p>Activation is a separate server mutation. Revalidation and the strong ETag for this exact immutable draft are required again.</p>
          <label className="check-field"><input checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} type="checkbox" />I reviewed every validation issue, plan change, and warning shown above.</label>
          <label>Type <code>{expectedActivationPhrase}</code> to activate<input autoComplete="off" disabled={!reviewed} onChange={(event) => setActivationPhrase(event.target.value)} value={activationPhrase} /></label>
          <button className="primary-action" disabled={!importAllowed || Boolean(busy) || !reviewed || activationPhrase !== expectedActivationPhrase} type="submit">{busy === "activate" ? "Activating…" : "Activate reviewed revision"}</button>
        </form> : null}
      </div> : null}
      {environmentID ? <details><summary>Equivalent CLI commands</summary><pre><code>{`latchway config pull --environment ${environmentID} --format yaml\nlatchway config apply --environment ${environmentID} --file environment.yaml --dry-run\nlatchway config apply --environment ${environmentID} --file environment.yaml`}</code></pre></details> : null}
    </section>

    <section aria-labelledby="sessions-heading" className="detail-card">
      <div className="detail-card__heading"><div><p className="eyebrow">Administrator access</p><h2 id="sessions-heading">Active session inventory</h2><p>Only credential-free metadata is returned. Revocation takes effect immediately and does not expose or restore credentials.</p></div><button className="secondary-action" disabled={!canManageOwners || Boolean(busy)} onClick={() => void loadSessionPage()} type="button">Refresh sessions</button></div>
      {!canManageOwners ? <div className="control-notice"><strong>Owner access required</strong><span>The manage_owners capability is required to list or revoke administrator sessions.</span></div> : !status?.server_capabilities.includes("admin_session_management") ? <div className="control-notice"><strong>Server capability unavailable</strong><span>This server does not negotiate administrator session management.</span></div> : null}
      {sessions ? <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Administrator</th><th>Created</th><th>Last seen</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead><tbody>{sessions.items.map((item) => <tr key={item.id}><td>{item.administrator.email}<br /><code>{item.id}</code>{item.current ? <><br /><strong>Current session</strong></> : null}</td><td>{displayInstant(item.created_at)}</td><td>{displayInstant(item.last_seen_at)}</td><td>{displayInstant(item.expires_at)}</td><td>{item.status}</td><td><button aria-label={`Review revoke session ${item.id}`} className="small-action" disabled={!sessionMutationAllowed || Boolean(busy) || item.status !== "active"} onClick={() => { setRevokeTarget(item); setRevokePhrase(""); }} type="button">Review revoke</button></td></tr>)}</tbody></table>{sessions.page.has_more ? <button className="secondary-action" disabled={Boolean(busy)} onClick={() => void loadSessionPage(sessions.page.next_cursor)} type="button">Next session page</button> : null}</div> : null}
      {revokeTarget ? <form aria-labelledby="revoke-session-heading" className="control-form" onSubmit={(event) => { event.preventDefault(); void revokeSession(); }}>
        <h3 id="revoke-session-heading">Revoke {revokeTarget.current ? "the current" : "administrator"} session?</h3><p>This immediately invalidates <code>{revokeTarget.id}</code> for {revokeTarget.administrator.email}. It cannot be restored; the administrator must authenticate again.</p>
        <label>Type <code>{expectedRevokePhrase}</code> to revoke immediately<input autoComplete="off" aria-label="Typed session revocation confirmation" onChange={(event) => setRevokePhrase(event.target.value)} value={revokePhrase} /></label>
        <div className="button-row"><button className="primary-action primary-action--danger" disabled={!sessionMutationAllowed || Boolean(busy) || revokePhrase !== expectedRevokePhrase} type="submit">{busy === "revoke" ? "Revoking…" : "Revoke session immediately"}</button><button className="secondary-action" disabled={Boolean(busy)} onClick={() => { setRevokeTarget(undefined); setRevokePhrase(""); }} type="button">Cancel</button></div>
      </form> : null}
    </section>
  </div>;
}

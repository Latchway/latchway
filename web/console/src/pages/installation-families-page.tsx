import { type ReactNode, useState } from "react";

import {
  adminRequest,
  ClientComponentSchema,
  InstallationFamilyPageSchema,
  InstallationFamilySchema,
  queryPath,
  type ClientComponent,
  type InstallationFamily,
  type InstallationFamilyPage
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";

const environmentInputPattern = "env_[A-Za-z0-9_-]{16,128}";
const applicationUserInputPattern = "usr_[A-Za-z0-9_-]{16,128}";
const compatibilityReference = "https://docs.latchway.dev/reference/compatibility";

function initialFilter(name: "environment_id" | "user_id"): string {
  return typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get(name) ?? "";
}

function PageHeading({ children }: { children: ReactNode }) {
  return <section className="page-heading"><div><p className="eyebrow">Identity &amp; trust</p><h1>Installation families</h1><p>{children}</p></div></section>;
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
}

function Table({ headers, rows }: { headers: string[]; rows: ReactNode[][] }) {
  return <div className="data-table-wrap"><table className="data-table"><thead><tr>{headers.map((header) => <th key={header} scope="col">{header}</th>)}</tr></thead><tbody>{rows.length ? rows.map((row, rowIndex) => <tr key={rowIndex}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>) : <tr><td colSpan={headers.length}>No matching records.</td></tr>}</tbody></table></div>;
}

function time(value?: string): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function label(value: string): string {
  return value.replaceAll("_", " ");
}

function cost(value: number): string {
  return `${value.toLocaleString()} nUSD`;
}

function TrustGraphNode({
  component,
  components,
  disabled,
  onSelect
}: {
  component: ClientComponent;
  components: ClientComponent[];
  disabled: boolean;
  onSelect: (componentID: string) => void;
}) {
  const children = components.filter((candidate) => candidate.parent_component_id === component.id);
  return <li className="trust-graph__branch"><button className="trust-node" disabled={disabled} onClick={() => onSelect(component.id)} type="button"><span className="trust-node__title">{component.definition_id}</span><span>{label(component.kind)} · {label(component.trust_source)}</span><span>{component.status} · {component.granted_features.join(", ")}</span></button>{children.length ? <ul>{children.map((child) => <TrustGraphNode component={child} components={components} disabled={disabled} key={child.id} onSelect={onSelect} />)}</ul> : null}</li>;
}

function TrustGraph({ family, disabled, onSelect }: { family: InstallationFamily; disabled: boolean; onSelect: (componentID: string) => void }) {
  const components = family.components ?? [];
  const root = components.find((component) => component.id === family.root_component_id);
  return <section className="trust-graph" aria-label="Installation Family trust graph"><div className="detail-card__heading"><div><h3>Component trust graph</h3><p>Edges show the persisted trust parent. Select a node to inspect exact provenance and its independent session family.</p></div></div>{root ? <ul className="trust-graph__roots"><TrustGraphNode component={root} components={components} disabled={disabled} onSelect={onSelect} /></ul> : <p>The family response did not contain its root component.</p>}</section>;
}

function FamilyMetrics({ family }: { family: InstallationFamily }) {
  return <section className="metric-grid"><article><span>Components</span><strong>{family.component_count.toLocaleString()}</strong></article><article><span>Requests</span><strong>{family.request_count.toLocaleString()}</strong></article><article><span>Input tokens</span><strong>{family.usage.input_tokens.toLocaleString()}</strong></article><article><span>Output tokens</span><strong>{family.usage.output_tokens.toLocaleString()}</strong></article><article><span>Total tokens</span><strong>{family.usage.total_tokens.toLocaleString()}</strong></article><article><span>Cost</span><strong>{cost(family.usage.cost_nano_usd)}</strong></article></section>;
}

function ComponentDetail({ component, busy, canRevoke, familyActive, hasReason, onReattest, onRevoke }: { component: ClientComponent; busy: boolean; canRevoke: boolean; familyActive: boolean; hasReason: boolean; onReattest: () => void; onRevoke: () => void }) {
  const terminal = component.status === "revoked" || component.status === "replaced";
  return <section className="detail-card" aria-labelledby="component-detail-heading"><div className="detail-card__heading"><div><p className="eyebrow">Client component</p><h2 id="component-detail-heading">{component.definition_id}</h2><p>{component.id} · {label(component.platform)} · {label(component.kind)}</p></div><div className="button-row"><button className="secondary-action" disabled={!canRevoke || busy || !hasReason || !familyActive || component.status !== "active"} onClick={onReattest} type="button">Require re-attestation</button><button className="primary-action primary-action--danger" disabled={!canRevoke || busy || !hasReason || terminal} onClick={onRevoke} type="button">Revoke component</button></div></div>
    {component.is_root ? <p className="control-notice component-warning"><strong>Root boundary</strong><span>Revoking this root revokes the complete family and every descendant credential.</span></p> : null}
    <p><small>Re-attestation expires this component subtree's trust and refresh credentials while already-issued access grants live only to their existing expiry. Sibling components are unchanged unless this is the root.</small></p>
    <h3>Trust provenance</h3><dl><div><dt>Trust source</dt><dd>{label(component.trust_source)}</dd></div><div><dt>Provider</dt><dd>{component.attestation_provider ?? "—"}</dd></div><div><dt>Parent component</dt><dd>{component.parent_component_id ?? "root"}</dd></div><div><dt>Parent attestation event</dt><dd>{component.parent_attestation_event_id ?? "—"}</dd></div><div><dt>Verified</dt><dd>{time(component.trust_verified_at)}</dd></div><div><dt>Trust expires</dt><dd>{time(component.trust_expires_at)}</dd></div></dl>
    {component.delegation ? <section className="provenance-panel"><h3>Delegation receipt</h3><dl><div><dt>Delegation</dt><dd>{component.delegation.id}</dd></div><div><dt>Configuration revision</dt><dd>{component.delegation.configuration_revision_id}</dd></div><div><dt>Trust level</dt><dd>{label(component.delegation.trust_level)}</dd></div><div><dt>Feature scopes</dt><dd>{component.delegation.feature_scopes.join(", ")}</dd></div><div><dt>Identity expires</dt><dd>{time(component.delegation.identity_expires_at)}</dd></div><div><dt>Attestation expires</dt><dd>{time(component.delegation.attestation_expires_at)}</dd></div><div><dt>Delegation expires</dt><dd>{time(component.delegation.expires_at)}</dd></div><div><dt>Consumed</dt><dd>{time(component.delegation.consumed_at)}</dd></div></dl></section> : null}
    <h3>Component key and grants</h3><dl><div><dt>Definition</dt><dd>{component.definition_id}</dd></div><div><dt>Component key</dt><dd>{component.component_key_id}</dd></div><div><dt>DPoP thumbprint</dt><dd><code>{component.dpop_jkt}</code></dd></div><div><dt>Key storage claim</dt><dd>{label(component.key_storage_claim)}</dd></div><div><dt>Granted features</dt><dd>{component.granted_features.join(", ")}</dd></div><div><dt>Status</dt><dd>{component.status}</dd></div><div><dt>Last activity</dt><dd>{time(component.last_seen_at)}</dd></div><div><dt>App / SDK version</dt><dd>{component.app_version ?? "—"} / {component.sdk_version ?? "—"}</dd></div></dl>
    <h3>Session and reuse</h3><dl><div><dt>Session family</dt><dd>{component.session_family_id ?? "—"}</dd></div><div><dt>Session status</dt><dd>{component.session_status ?? "—"}</dd></div><div><dt>Access expires</dt><dd>{time(component.session_expires_at)}</dd></div><div><dt>Closed session families</dt><dd>{component.session_failure_count.toLocaleString()}</dd></div><div><dt>Refresh reuse events</dt><dd>{component.refresh_reuse_count.toLocaleString()}</dd></div><div><dt>Revoked</dt><dd>{time(component.revoked_at)}</dd></div><div><dt>Revocation reason</dt><dd>{component.revocation_reason ?? "—"}</dd></div></dl>
    <h3>Usage and cost</h3><Table headers={["Requests", "Logical requests", "Input", "Output", "Total", "Cost"]} rows={[[component.request_count, component.usage.logical_requests, component.usage.input_tokens, component.usage.output_tokens, component.usage.total_tokens, cost(component.usage.cost_nano_usd)]]} />
  </section>;
}

export function InstallationFamiliesPage() {
  const session = useConsoleSession();
  const [environment, setEnvironment] = useState(() => initialFilter("environment_id"));
  const [userID, setUserID] = useState(() => initialFilter("user_id"));
  const [page, setPage] = useState<InstallationFamilyPage>();
  const [family, setFamily] = useState<InstallationFamily>();
  const [component, setComponent] = useState<ClientComponent>();
  const [reason, setReason] = useState("console operator revocation");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in before inspecting installation families.</h1><p>Family and component trust is available only through the authenticated Admin API.</p></section>;
  const canRevoke = session.data.session?.capabilities.includes("revoke_installations") ?? false;

  async function list(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(queryPath("/admin/v1/installation-families", { environment_id: environment, user_id: userID || undefined, page_size: "50", cursor }), InstallationFamilyPageSchema);
      if (response.data.items.some((item) => item.environment_id !== environment)) throw new Error("family_context");
      setPage(response.data); setFamily(undefined); setComponent(undefined);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "family_context" ? { code: "invalid_response", detail: "The family page contained an item outside the selected environment.", retryable: true, status: 0, title: "Family scope mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function loadFamily(familyID: string): Promise<InstallationFamily | undefined> {
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/installation-families/${familyID}`, InstallationFamilySchema);
      if (response.data.id !== familyID || response.data.environment_id !== environment || !response.data.components) throw new Error("family_context");
      setFamily(response.data); setComponent(undefined);
      return response.data;
    } catch (error) {
      setFamily(undefined); setComponent(undefined);
      setProblem(error instanceof Error && error.message === "family_context" ? { code: "invalid_response", detail: "The family detail did not match the selected family and environment.", retryable: true, status: 0, title: "Family detail mismatch" } : problemFromError(error));
      return undefined;
    } finally { setBusy(false); }
  }

  async function loadComponent(componentID: string): Promise<void> {
    if (!family) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/client-components/${componentID}`, ClientComponentSchema);
      if (response.data.id !== componentID || response.data.installation_family_id !== family.id || response.data.environment_id !== environment) throw new Error("component_context");
      setComponent(response.data);
    } catch (error) {
      setComponent(undefined);
      setProblem(error instanceof Error && error.message === "component_context" ? { code: "invalid_response", detail: "The component detail did not match the selected family and environment.", retryable: true, status: 0, title: "Component detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function revokeFamily(): Promise<void> {
    if (!family) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/installation-families/${family.id}/revoke`, InstallationFamilySchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== family.id || response.data.environment_id !== environment) throw new Error("family_context");
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === response.data.id ? response.data : item) } : current);
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("family_context");
      setFamily(exact.data); setComponent(undefined);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "family_context" ? { code: "invalid_response", detail: "The revoked family response did not match the selected family and environment.", retryable: true, status: 0, title: "Family detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function requireFamilyRenewal(): Promise<void> {
    if (!family) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/installation-families/${family.id}/require-renewal`, InstallationFamilySchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== family.id || response.data.environment_id !== environment) throw new Error("family_context");
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === response.data.id ? response.data : item) } : current);
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("family_context");
      setFamily(exact.data); setComponent(undefined);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "family_context" ? { code: "invalid_response", detail: "The renewed family response did not match the selected family and environment.", retryable: true, status: 0, title: "Family detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function revokeComponent(): Promise<void> {
    if (!family || !component) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/client-components/${component.id}/revoke`, ClientComponentSchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== component.id || response.data.installation_family_id !== family.id || response.data.environment_id !== environment) throw new Error("component_context");
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("component_context");
      setFamily(exact.data); setComponent(response.data);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === exact.data.id ? { ...item, status: exact.data.status, revoked_at: exact.data.revoked_at, revocation_reason: exact.data.revocation_reason, updated_at: exact.data.updated_at } : item) } : current);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "component_context" ? { code: "invalid_response", detail: "The revoked component response did not match the selected family and environment.", retryable: true, status: 0, title: "Component detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function requireComponentReattestation(): Promise<void> {
    if (!family || !component) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/client-components/${component.id}/require-reattestation`, ClientComponentSchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== component.id || response.data.installation_family_id !== family.id || response.data.environment_id !== environment) throw new Error("component_context");
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("component_context");
      setFamily(exact.data); setComponent(response.data);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === exact.data.id ? { ...exact.data, components: undefined } : item) } : current);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "component_context" ? { code: "invalid_response", detail: "The re-attested component response did not match the selected family and environment.", retryable: true, status: 0, title: "Component detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  return <div className="control-page"><PageHeading>Inspect the complete root-and-delegated trust boundary, independent component sessions, feature grants, usage, cost, and revocation state. Raw attestation evidence, private keys, refresh grants, and provider bodies never appear here.</PageHeading>
    <section className="compatibility-reference"><div><strong>Framework support is versioned separately.</strong><span>Check the generated registry before treating an SDK or framework adapter as supported.</span></div><a href={compatibilityReference} rel="noreferrer" target="_blank">Open compatibility reference</a></section>
    <form className="filter-bar" onSubmit={(event) => { event.preventDefault(); void list(); }}><label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => { setEnvironment(event.target.value); setPage(undefined); setFamily(undefined); setComponent(undefined); }} /></label><label>User ID (optional)<input pattern={applicationUserInputPattern} value={userID} onChange={(event) => { setUserID(event.target.value); setPage(undefined); setFamily(undefined); setComponent(undefined); }} /></label><button className="primary-action" disabled={busy} type="submit">{busy ? "Working…" : "List families"}</button></form>
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Family", "Platform", "Status", "Root trust", "Components", "Requests", "Cost", "Last activity"]} rows={page.items.map((item) => [<button className="link-button" disabled={busy} onClick={() => void loadFamily(item.id)} type="button">{item.id}</button>, label(item.platform), item.status, label(item.root_trust_source), item.component_count, item.request_count, cost(item.usage.cost_nano_usd), time(item.last_seen_at)])} />{page.page.has_more ? <button className="secondary-action" disabled={busy} onClick={() => void list(page.page.next_cursor)} type="button">Next page</button> : null}</> : null}
    {family ? <section className="detail-card family-detail"><div className="detail-card__heading"><div><p className="eyebrow">Installation Family</p><h2>{family.id}</h2><p>{label(family.platform)} · {family.status} · user {family.user_id}</p></div><div className="button-row"><button className="secondary-action" disabled={!canRevoke || busy || !reason.trim() || family.status !== "active"} onClick={() => void requireFamilyRenewal()} type="button">Require containing-app renewal</button><button className="primary-action primary-action--danger" disabled={!canRevoke || busy || !reason.trim() || family.status === "revoked"} onClick={() => void revokeFamily()} type="button">Revoke family</button></div></div><p><small>Renewal expires family trust and refresh credentials. Existing access grants are not revoked early and live only to their current expiry.</small></p><label className="revocation-reason">Operator reason<input maxLength={100} minLength={1} required value={reason} onChange={(event) => setReason(event.target.value)} /></label><dl><div><dt>Root component</dt><dd>{family.root_component_id}</dd></div><div><dt>Root trust</dt><dd>{label(family.root_trust_source)}</dd></div><div><dt>Root trust expires</dt><dd>{time(family.root_trust_expires_at)}</dd></div><div><dt>Created</dt><dd>{time(family.created_at)}</dd></div><div><dt>Last activity</dt><dd>{time(family.last_seen_at)}</dd></div><div><dt>Revocation</dt><dd>{family.revocation_reason ?? "—"}</dd></div></dl><FamilyMetrics family={family} /><TrustGraph disabled={busy} family={family} onSelect={(componentID) => void loadComponent(componentID)} /><h3>Component inventory</h3><Table headers={["Definition", "Kind", "Trust", "Features", "Session", "Closed sessions", "Reuse", "Requests", "Cost"]} rows={(family.components ?? []).map((item) => [<button className="link-button" disabled={busy} onClick={() => void loadComponent(item.id)} type="button">{item.definition_id}</button>, label(item.kind), label(item.trust_source), item.granted_features.join(", "), item.session_status ?? "—", item.session_failure_count, item.refresh_reuse_count, item.request_count, cost(item.usage.cost_nano_usd)])} /></section> : null}
    {component && family ? <ComponentDetail busy={busy} canRevoke={canRevoke} component={component} familyActive={family.status === "active"} hasReason={Boolean(reason.trim())} onReattest={() => void requireComponentReattestation()} onRevoke={() => void revokeComponent()} /> : null}
  </div>;
}

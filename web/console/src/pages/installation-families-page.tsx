import { type ReactNode, useEffect, useState } from "react";

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
import {
  InstallationFamilyRouteSearchSchema,
  type InstallationFamilyRouteSearch
} from "../app/route-search";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { ImmediateOperationConfirmation } from "../components/immediate-operation-confirmation";

const environmentInputPattern = "env_[A-Za-z0-9_-]{16,128}";
const applicationUserInputPattern = "usr_[A-Za-z0-9_-]{16,128}";
const compatibilityReference = "https://docs.latchway.dev/reference/compatibility";

function initialRouteSearch(): InstallationFamilyRouteSearch {
  if (typeof window === "undefined") return {};
  const candidate = InstallationFamilyRouteSearchSchema.safeParse(Object.fromEntries(new URLSearchParams(window.location.search)));
  return candidate.success ? candidate.data : {};
}

function routePatch(search: InstallationFamilyRouteSearch): Partial<InstallationFamilyRouteSearch> {
  return {
    component_id: search.component_id,
    cursor: search.cursor,
    environment_id: search.environment_id,
    family_id: search.family_id,
    user_id: search.user_id
  };
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

function componentAuditHref(component: ClientComponent): string {
  return `/audit?${new URLSearchParams({
    environment_id: component.environment_id,
    resource_id: component.id,
    resource_type: "client_component"
  }).toString()}`;
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

function ComponentDetail({ component, busy, canRevoke, familyActive, onClose, onReattest, onRevoke }: { component: ClientComponent; busy: boolean; canRevoke: boolean; familyActive: boolean; onClose: () => void; onReattest: () => void; onRevoke: () => void }) {
  const terminal = component.status === "revoked" || component.status === "replaced";
  return <section className="detail-card" aria-labelledby="component-detail-heading"><div className="detail-card__heading"><div><p className="eyebrow">Client component</p><h2 id="component-detail-heading">{component.definition_id}</h2><p>{component.id} · {label(component.platform)} · {label(component.kind)}</p></div><div className="button-row"><button className="secondary-action" disabled={!canRevoke || busy || !familyActive || component.status !== "active"} onClick={onReattest} type="button">Review re-attestation</button><button className="primary-action primary-action--danger" disabled={!canRevoke || busy || terminal} onClick={onRevoke} type="button">Review component revocation</button><button className="small-action" disabled={busy} onClick={onClose} type="button">Close component</button></div></div>
    {component.is_root ? <p className="control-notice component-warning"><strong>Root boundary</strong><span>Revoking this root revokes the complete family and every descendant credential.</span></p> : null}
    <p><small>Re-attestation expires this component subtree's trust and refresh credentials while already-issued access grants live only to their existing expiry. Sibling components are unchanged unless this is the root.</small></p>
    <h3>Trust provenance</h3><dl><div><dt>Trust source</dt><dd>{label(component.trust_source)}</dd></div><div><dt>Provider</dt><dd>{component.attestation_provider ?? "—"}</dd></div><div><dt>Parent component</dt><dd>{component.parent_component_id ?? "root"}</dd></div><div><dt>Parent attestation event</dt><dd>{component.parent_attestation_event_id ?? "—"}</dd></div><div><dt>Verified</dt><dd>{time(component.trust_verified_at)}</dd></div><div><dt>Trust expires</dt><dd>{time(component.trust_expires_at)}</dd></div></dl>
    {component.delegation ? <section className="provenance-panel"><h3>Delegation receipt</h3><dl><div><dt>Delegation</dt><dd>{component.delegation.id}</dd></div><div><dt>Configuration revision</dt><dd>{component.delegation.configuration_revision_id}</dd></div><div><dt>Trust level</dt><dd>{label(component.delegation.trust_level)}</dd></div><div><dt>Feature scopes</dt><dd>{component.delegation.feature_scopes.join(", ")}</dd></div><div><dt>Identity expires</dt><dd>{time(component.delegation.identity_expires_at)}</dd></div><div><dt>Attestation expires</dt><dd>{time(component.delegation.attestation_expires_at)}</dd></div><div><dt>Delegation expires</dt><dd>{time(component.delegation.expires_at)}</dd></div><div><dt>Consumed</dt><dd>{time(component.delegation.consumed_at)}</dd></div></dl></section> : null}
    <h3>Component key and grants</h3><dl><div><dt>Definition</dt><dd>{component.definition_id}</dd></div><div><dt>Component key</dt><dd>{component.component_key_id}</dd></div><div><dt>DPoP thumbprint</dt><dd><code>{component.dpop_jkt}</code></dd></div><div><dt>Key storage claim</dt><dd>{label(component.key_storage_claim)}</dd></div><div><dt>Granted features</dt><dd>{component.granted_features.join(", ")}</dd></div><div><dt>Status</dt><dd>{component.status}</dd></div><div><dt>Last activity</dt><dd>{time(component.last_seen_at)}</dd></div><div><dt>App / SDK version</dt><dd>{component.app_version ?? "—"} / {component.sdk_version ?? "—"}</dd></div></dl>
    <h3>Session and reuse</h3><dl><div><dt>Session family</dt><dd>{component.session_family_id ?? "—"}</dd></div><div><dt>Session status</dt><dd>{component.session_status ?? "—"}</dd></div><div><dt>Access expires</dt><dd>{time(component.session_expires_at)}</dd></div><div><dt>Closed session families</dt><dd>{component.session_failure_count.toLocaleString()}</dd></div><div><dt>Refresh reuse events</dt><dd>{component.refresh_reuse_count.toLocaleString()}</dd></div><div><dt>Revoked</dt><dd>{time(component.revoked_at)}</dd></div><div><dt>Revocation reason</dt><dd>{component.revocation_reason ?? "—"}</dd></div></dl><a className="secondary-action" href={componentAuditHref(component)}>Inspect session failures and reuse</a>
    <h3>Usage and cost</h3><Table headers={["Requests", "Logical requests", "Input", "Output", "Total", "Cost"]} rows={[[component.request_count, component.usage.logical_requests, component.usage.input_tokens, component.usage.output_tokens, component.usage.total_tokens, cost(component.usage.cost_nano_usd)]]} />
  </section>;
}

export function InstallationFamiliesPage() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  const routeSearch = InstallationFamilyRouteSearchSchema.parse(workspace?.search ?? {});
  const [standaloneSearch, setStandaloneSearch] = useState<InstallationFamilyRouteSearch>(initialRouteSearch);
  const activeSearch = workspace ? routeSearch : standaloneSearch;
  const [environment, setEnvironment] = useState(activeSearch.environment_id ?? "");
  const [userID, setUserID] = useState(activeSearch.user_id ?? "");
  const [page, setPage] = useState<InstallationFamilyPage>();
  const [family, setFamily] = useState<InstallationFamily>();
  const [component, setComponent] = useState<ClientComponent>();
  const [pendingOperation, setPendingOperation] = useState<"family-renewal" | "family-revoke" | "component-reattestation" | "component-revoke">();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const canonicalSearchKey = JSON.stringify(routePatch(activeSearch));
  useEffect(() => {
    if (session.data?.mode !== "configured") return;
    // Browser navigation is an external state source for the safe filter draft and selected detail.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setEnvironment(activeSearch.environment_id ?? "");
    setUserID(activeSearch.user_id ?? "");
    if (activeSearch.environment_id) void restore(activeSearch);
    else { setPage(undefined); setFamily(undefined); setComponent(undefined); setPendingOperation(undefined); }
    // The validated URL key is the canonical restore trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canonicalSearchKey, session.data?.mode]);
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in before inspecting installation families.</h1><p>Family and component trust is available only through the authenticated Admin API.</p></section>;
  const canRevoke = session.data.session?.capabilities.includes("revoke_installations") ?? false;

  async function restore(search: InstallationFamilyRouteSearch): Promise<void> {
    if (!search.environment_id) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(queryPath("/admin/v1/installation-families", { environment_id: search.environment_id, user_id: search.user_id, page_size: "50", cursor: search.cursor }), InstallationFamilyPageSchema);
      if (response.data.items.some((item) => item.environment_id !== search.environment_id)) throw new Error("family_context");
      let restoredFamily: InstallationFamily | undefined;
      let restoredComponent: ClientComponent | undefined;
      if (search.family_id) {
        const detail = await adminRequest(`/admin/v1/installation-families/${search.family_id}`, InstallationFamilySchema);
        if (detail.data.id !== search.family_id || detail.data.environment_id !== search.environment_id || !detail.data.components) throw new Error("family_context");
        restoredFamily = detail.data;
      }
      if (search.component_id) {
        if (!restoredFamily) throw new Error("component_context");
        const detail = await adminRequest(`/admin/v1/client-components/${search.component_id}`, ClientComponentSchema);
        if (detail.data.id !== search.component_id || detail.data.installation_family_id !== restoredFamily.id || detail.data.environment_id !== search.environment_id || !restoredFamily.components?.some((item) => item.id === detail.data.id)) throw new Error("component_context");
        restoredComponent = detail.data;
      }
      setPage(response.data); setFamily(restoredFamily); setComponent(restoredComponent); setPendingOperation(undefined);
    } catch (error) {
      setFamily(undefined); setComponent(undefined); setPendingOperation(undefined);
      setProblem(error instanceof Error && error.message === "component_context"
        ? { code: "invalid_response", detail: "The component detail did not match the selected family and environment.", retryable: true, status: 0, title: "Component detail mismatch" }
        : error instanceof Error && error.message === "family_context"
          ? { code: "invalid_response", detail: "The family list or detail did not match the selected environment and identifiers.", retryable: true, status: 0, title: "Family scope mismatch" }
          : problemFromError(error));
    } finally { setBusy(false); }
  }

  function navigate(search: InstallationFamilyRouteSearch, replace: boolean): void {
    if (workspace) workspace.updateSearch(routePatch(search), { replace });
    else setStandaloneSearch(search);
  }

  function applyFilters(): void {
    const candidate = InstallationFamilyRouteSearchSchema.safeParse({
      ...activeSearch,
      component_id: undefined,
      cursor: undefined,
      environment_id: environment || undefined,
      family_id: undefined,
      user_id: userID || undefined
    });
    if (!candidate.success) {
      setProblem({ code: "request_invalid", detail: "Enter canonical environment and optional pseudonymous-user identifiers.", retryable: false, status: 0, title: "Invalid family filters" });
      return;
    }
    if (JSON.stringify(routePatch(candidate.data)) === canonicalSearchKey) void restore(candidate.data);
    else navigate(candidate.data, true);
  }

  function selectFamily(familyID: string): void {
    navigate(InstallationFamilyRouteSearchSchema.parse({ ...activeSearch, component_id: undefined, family_id: familyID }), false);
  }

  function selectComponent(componentID: string): void {
    if (!family) return;
    navigate(InstallationFamilyRouteSearchSchema.parse({ ...activeSearch, component_id: componentID, family_id: family.id }), false);
  }

  function closeFamily(): void {
    navigate(InstallationFamilyRouteSearchSchema.parse({ ...activeSearch, component_id: undefined, family_id: undefined }), true);
  }

  function closeComponent(): void {
    navigate(InstallationFamilyRouteSearchSchema.parse({ ...activeSearch, component_id: undefined }), true);
  }

  async function revokeFamily(reason: string): Promise<void> {
    if (!family) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/installation-families/${family.id}/revoke`, InstallationFamilySchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== family.id || response.data.environment_id !== environment) throw new Error("family_context");
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === response.data.id ? response.data : item) } : current);
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("family_context");
      setFamily(exact.data); setComponent(undefined); setPendingOperation(undefined);
      if (activeSearch.component_id) navigate(InstallationFamilyRouteSearchSchema.parse({ ...activeSearch, component_id: undefined }), true);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "family_context" ? { code: "invalid_response", detail: "The revoked family response did not match the selected family and environment.", retryable: true, status: 0, title: "Family detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function requireFamilyRenewal(reason: string): Promise<void> {
    if (!family) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/installation-families/${family.id}/require-renewal`, InstallationFamilySchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== family.id || response.data.environment_id !== environment) throw new Error("family_context");
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === response.data.id ? response.data : item) } : current);
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("family_context");
      setFamily(exact.data); setComponent(undefined); setPendingOperation(undefined);
      if (activeSearch.component_id) navigate(InstallationFamilyRouteSearchSchema.parse({ ...activeSearch, component_id: undefined }), true);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "family_context" ? { code: "invalid_response", detail: "The renewed family response did not match the selected family and environment.", retryable: true, status: 0, title: "Family detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function revokeComponent(reason: string): Promise<void> {
    if (!family || !component) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/client-components/${component.id}/revoke`, ClientComponentSchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== component.id || response.data.installation_family_id !== family.id || response.data.environment_id !== environment) throw new Error("component_context");
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("component_context");
      setFamily(exact.data); setComponent(response.data);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === exact.data.id ? { ...item, status: exact.data.status, revoked_at: exact.data.revoked_at, revocation_reason: exact.data.revocation_reason, updated_at: exact.data.updated_at } : item) } : current);
      setPendingOperation(undefined);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "component_context" ? { code: "invalid_response", detail: "The revoked component response did not match the selected family and environment.", retryable: true, status: 0, title: "Component detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  async function requireComponentReattestation(reason: string): Promise<void> {
    if (!family || !component) return;
    setBusy(true); setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/client-components/${component.id}/require-reattestation`, ClientComponentSchema, { body: { reason: reason.trim() }, method: "POST" });
      if (response.data.id !== component.id || response.data.installation_family_id !== family.id || response.data.environment_id !== environment) throw new Error("component_context");
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environment || !exact.data.components) throw new Error("component_context");
      setFamily(exact.data); setComponent(response.data);
      setPage((current) => current ? { ...current, items: current.items.map((item) => item.id === exact.data.id ? { ...exact.data, components: undefined } : item) } : current);
      setPendingOperation(undefined);
    } catch (error) {
      setProblem(error instanceof Error && error.message === "component_context" ? { code: "invalid_response", detail: "The re-attested component response did not match the selected family and environment.", retryable: true, status: 0, title: "Component detail mismatch" } : problemFromError(error));
    } finally { setBusy(false); }
  }

  return <div className="control-page"><PageHeading>Inspect the complete root-and-delegated trust boundary, independent component sessions, feature grants, usage, cost, and revocation state. Raw attestation evidence, private keys, refresh grants, and provider bodies never appear here.</PageHeading>
    <section className="compatibility-reference"><div><strong>Framework support is versioned separately.</strong><span>Check the generated registry before treating an SDK or framework adapter as supported.</span></div><a href={compatibilityReference} rel="noreferrer" target="_blank">Open compatibility reference</a></section>
    <form className="filter-bar" onSubmit={(event) => { event.preventDefault(); applyFilters(); }}><label>Environment ID<input pattern={environmentInputPattern} required value={environment} onChange={(event) => { setEnvironment(event.target.value); setPage(undefined); setFamily(undefined); setComponent(undefined); setPendingOperation(undefined); }} /></label><label>User ID (optional)<input pattern={applicationUserInputPattern} value={userID} onChange={(event) => { setUserID(event.target.value); setPage(undefined); setFamily(undefined); setComponent(undefined); setPendingOperation(undefined); }} /></label><button className="primary-action" disabled={busy} type="submit">{busy ? "Working…" : "List families"}</button></form>
    <ProblemNotice problem={problem} />
    {page ? <><Table headers={["Family", "Platform", "Status", "Root trust", "Components", "Requests", "Cost", "Last activity"]} rows={page.items.map((item) => [<button className="link-button" disabled={busy} onClick={() => selectFamily(item.id)} type="button">{item.id}</button>, label(item.platform), item.status, label(item.root_trust_source), item.component_count, item.request_count, cost(item.usage.cost_nano_usd), time(item.last_seen_at)])} />{page.page.has_more && page.page.next_cursor ? <button className="secondary-action" disabled={busy} onClick={() => navigate(InstallationFamilyRouteSearchSchema.parse({ ...activeSearch, component_id: undefined, cursor: page.page.next_cursor, family_id: undefined }), false)} type="button">Next page</button> : null}</> : null}
    {family ? <section className="detail-card family-detail"><div className="detail-card__heading"><div><p className="eyebrow">Installation Family</p><h2>{family.id}</h2><p>{label(family.platform)} · {family.status} · user {family.user_id}</p></div><div className="button-row"><button className="secondary-action" disabled={!canRevoke || busy || family.status !== "active"} onClick={() => setPendingOperation("family-renewal")} type="button">Review containing-app renewal</button><button className="primary-action primary-action--danger" disabled={!canRevoke || busy || family.status === "revoked"} onClick={() => setPendingOperation("family-revoke")} type="button">Review family revocation</button><button className="small-action" disabled={busy} onClick={closeFamily} type="button">Close family</button></div></div><p><small>Renewal expires family trust and refresh credentials. Existing access grants are not revoked early and live only to their current expiry.</small></p><dl><div><dt>Root component</dt><dd>{family.root_component_id}</dd></div><div><dt>Root trust</dt><dd>{label(family.root_trust_source)}</dd></div><div><dt>Root trust expires</dt><dd>{time(family.root_trust_expires_at)}</dd></div><div><dt>Created</dt><dd>{time(family.created_at)}</dd></div><div><dt>Last activity</dt><dd>{time(family.last_seen_at)}</dd></div><div><dt>Revocation</dt><dd>{family.revocation_reason ?? "—"}</dd></div></dl><FamilyMetrics family={family} /><TrustGraph disabled={busy} family={family} onSelect={selectComponent} /><h3>Component inventory</h3><Table headers={["Definition", "Kind", "Trust", "Features", "Session", "Closed sessions", "Reuse", "Requests", "Cost"]} rows={(family.components ?? []).map((item) => [<button className="link-button" disabled={busy} onClick={() => selectComponent(item.id)} type="button">{item.definition_id}</button>, label(item.kind), label(item.trust_source), item.granted_features.join(", "), item.session_status ?? "—", item.session_failure_count, item.refresh_reuse_count, item.request_count, cost(item.usage.cost_nano_usd)])} /></section> : null}
    {family && pendingOperation === "family-renewal" ? <ImmediateOperationConfirmation acknowledgement="I understand this immediately blocks future refresh and provisioning until the containing application establishes fresh direct trust." affectedScope={<><code>{family.id}</code> and all components in this family</>} busy={busy} confirmLabel="Require fresh family trust" credentialRestoration="No old refresh credential is restored. The containing application must establish fresh direct trust and obtain new credentials." heading="Require containing-app renewal?" key={pendingOperation} onCancel={() => setPendingOperation(undefined)} onConfirm={(confirmedReason) => { if (confirmedReason) void requireFamilyRenewal(confirmedReason); }} requiresReason reversibility="Service can recover through a fresh direct-trust flow, but this operation cannot be undone." summary="Family trust and rotating refresh credentials expire as soon as the server commits this action. Already-issued access grants remain usable only until their existing expiry." timing="Immediately for future refresh and provisioning; existing access grants are not cut short" /> : null}
    {family && pendingOperation === "family-revoke" ? <ImmediateOperationConfirmation acknowledgement="I understand this immediately and permanently revokes the complete Installation Family credential boundary." affectedScope={<><code>{family.id}</code>, its root, every descendant component, and every component session and refresh chain</>} busy={busy} confirmLabel="Revoke complete family" credentialRestoration="Never. The revoked family and credentials stay revoked; the application must establish a new trust boundary." heading="Revoke this Installation Family?" key={pendingOperation} onCancel={() => setPendingOperation(undefined)} onConfirm={(confirmedReason) => { if (confirmedReason) void revokeFamily(confirmedReason); }} requiresReason reversibility="No. Family revocation is terminal." summary="This revokes the family root, every component key, and every component session and refresh chain as soon as the server commits the action." timing="Immediately after the server accepts the revocation" /> : null}
    {component && family ? <ComponentDetail busy={busy} canRevoke={canRevoke} component={component} familyActive={family.status === "active"} onClose={closeComponent} onReattest={() => setPendingOperation("component-reattestation")} onRevoke={() => setPendingOperation("component-revoke")} /> : null}
    {component && family && pendingOperation === "component-reattestation" ? <ImmediateOperationConfirmation acknowledgement="I understand this immediately expires trust and refresh credentials in the stated component subtree." affectedScope={component.is_root ? <><code>{component.id}</code> is the root, so the complete family is affected</> : <><code>{component.id}</code> and its delegated descendants; sibling components remain unchanged</>} busy={busy} confirmLabel="Require fresh component trust" credentialRestoration="No old refresh credential is restored. The affected component subtree must establish fresh trust and obtain new credentials." heading={`Require fresh trust for ${component.definition_id}?`} key={`${pendingOperation}-${component.id}`} onCancel={() => setPendingOperation(undefined)} onConfirm={(confirmedReason) => { if (confirmedReason) void requireComponentReattestation(confirmedReason); }} requiresReason reversibility="Service can recover through fresh attestation, but this operation cannot be undone." summary="Trust and refresh credentials expire for this component subtree when the server commits the action. Already-issued access grants remain usable only until their existing expiry." timing="Immediately for future refresh; existing access grants are not cut short" /> : null}
    {component && family && pendingOperation === "component-revoke" ? <ImmediateOperationConfirmation acknowledgement="I understand this immediately and permanently revokes the stated component credential scope." affectedScope={component.is_root ? <><code>{component.id}</code> is the root, so the complete family and every descendant are revoked</> : <><code>{component.id}</code> and its delegated descendants; sibling components remain unchanged</>} busy={busy} confirmLabel="Revoke component credential scope" credentialRestoration="Never. Revoked component keys and credentials stay revoked; the client must provision a new component identity." heading={`Revoke ${component.definition_id}?`} key={`${pendingOperation}-${component.id}`} onCancel={() => setPendingOperation(undefined)} onConfirm={(confirmedReason) => { if (confirmedReason) void revokeComponent(confirmedReason); }} requiresReason reversibility="No. Component revocation is terminal." summary="This revokes the component key, its delegated descendants, and their session and refresh chains when the server commits the action." timing="Immediately after the server accepts the revocation" /> : null}
  </div>;
}

import { type FormEvent, useState } from "react";
import { z } from "zod";

import {
  adminRequest,
  APITokenPageSchema,
  CreatedAPITokenSchema,
  type APITokenMetadata,
  type CreatedAPIToken
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { useConsoleCompatibility } from "../app/console-compatibility-context";
import { ImmediateOperationConfirmation } from "../components/immediate-operation-confirmation";

const capabilityChoices = [
  ["activate_configuration", "Activate configuration"],
  ["inspect_users", "Inspect users and usage"],
  ["manage_owners", "Manage administrators"],
  ["manage_secrets", "Manage secrets"],
  ["revoke_installations", "Revoke installations"],
  ["run_self_tests", "Run self-tests"]
] as const;

interface CredentialRevealState {
  compatibilityAllowed: boolean;
  generation: number;
  issued?: CreatedAPIToken;
  copyStatus?: string;
}

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}{problem.operationId ? ` · Operation: ${problem.operationId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
}

function scopeRequiredProblem(): AdminProblem {
  return {
    code: "request_invalid",
    detail: "Select at least one capability for the new token.",
    retryable: false,
    status: 0,
    title: "Scope required"
  };
}

function displayInstant(value?: string): string {
  return value ? new Date(value).toLocaleString() : "Never";
}

export function APITokensPage() {
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const [tokens, setTokens] = useState<APITokenMetadata[]>();
  const [credentialReveal, setCredentialReveal] = useState<CredentialRevealState>({
    compatibilityAllowed: consoleCompatibility.mutationAllowed,
    generation: 0
  });
  const [revocationTarget, setRevocationTarget] = useState<APITokenMetadata>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (credentialReveal.compatibilityAllowed !== consoleCompatibility.mutationAllowed) {
    // A compatibility transition invalidates the one-time reveal generation.
    setCredentialReveal((current) => ({
      compatibilityAllowed: consoleCompatibility.mutationAllowed,
      generation: current.generation + 1
    }));
  }
  const { copyStatus, issued } = credentialReveal;
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to manage API tokens.</h1></section>;

  const capabilities = session.data.session?.capabilities ?? [];
  const availableChoices = capabilityChoices.filter(([capability]) => capabilities.includes(capability));

  async function load(): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      setTokens((await adminRequest("/admin/v1/api-tokens", APITokenPageSchema)).data.items);
      setRevocationTarget(undefined);
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setBusy(false);
    }
  }

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!consoleCompatibility.mutationAllowed || issued) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const scopes = data.getAll("scopes").map(String);
    if (scopes.length === 0) {
      setProblem(scopeRequiredProblem());
      return;
    }
    const localExpiry = String(data.get("expires_at") ?? "");
    const body: { expires_at?: string; name: string; scopes: string[] } = {
      name: String(data.get("name")),
      scopes
    };
    if (localExpiry) {
      const parsedExpiry = new Date(localExpiry);
      if (Number.isNaN(parsedExpiry.getTime())) {
        setProblem({
          code: "request_invalid",
          detail: "Choose a valid expiration date and time.",
          retryable: false,
          status: 0,
          title: "Expiration is invalid"
        });
        return;
      }
      body.expires_at = parsedExpiry.toISOString();
    }
    setBusy(true);
    setProblem(undefined);
    const revealGeneration = credentialReveal.generation;
    setCredentialReveal((current) => ({ ...current, copyStatus: undefined }));
    try {
      const created = (await adminRequest("/admin/v1/api-tokens", CreatedAPITokenSchema, {
        body,
        method: "POST"
      })).data;
      setTokens((current) => current ? [...current, created.metadata] : [created.metadata]);
      form.reset();
      setCredentialReveal((current) => current.compatibilityAllowed && current.generation === revealGeneration
        ? { ...current, issued: created }
        : current);
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setBusy(false);
    }
  }

  async function copyToken(token: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(token);
      setCredentialReveal((current) => current.issued?.token === token
        ? { ...current, copyStatus: "Copied. The operating system clipboard may retain this credential." }
        : current);
    } catch {
      setCredentialReveal((current) => current.issued?.token === token
        ? { ...current, copyStatus: "Clipboard access was unavailable. Select the token and copy it manually." }
        : current);
    }
  }

  function dismissToken(): void {
    setCredentialReveal((current) => ({
      compatibilityAllowed: current.compatibilityAllowed,
      generation: current.generation,
    }));
  }

  async function revoke(tokenID: string): Promise<void> {
    if (!consoleCompatibility.mutationAllowed) return;
    setBusy(true);
    setProblem(undefined);
    try {
      await adminRequest(`/admin/v1/api-tokens/${tokenID}`, z.undefined(), { method: "DELETE" });
      setTokens((current) => current?.map((token) => token.id === tokenID ? { ...token, revoked: true } : token));
      if (issued?.metadata.id === tokenID) dismissToken();
      setRevocationTarget(undefined);
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setBusy(false);
    }
  }

  return <div className="control-page">
    <section className="page-heading"><div><p className="eyebrow">Administration</p><h1>API tokens</h1><p>Create narrowly scoped automation credentials for your administrator account. Token plaintext is returned once and is never included in the metadata list.</p></div></section>
    {availableChoices.length === 0 ? <div className="control-notice"><strong>No delegable capabilities</strong><span>Your current administrator session cannot create a useful scoped token.</span></div> : <form className="control-form" onSubmit={(event) => void create(event)}>
      <h2>Create API token</h2>
      <div className="form-field-grid"><label>Token name<input autoComplete="off" maxLength={256} name="name" required /></label><label>Expiration (optional)<input name="expires_at" type="datetime-local" /></label></div>
      <fieldset><legend>Capability scope</legend><div className="form-field-grid">{availableChoices.map(([capability, label]) => <label className="check-field" key={capability}><input name="scopes" type="checkbox" value={capability} />{label}</label>)}</div></fieldset>
      <button className="primary-action" disabled={busy || !consoleCompatibility.mutationAllowed || Boolean(issued)} type="submit">{busy ? "Working…" : "Create API token"}</button>
      {issued ? <small>Dismiss the current one-time credential before creating another.</small> : null}
    </form>}
    {issued && consoleCompatibility.mutationAllowed ? <section className="detail-card credential-reveal" aria-labelledby="issued-token-heading">
      <h2 id="issued-token-heading">Store this token now</h2>
      <p><strong>This is the only time Latchway will show this credential.</strong> Copying places it on the operating system clipboard, which may retain it after this page is closed.</p>
      <label>One-time API token<textarea className="credential-reveal__value" readOnly rows={3} value={issued.token} /></label>
      <div className="button-row"><button className="primary-action" onClick={() => void copyToken(issued.token)} type="button">Copy token — clipboard may retain it</button><button className="secondary-action" onClick={dismissToken} type="button">Dismiss token</button></div>
      {copyStatus ? <p aria-live="polite" className="resource-result">{copyStatus}</p> : null}
    </section> : null}
    <div className="button-row"><button className="secondary-action" disabled={busy} onClick={() => void load()} type="button">Load API tokens</button></div>
    <ProblemNotice problem={problem} />
    {tokens ? tokens.length === 0 ? <div className="control-notice"><strong>No API tokens</strong><span>No scoped automation credentials have been created for this administrator.</span></div> : <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Name</th><th>Scopes</th><th>Created</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead><tbody>{tokens.map((token) => <tr key={token.id}><td>{token.name}<br /><small>{token.id}</small></td><td>{token.scopes.join(", ")}</td><td>{displayInstant(token.created_at)}</td><td>{displayInstant(token.expires_at)}</td><td>{token.revoked ? "Revoked" : "Active"}</td><td><button className="small-action" disabled={busy || !consoleCompatibility.mutationAllowed || token.revoked} onClick={() => setRevocationTarget(token)} type="button">Review revoke</button></td></tr>)}</tbody></table></div> : null}
    {revocationTarget ? <ImmediateOperationConfirmation acknowledgement="I understand this immediately and permanently revokes this token and stops future authorization with its plaintext." affectedScope={<><code>{revocationTarget.id}</code> ({revocationTarget.name}) with scopes {revocationTarget.scopes.join(", ")}</>} busy={busy} confirmLabel="Revoke API token" credentialRestoration="Never. Latchway cannot recover or reactivate this token; create and distribute a replacement credential if automation must continue." disabled={!consoleCompatibility.mutationAllowed} heading={`Revoke ${revocationTarget.name}?`} key={revocationTarget.id} onCancel={() => setRevocationTarget(undefined)} onConfirm={() => void revoke(revocationTarget.id)} reversibility="No. API-token revocation is terminal." summary="Future requests using this token are denied. Durable self-test schedules bound to it can no longer authorize future runs and are not silently rebound." timing="Immediately after the server accepts the revocation" /> : null}
  </div>;
}

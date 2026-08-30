import { type FormEvent, useState } from "react";

import {
  adminRequest,
  AdministratorPageSchema,
  AdministratorSchema,
  queryPath,
  type Administrator,
  type AdministratorPage
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";

type AdministratorRole = "owner" | "admin" | "operator" | "viewer";

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}</small></div> : null;
}

export function AdministratorsPage() {
  const session = useConsoleSession();
  const [page, setPage] = useState<AdministratorPage>();
  const [resetTarget, setResetTarget] = useState<Administrator>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  if (session.data?.mode !== "configured") return <section className="empty-state"><h1>Sign in to manage administrators.</h1></section>;
  const canManage = session.data.session?.capabilities.includes("manage_owners") ?? false;

  async function load(cursor?: string): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      setPage((await adminRequest(queryPath("/admin/v1/administrators", { page_size: "50", cursor }), AdministratorPageSchema)).data);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setProblem(undefined); const form = event.currentTarget; const data = new FormData(form);
    try {
      const item = (await adminRequest("/admin/v1/administrators", AdministratorSchema, { method: "POST", body: {
        email: String(data.get("email")), display_name: String(data.get("display_name")),
        password: String(data.get("password")), role: String(data.get("role"))
      } })).data;
      setPage((current) => current ? { ...current, items: [...current.items, item] } : { items: [item], page: { has_more: false } });
      form.reset();
    } catch (error) { setProblem(problemFromError(error)); const field = form.elements.namedItem("password"); if (field instanceof HTMLInputElement) field.value = ""; }
    finally { setBusy(false); }
  }

  async function changeRole(item: Administrator, role: AdministratorRole): Promise<void> {
    await mutate(item, "role", { role }, "PUT");
  }

  async function changeStatus(item: Administrator): Promise<void> {
    await mutate(item, item.status === "active" ? "disable" : "enable", undefined, "POST");
  }

  async function mutate(item: Administrator, action: string, body: unknown, method: "POST" | "PUT"): Promise<void> {
    setBusy(true); setProblem(undefined);
    try {
      const updated = (await adminRequest(`/admin/v1/administrators/${item.id}/${action}`, AdministratorSchema, { method, ...(body === undefined ? {} : { body }) })).data;
      setPage((current) => current ? { ...current, items: current.items.map((entry) => entry.id === updated.id ? updated : entry) } : current);
      if (resetTarget?.id === updated.id) setResetTarget(updated);
    } catch (error) { setProblem(problemFromError(error)); } finally { setBusy(false); }
  }

  async function resetPassword(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); if (!resetTarget) return; setBusy(true); setProblem(undefined); const form = event.currentTarget; const data = new FormData(form);
    try {
      const updated = (await adminRequest(`/admin/v1/administrators/${resetTarget.id}/reset-password`, AdministratorSchema, { method: "POST", body: { password: String(data.get("password")) } })).data;
      setPage((current) => current ? { ...current, items: current.items.map((entry) => entry.id === updated.id ? updated : entry) } : current);
      setResetTarget(undefined); form.reset();
    } catch (error) { setProblem(problemFromError(error)); }
    finally { const field = form.elements.namedItem("password"); if (field instanceof HTMLInputElement) field.value = ""; setBusy(false); }
  }

  return <div className="control-page">
    <section className="page-heading"><div><p className="eyebrow">Administration</p><h1>Administrators</h1><p>Local accounts and organization roles. The server preserves the final active owner and revokes credentials on disable or password reset.</p></div></section>
    {!canManage ? <div className="control-notice"><strong>Owner access required</strong><span>Your current role can’t manage administrator accounts.</span></div> : <form className="control-form" onSubmit={(event) => void create(event)}>
      <h2>Create administrator</h2><div className="form-field-grid"><label>Email<input autoComplete="off" name="email" required type="email" /></label><label>Display name<input maxLength={200} name="display_name" required /></label><label>Role<select defaultValue="viewer" name="role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option><option value="owner">Owner</option></select></label></div>
      <label>Initial password<input autoComplete="new-password" minLength={12} name="password" required type="password" /><small>Sent once over the canonical Admin API and never returned or stored by this console.</small></label>
      <button className="primary-action" disabled={busy} type="submit">{busy ? "Working…" : "Create administrator"}</button>
    </form>}
    <div className="button-row"><button className="secondary-action" disabled={busy || !canManage} onClick={() => void load()} type="button">Load administrators</button></div><ProblemNotice problem={problem} />
    {page ? <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>{page.items.map((item) => <tr key={item.id}><td>{item.email}</td><td>{item.display_name}</td><td><select aria-label={`Role for ${item.email}`} disabled={busy || !canManage} onChange={(event) => void changeRole(item, event.target.value as AdministratorRole)} value={item.role}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option><option value="owner">Owner</option></select></td><td>{item.status}</td><td><div className="button-row"><button className="small-action" disabled={busy || !canManage} onClick={() => void changeStatus(item)} type="button">{item.status === "active" ? "Disable" : "Enable"}</button><button className="small-action" disabled={busy || !canManage} onClick={() => setResetTarget(item)} type="button">Reset password</button></div></td></tr>)}</tbody></table>{page.page.has_more ? <button className="secondary-action" disabled={busy} onClick={() => void load(page.page.next_cursor)} type="button">Next page</button> : null}</div> : null}
    {resetTarget ? <form className="detail-card" onSubmit={(event) => void resetPassword(event)}><h2>Reset {resetTarget.email}</h2><p>This revokes the administrator’s active sessions and API tokens. Cross-organization accounts require a separate recovery process.</p><label>Replacement password<input autoComplete="new-password" minLength={12} name="password" required type="password" /></label><div className="button-row"><button className="primary-action" disabled={busy} type="submit">Reset and revoke credentials</button><button className="secondary-action" disabled={busy} onClick={() => setResetTarget(undefined)} type="button">Cancel</button></div></form> : null}
  </div>;
}

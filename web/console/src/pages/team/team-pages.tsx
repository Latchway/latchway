import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, type ReactNode, useMemo, useRef, useState } from "react";
import { z } from "zod";

import {
  adminRequest,
  type Administrator,
  type AdministratorPage,
  AdministratorPageSchema,
  AdministratorSchema,
  type AdminSessionMetadata,
  type AdminSessionMetadataPage,
  AdminSessionMetadataPageSchema,
  type APITokenMetadata,
  APITokenPageSchema,
  type CreatedAPIToken,
  CreatedAPITokenSchema,
  queryPath
} from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { capabilitiesAnywhere, useCapabilities } from "../../app/permissions";
import { TeamRouteSearchSchema } from "../../app/route-search";
import { useOptionalWorkspace } from "../../app/workspace-context-value";
import { PasswordField } from "../../components/password-field";
import { takePassword } from "../../components/password-value";
import { resetMemberTwoFactor } from "../../api/account";
import { applicationRolesQueryOptions, removeApplicationRole, setApplicationRole } from "../../api/application-roles";
import { applicationsQueryOptions } from "../../api/workspace";
import { createInvitation, type Invitation, type InvitationLink, invitationsQueryOptions, renewInvitation, revokeInvitation } from "../../api/invitations";
import {
  Badge,
  Button,
  buttonClass,
  Card,
  type Column,
  ConfirmDialog,
  DataTable,
  DetailPanel,
  EmptyState,
  Field,
  Input,
  Notice,
  PageHeader,
  Properties,
  Segmented
} from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { CopyButton } from "../requests/request-detail";
import {
  CAPABILITIES,
  type Capability,
  capabilitiesOf,
  capabilityLabel,
  daysUntil,
  lowestRoleWith,
  type Role,
  ROLE_LABEL,
  ROLE_SUMMARY,
  roleChange,
  ROLES
} from "./roles";

const wallClock = (): number => Date.now();

function when(value: string | undefined): string {
  return value ? new Date(value).toLocaleString() : "—";
}

/** The signed-in administrator, their role in this organization and what the console may do for them. */
function useMe() {
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const { can, previewRole } = useCapabilities();
  const me = session.data?.session;
  const role = me?.memberships.find((membership) => membership.organization_id === me.organization_id)?.role as Role | undefined;
  // Tokens may carry any capability held in some application; each use is checked per application.
  const capabilities = capabilitiesAnywhere(me, previewRole);
  return {
    applicationRolesSupported: compatibility.status?.server_capabilities.includes("admin_application_roles") ?? false,
    canManageOwners: can("manage_owners"),
    capabilities,
    id: me?.administrator.id,
    mutationAllowed: compatibility.mutationAllowed,
    role
  };
}

function TeamScope({ children }: { children: ReactNode }) {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <>{children}</>;
}

function OwnerOnly({ what }: { what: string }) {
  return <div className="lw-page-empty"><EmptyState icon="lock" orientation="horizontal" title="Owner role needed">{what} needs the Owner role (the <code className="lw-code-inline">manage_owners</code> capability). Ask an owner of this organization.</EmptyState></div>;
}

function RoleCards({ disabledReason, name, onChange, value }: { disabledReason?: (role: Role) => string | undefined; name: string; onChange: (role: Role) => void; value: Role }) {
  return (
    <div className="lw-role-cards" role="radiogroup">
      {ROLES.map((role) => {
        const reason = disabledReason?.(role);
        return (
          <label className={`lw-role-card${value === role ? " is-on" : ""}${reason ? " is-off" : ""}`} key={role}>
            <input checked={value === role} disabled={Boolean(reason)} name={name} onChange={() => onChange(role)} type="radio" value={role} />
            <strong>{ROLE_LABEL[role]}</strong>
            <span className="lw-faint lw-note">{reason ?? ROLE_SUMMARY[role]}</span>
          </label>
        );
      })}
    </div>
  );
}

function CapabilityList({ from, to }: { from?: Role; to: Role }) {
  if (!from || from === to) {
    const allowed = capabilitiesOf(to);
    return <ul className="lw-cap-list">{CAPABILITIES.map((capability) => <li className={allowed.includes(capability.id) ? "is-yes" : "is-no"} key={capability.id}>{allowed.includes(capability.id) ? "✓" : "—"} {capability.label}</li>)}</ul>;
  }
  const change = roleChange(from, to);
  return (
    <ul className="lw-cap-list">
      {change.loses.map((capability) => <li className="is-lose" key={capability}>Loses: {capabilityLabel(capability)}</li>)}
      {change.gains.map((capability) => <li className="is-gain" key={capability}>Gains: {capabilityLabel(capability)}</li>)}
      {!change.loses.length && !change.gains.length ? <li className="is-no">No change in what they can do.</li> : null}
    </ul>
  );
}

function statusBadge(member: Administrator): ReactNode {
  if (member.status === "disabled") return <Badge color="red" variant="soft">Disabled</Badge>;
  if (member.password_reset_required) return <Badge color="orange" variant="soft">Must set password</Badge>;
  return <Badge color="success" variant="soft">Active</Badge>;
}

// ─── Members ────────────────────────────────────────────────────────────────

function useMembers(enabled: boolean) {
  return useInfiniteQuery({
    enabled,
    getNextPageParam: (page: AdministratorPage) => (page.page.has_more ? page.page.next_cursor : undefined),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }): Promise<AdministratorPage> => (await adminRequest(queryPath("/admin/v1/administrators", { cursor: pageParam, page_size: "100" }), AdministratorPageSchema)).data,
    queryKey: ["team", "members"],
    retry: false
  });
}

function useSessions(enabled: boolean) {
  return useInfiniteQuery({
    enabled,
    getNextPageParam: (page: AdminSessionMetadataPage) => (page.page.has_more ? page.page.next_cursor : undefined),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }): Promise<AdminSessionMetadataPage> => (await adminRequest(queryPath("/admin/v1/admin-sessions", { cursor: pageParam, page_size: "100" }), AdminSessionMetadataPageSchema)).data,
    queryKey: ["team", "sessions"],
    retry: false
  });
}

function AddMemberDrawer({ existing, onClose, onCreated }: { existing: readonly Administrator[]; onClose: () => void; onCreated: (member: Administrator) => void }) {
  const password = useRef<HTMLInputElement>(null);
  const [role, setRole] = useState<Role>("viewer");
  const [email, setEmail] = useState("");
  const [shared, setShared] = useState(false);
  const [error, setError] = useState<string>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const duplicate = existing.some((member) => member.email.toLowerCase() === email.trim().toLowerCase());

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const secret = takePassword(password);
    const name = String(data.get("display_name") ?? "").trim();
    if (duplicate) return setError("Someone on the team already uses this email.");
    if (secret.length < 12) return setError("The first password needs at least 12 characters.");
    if (!shared) return setError("Confirm you'll share the password privately.");
    setError(undefined);
    setBusy(true);
    setProblem(undefined);
    try {
      const created = (await adminRequest("/admin/v1/administrators", AdministratorSchema, { body: { display_name: name, email: email.trim(), password: secret, role }, method: "POST" })).data;
      onCreated(created);
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">Latchway sends no email; you share the first password yourself</span>} title="Add member">
      <form autoComplete="off" className="lw-stack" onSubmit={(event) => void submit(event)}>
        <Field id="member-name" label="Name"><Input id="member-name" maxLength={200} name="display_name" required /></Field>
        <Field error={duplicate ? "Someone on the team already uses this email." : undefined} id="member-email" label="Email"><Input id="member-email" maxLength={320} name="email" onChange={(event) => setEmail(event.target.value)} required type="email" value={email} /></Field>
        <div><strong className="lw-note">Role</strong><RoleCards name="new-member-role" onChange={setRole} value={role} /></div>
        <CapabilityList to={role} />
        <p className="lw-secondary lw-note">Roles apply to every application and environment in the organization.</p>
        <PasswordField hint="At least 12 characters. They choose their own when they first sign in. Latchway stores only a hash." id="member-password" inputRef={password} label="First password" />
        <label className="lw-check"><input checked={shared} onChange={(event) => setShared(event.target.checked)} type="checkbox" /><span>I&apos;ll share this password privately, not over chat history or email.</span></label>
        {error ? <Notice title="Not added" tone="danger">{error}</Notice> : null}
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!shared || duplicate} loading={busy} type="submit" variant="primary">Add Member</Button></div>
      </form>
    </DetailPanel>
  );
}

const INVITATION_STATUS: Readonly<Record<Invitation["status"], ReactNode>> = {
  accepted: <Badge color="success" variant="soft">Accepted</Badge>,
  expired: <Badge variant="soft">Expired</Badge>,
  pending: <Badge color="accent" variant="soft">Pending</Badge>,
  revoked: <Badge variant="soft">Revoked</Badge>
};

/** Shows an invitation link once; it can't be read back later, only replaced. */
function InvitationLinkReveal({ link, onDone }: { link: InvitationLink; onDone: () => void }) {
  const emailed = link.invitation.email_status === "sent" ? `It was also emailed to ${link.invitation.email}.` : link.invitation.email_status === "failed" ? "Emailing it failed, so share it yourself." : "Share it with them privately.";
  return (
    <ConfirmDialog confirmLabel="Done" description={`Anyone with this link can join as ${ROLE_LABEL[link.invitation.role]} until ${new Date(link.invitation.expires_at).toLocaleString()} or until it's used. ${emailed} It won't be shown again.`} hideCancel onCancel={onDone} onConfirm={onDone} size="wide" title={`Invitation for ${link.invitation.email}`}>
      <div className="lw-row lw-row--wrap"><code className="lw-code-inline lw-break">{link.url}</code><CopyButton label="Copy invitation link" value={link.url} /></div>
      {link.invitation.email_status === "failed" ? <Notice tone="warning">The server couldn&apos;t send the email. Check its SMTP settings.</Notice> : null}
    </ConfirmDialog>
  );
}

function InviteMemberDrawer({ emailDelivery, existing, onClose, onInvited, organizationID }: { emailDelivery: boolean; existing: readonly Administrator[]; onClose: () => void; onInvited: (link: InvitationLink) => void; organizationID: string }) {
  const [role, setRole] = useState<Role>("viewer");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [send, setSend] = useState(emailDelivery);
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const duplicate = existing.some((member) => member.email.toLowerCase() === email.trim().toLowerCase());

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (duplicate) return;
    setBusy(true);
    setProblem(undefined);
    try {
      onInvited(await createInvitation(organizationID, { ...(name.trim() ? { display_name: name.trim() } : {}), email: email.trim(), role, send_email: emailDelivery && send }));
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">They choose their own password, or sign in to an account they already have</span>} title="Invite member">
      <form autoComplete="off" className="lw-stack" onSubmit={(event) => void submit(event)}>
        <Field error={duplicate ? "Someone on the team already uses this email." : undefined} id="invite-email" label="Email"><Input id="invite-email" maxLength={320} onChange={(event) => setEmail(event.target.value)} required type="email" value={email} /></Field>
        <Field hint="Optional; they can change it when they accept." id="invite-name" label="Name"><Input id="invite-name" maxLength={200} onChange={(event) => setName(event.target.value)} value={name} /></Field>
        <div><strong className="lw-note">Role</strong><RoleCards name="invite-role" onChange={setRole} value={role} /></div>
        <CapabilityList to={role} />
        {emailDelivery ? <label className="lw-check"><input checked={send} onChange={(event) => setSend(event.target.checked)} type="checkbox" /><span>Email the invitation link</span></label> : <p className="lw-secondary lw-note">This server doesn&apos;t send email; you&apos;ll get a link to share.</p>}
        <p className="lw-secondary lw-note">The link works once and expires in seven days. Inviting the same address again replaces the earlier link.</p>
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={duplicate} loading={busy} type="submit" variant="primary">Create Invitation</Button></div>
      </form>
    </DetailPanel>
  );
}

function InvitationsCard({ enabled, onLink, organizationID }: { enabled: boolean; onLink: (link: InvitationLink) => void; organizationID: string }) {
  const queryClient = useQueryClient();
  const invitations = useQuery(invitationsQueryOptions(organizationID));
  const [busy, setBusy] = useState<string>();
  const [revoking, setRevoking] = useState<Invitation>();
  const [problem, setProblem] = useState<AdminProblem>();
  const items = invitations.data?.items ?? [];
  const open = items.filter((item) => item.status === "pending" || item.status === "expired");
  const refresh = () => queryClient.invalidateQueries({ queryKey: invitationsQueryOptions(organizationID).queryKey });

  async function renew(item: Invitation): Promise<void> {
    setBusy(item.id);
    setProblem(undefined);
    try {
      onLink(await renewInvitation(organizationID, item.id, false));
      await refresh();
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(undefined);
    }
  }

  async function revoke(item: Invitation): Promise<void> {
    setBusy(item.id);
    setProblem(undefined);
    try {
      await revokeInvitation(organizationID, item.id);
      setRevoking(undefined);
      await refresh();
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(undefined);
    }
  }

  if (!invitations.data && !invitations.error) return null;
  return (
    <Card description={open.length ? `${open.length} open ${open.length === 1 ? "invitation" : "invitations"}. Links can't be shown again; New Link replaces one.` : "Invitations you send appear here until they're used, revoked or replaced."} flush icon="users" title="Invitations">
      {invitations.error ? <div className="lw-card__body"><ProblemNotice problem={problemFromError(invitations.error)} /></div> : null}
      {problem ? <div className="lw-card__body"><ProblemNotice problem={problem} /></div> : null}
      {items.length ? (
        <div className="lw-table-wrap">
          <table className="lw-table lw-table--dense">
            <thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Invited by</th><th scope="col">Expires</th><th scope="col"><span className="lw-sr">Actions</span></th></tr></thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td>{item.email}{item.email_status === "failed" ? <> <Badge color="warning" variant="soft">Email failed</Badge></> : null}</td>
                  <td>{ROLE_LABEL[item.role]}</td>
                  <td>{INVITATION_STATUS[item.status]}</td>
                  <td>{item.invited_by}</td>
                  <td className="lw-num">{item.status === "pending" || item.status === "expired" ? when(item.expires_at) : "—"}</td>
                  <td>{enabled && (item.status === "pending" || item.status === "expired") ? (
                    <span className="lw-row lw-row--wrap">
                      <Button disabled={Boolean(busy)} loading={busy === item.id && !revoking} onClick={() => void renew(item)} size="sm">New Link</Button>
                      {item.status === "pending" ? <Button destructive disabled={Boolean(busy)} onClick={() => setRevoking(item)} size="sm" variant="ghost">Revoke</Button> : null}
                    </span>
                  ) : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {revoking ? <ConfirmDialog confirmLabel="Revoke" description={`The link sent to ${revoking.email} stops working.`} destructive onCancel={() => setRevoking(undefined)} onConfirm={() => void revoke(revoking)} pending={busy === revoking.id} title="Revoke this invitation?" /> : null}
    </Card>
  );
}

const RAISED_ROLES: readonly Role[] = ["operator", "admin"];

/**
 * Roles that raise a member's organization role in single applications. They never lower it, so only roles above the
 * organization role are offered, and owners have none.
 */
function ApplicationRolesSection({ canEdit, member }: { canEdit: boolean; member: Administrator }) {
  const queryClient = useQueryClient();
  const organizationID = member.organization_id;
  const applications = useQuery(applicationsQueryOptions(organizationID));
  const grants = useQuery(applicationRolesQueryOptions);
  const [busy, setBusy] = useState<string>();
  const [problem, setProblem] = useState<AdminProblem>();
  const offered = RAISED_ROLES.filter((candidate) => ROLES.indexOf(candidate) < ROLES.indexOf(member.role));
  const mine = new Map((grants.data ?? []).filter((grant) => grant.admin_user_id === member.id).map((grant) => [grant.application_id, grant.role]));
  if (member.role === "owner" || !offered.length) {
    return <p className="lw-secondary lw-note">{member.role === "owner" ? "Owners have every role in every application." : `${ROLE_LABEL[member.role]} is the highest role an application can grant, so there's nothing to raise.`}</p>;
  }

  async function change(applicationID: string, next: string): Promise<void> {
    setBusy(applicationID);
    setProblem(undefined);
    try {
      if (next === "") await removeApplicationRole(member.id, applicationID);
      else await setApplicationRole(member.id, applicationID, next as "admin" | "operator");
      await queryClient.invalidateQueries({ queryKey: applicationRolesQueryOptions.queryKey });
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(undefined);
    }
  }

  const items = applications.data?.items ?? [];
  return (
    <div className="lw-stack">
      <p className="lw-secondary lw-note">Raise {member.display_name}&apos;s role in one application without changing it elsewhere.</p>
      {problem ? <ProblemNotice problem={problem} /> : null}
      {items.length ? (
        <ul className="lw-session-list">
          {items.map((application) => (
            <li key={application.id}>
              <label className="lw-note" htmlFor={`app-role-${member.id}-${application.id}`}>{application.display_name}</label>
              <div className="lw-input-box">
                <select aria-label={`Role in ${application.display_name}`} className="lw-input" disabled={!canEdit || busy === application.id} id={`app-role-${member.id}-${application.id}`} onChange={(event) => void change(application.id, event.target.value)} value={mine.get(application.id) ?? ""}>
                  <option value="">{ROLE_LABEL[member.role]} (organization role)</option>
                  {offered.map((candidate) => <option key={candidate} value={candidate}>{ROLE_LABEL[candidate]}</option>)}
                </select>
              </div>
            </li>
          ))}
        </ul>
      ) : <p className="lw-secondary lw-note">{applications.isPending ? "Loading applications…" : "No applications yet."}</p>}
    </div>
  );
}

type MemberAction = { kind: "role"; role: Role } | { kind: "disable" } | { kind: "enable" } | { kind: "reset" } | { kind: "reset2fa" } | { kind: "signout"; session: AdminSessionMetadata };

function MemberDrawer({ activeOwners, member, onClose, onUpdated, sessions }: { activeOwners: number; member: Administrator; onClose: () => void; onUpdated: () => Promise<void>; sessions: readonly AdminSessionMetadata[] }) {
  const me = useMe();
  const [role, setRole] = useState<Role>(member.role);
  const [savedRole, setSavedRole] = useState<Role>(member.role);
  if (savedRole !== member.role) {
    // The server changed the role (here or elsewhere): start the picker from it.
    setSavedRole(member.role);
    setRole(member.role);
  }
  const [action, setAction] = useState<MemberAction>();
  const [typed, setTyped] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [notice, setNotice] = useState<string>();
  const [busy, setBusy] = useState(false);
  const password = useRef<HTMLInputElement>(null);
  const canEdit = me.canManageOwners && me.mutationAllowed;
  const lastOwner = member.role === "owner" && member.status === "active" && activeOwners <= 1;
  const disabled = member.status === "disabled";
  const self = member.id === me.id;
  const change = roleChange(member.role, role);
  const theirSessions = sessions.filter((session) => session.administrator.id === member.id && session.status === "active");

  function open(next: MemberAction): void {
    setAction(next);
    setTyped("");
    setAcknowledged(false);
    setProblem(undefined);
  }

  async function run(): Promise<void> {
    if (!action) return;
    setBusy(true);
    setProblem(undefined);
    try {
      if (action.kind === "role") await adminRequest(`/admin/v1/administrators/${member.id}/role`, AdministratorSchema, { body: { role: action.role }, method: "PUT" });
      if (action.kind === "disable") await adminRequest(`/admin/v1/administrators/${member.id}/disable`, AdministratorSchema, { method: "POST" });
      if (action.kind === "enable") await adminRequest(`/admin/v1/administrators/${member.id}/enable`, AdministratorSchema, { method: "POST" });
      if (action.kind === "reset") {
        const secret = takePassword(password);
        if (secret.length < 12) throw new Error("The new password needs at least 12 characters.");
        await adminRequest(`/admin/v1/administrators/${member.id}/reset-password`, AdministratorSchema, { body: { password: secret }, method: "POST" });
      }
      if (action.kind === "reset2fa") await resetMemberTwoFactor(member.id);
      if (action.kind === "signout") await adminRequest(`/admin/v1/admin-sessions/${action.session.id}/revoke`, z.undefined(), { method: "POST" });
      setNotice(action.kind === "reset2fa" ? `${member.display_name}'s two-factor sign-in was removed and their sessions here ended.` : action.kind === "role" ? `${member.display_name} is now ${ROLE_LABEL[action.role]}.` : action.kind === "disable" ? `${member.display_name} is disabled; their sessions and API tokens were revoked.` : action.kind === "enable" ? `${member.display_name} can sign in again. Revoked sessions and tokens stay revoked.` : action.kind === "reset" ? "Password replaced. Share it privately; their sessions and API tokens were revoked." : "Session signed out.");
      setAction(undefined);
      await onUpdated();
    } catch (failure) {
      setProblem(failure instanceof Error && !("problem" in failure) ? { code: "request_invalid", detail: failure.message, retryable: false, status: 0, title: "Not done" } : problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  const roleReason = (candidate: Role): string | undefined => {
    if (!canEdit) return undefined;
    if (disabled && candidate !== member.role) return "Enable them first";
    if (lastOwner && candidate !== "owner") return "Add another owner first";
    return undefined;
  };

  return (
    <>
      <DetailPanel
        actions={canEdit ? <>
          {disabled ? <Button onClick={() => open({ kind: "enable" })} size="sm">Enable</Button> : <Button destructive disabled={lastOwner} onClick={() => open({ kind: "disable" })} size="sm" title={lastOwner ? "The last active owner can't be disabled" : undefined}>Disable</Button>}
          <Button disabled={disabled} onClick={() => open({ kind: "reset" })} size="sm">Reset Password</Button>
          {member.two_factor_enabled ? <Button onClick={() => open({ kind: "reset2fa" })} size="sm">Reset Two-Factor</Button> : null}
        </> : undefined}
        className="lw-request-drawer"
        onClose={onClose}
        subtitle={<>{statusBadge(member)}<span className="lw-faint">{member.email}</span></>}
        title={member.display_name}
      >
        <div className="lw-stack">
          {member.password_reset_required && !disabled ? <Notice tone="info">They haven&apos;t chosen their own password yet. They will on their next sign-in.</Notice> : null}
          {disabled ? <Notice tone="warning">Disabled {when(member.disabled_at)}. Enable lets them sign in again; ended sessions and revoked tokens aren&apos;t restored.</Notice> : null}
          {notice ? <Notice tone="success">{notice}</Notice> : null}
          {!me.canManageOwners ? <Notice tone="info">View only: changing members needs the Owner role.</Notice> : null}
          <Properties columns={2} items={[
            { label: "Email", value: member.email },
            { label: "Role", value: ROLE_LABEL[member.role] },
            ...(member.two_factor_enabled === undefined ? [] : [{ label: "Two-factor", value: member.two_factor_enabled ? "On" : "Off" }]),
            ...(member.sso_linked === undefined ? [] : [{ label: "Single sign-on", value: member.sso_linked ? "Linked" : "Not linked" }]),
            { label: "Added", value: when(member.created_at) },
            { label: "Updated", value: when(member.updated_at) },
            { label: "Member ID", value: <span className="lw-mono lw-mono--sm">{member.id}</span> }
          ]} />
          <div>
            <strong className="lw-note">Role</strong>
            <RoleCards disabledReason={roleReason} name={`role-${member.id}`} onChange={(next) => (canEdit ? setRole(next) : undefined)} value={role} />
          </div>
          <CapabilityList from={member.role} to={role} />
          {self && role !== member.role ? <Notice tone="warning">This is your own role. {change.loses.length ? "You'll lose access to some pages as soon as you save." : ""}</Notice> : null}
          {change.loses.length ? <Notice tone="info">Their API tokens stop using what the new role doesn&apos;t allow: tokens never exceed their owner&apos;s role.</Notice> : null}
          {canEdit && role !== member.role ? <div className="lw-row"><Button onClick={() => setRole(member.role)}>Cancel</Button><Button onClick={() => open({ kind: "role", role })} variant="primary">Change to {ROLE_LABEL[role]}</Button></div> : null}
          {me.canManageOwners && me.applicationRolesSupported ? (
            <div>
              <strong className="lw-note">Application roles</strong>
              <ApplicationRolesSection canEdit={canEdit && !disabled} member={member} />
            </div>
          ) : null}
          <div>
            <strong className="lw-note">Console sessions</strong>
            {!me.canManageOwners ? <p className="lw-secondary lw-note">Only owners can see console sessions.</p> : theirSessions.length ? (
              <ul className="lw-session-list">
                {theirSessions.map((session) => (
                  <li key={session.id}>
                    <span className="lw-note">Signed in {when(session.created_at)} · last seen {when(session.last_seen_at)}{session.current ? " · This session" : ""}</span>
                    {canEdit ? <Button onClick={() => open({ kind: "signout", session })} size="sm" variant="ghost">Sign Out</Button> : null}
                  </li>
                ))}
              </ul>
            ) : <p className="lw-secondary lw-note">No active console sessions.</p>}
          </div>
          <p className="lw-secondary lw-note">Their API tokens are under Team › API tokens › Everyone.</p>
        </div>
      </DetailPanel>
      {action && canEdit ? (
        <ConfirmDialog
          confirmDisabled={(action.kind === "disable" || (action.kind === "role" && change.loses.length > 0)) ? typed !== member.email || !acknowledged : action.kind === "reset" ? !acknowledged : false}
          confirmLabel={action.kind === "role" ? `Change to ${ROLE_LABEL[action.role]}` : action.kind === "disable" ? "Disable" : action.kind === "enable" ? "Enable" : action.kind === "reset" ? "Reset Password" : action.kind === "reset2fa" ? "Reset Two-Factor" : "Sign Out"}
          description={action.kind === "role" ? "It applies at once, in every application and environment. Application roles the new role already covers are removed." : action.kind === "disable" ? "They're signed out of every console session and their API tokens stop working. There's no delete; Enable lets them sign in again, but ended sessions and revoked tokens aren't restored." : action.kind === "enable" ? "They can sign in again with their current password. Revoked sessions and tokens stay revoked." : action.kind === "reset" ? "Their console sessions end and their API tokens are revoked. They choose a new password when they next sign in." : action.kind === "reset2fa" ? "Their authenticator and recovery codes are removed and their console sessions here end. They sign in with just their password, and set it up again if this organization requires it. Do this only after confirming who's asking." : action.session.current ? "This is your current session: you'll be signed out." : "They'll need to sign in again on that device."}
          destructive={action.kind !== "enable"}
          onCancel={() => setAction(undefined)}
          onConfirm={() => void run()}
          pending={busy}
          size="wide"
          title={action.kind === "role" ? `Change ${member.display_name} to ${ROLE_LABEL[action.role]}?` : action.kind === "disable" ? `Disable ${member.display_name}?` : action.kind === "enable" ? `Enable ${member.display_name}?` : action.kind === "reset" ? `Reset ${member.display_name}'s password?` : action.kind === "reset2fa" ? `Reset ${member.display_name}'s two-factor sign-in?` : "Sign out this session?"}
        >
          {action.kind === "role" ? <CapabilityList from={member.role} to={action.role} /> : null}
          {action.kind === "disable" ? <p className="lw-note">Active console sessions: <strong>{theirSessions.length}</strong>.</p> : null}
          {action.kind === "reset" ? (
            <>
              <PasswordField hint="At least 12 characters. Share it privately; Latchway stores only a hash." id="reset-password" inputRef={password} label="New password" />
              <label className="lw-check"><input checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" /><span>I&apos;ll share it privately with {member.display_name}.</span></label>
            </>
          ) : null}
          {action.kind === "disable" || (action.kind === "role" && change.loses.length > 0) ? (
            <>
              <Field id="member-confirm" label={<>Type <code className="lw-code-inline">{member.email}</code> to confirm</>}><Input autoComplete="off" id="member-confirm" onChange={(event) => setTyped(event.target.value)} value={typed} /></Field>
              <label className="lw-check"><input checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" /><span>{action.kind === "disable" ? "I understand their sessions end and their API tokens stop working now." : "I understand they lose these capabilities now."}</span></label>
            </>
          ) : null}
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </>
  );
}

function MembersView() {
  const me = useMe();
  const workspace = useOptionalWorkspace();
  const queryClient = useQueryClient();
  const search = TeamRouteSearchSchema.parse(workspace?.search ?? {});
  const members = useMembers(me.canManageOwners);
  const sessions = useSessions(me.canManageOwners);
  const [adding, setAdding] = useState(false);
  const [inviting, setInviting] = useState(false);
  const [link, setLink] = useState<InvitationLink>();
  const compatibility = useConsoleCompatibility();
  const invitationsSupported = compatibility.status?.server_capabilities.includes("admin_invitations") ?? false;
  const organizationID = useConsoleSession().data?.session?.organization_id;
  const delivery = useQuery({ ...invitationsQueryOptions(organizationID ?? ""), enabled: invitationsSupported && me.canManageOwners && Boolean(organizationID) });
  const [roleFilter, setRoleFilter] = useState<"all" | Role>("all");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "password" | "disabled">("all");
  const [added, setAdded] = useState<string>();
  const items = useMemo(() => members.data?.pages.flatMap((page) => page.items) ?? [], [members.data]);
  const sessionItems = sessions.data?.pages.flatMap((page) => page.items) ?? [];
  const activeOwners = items.filter((member) => member.role === "owner" && member.status === "active").length;
  const shown = items.filter((member) => (roleFilter === "all" || member.role === roleFilter) && (statusFilter === "all" || (statusFilter === "disabled" ? member.status === "disabled" : statusFilter === "password" ? member.status === "active" && member.password_reset_required : member.status === "active" && !member.password_reset_required)));
  const open = (member: string | undefined) => workspace?.updateSearch({ member }, { replace: false });
  const selected = search.member ? items.find((member) => member.id === search.member) : undefined;

  const columns: Array<Column<Administrator>> = [
    { header: "Member", key: "member", render: (member) => <span className="lw-rq-model"><span>{member.display_name}{member.id === me.id ? <span className="lw-faint"> (you)</span> : null}</span><span className="lw-faint">{member.email}</span></span> },
    { header: "Role", key: "role", render: (member) => <Badge color={member.role === "owner" ? "accent" : undefined} variant="soft">{ROLE_LABEL[member.role]}</Badge> },
    { header: "Status", key: "status", render: statusBadge },
    { header: "Two-factor", key: "two-factor", render: (member) => (
      <span className="lw-row lw-row--wrap">
        {member.two_factor_enabled === undefined ? <span className="lw-faint">—</span> : member.two_factor_enabled ? <Badge color="success" variant="soft">On</Badge> : <span className="lw-note lw-secondary">Off</span>}
        {member.sso_linked ? <Badge title="Signs in with the organization's identity provider" variant="soft">SSO</Badge> : null}
      </span>
    ) },
    { header: "Added", key: "added", render: (member) => <span className="lw-note">{new Date(member.created_at).toLocaleDateString()}</span> }
  ];

  if (!me.canManageOwners) {
    return <div className="lw-page"><PageHeader description="People who can sign in to this console, and their roles." title="Members" /><OwnerOnly what="Listing the team" /></div>;
  }
  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={<>
        {invitationsSupported ? <Button disabled={!me.mutationAllowed} icon="plus" onClick={() => { setInviting(true); setAdding(false); open(undefined); }} variant="primary">Invite Member</Button> : null}
        <Button disabled={!me.mutationAllowed} icon={invitationsSupported ? undefined : "plus"} onClick={() => { setAdding(true); setInviting(false); open(undefined); }} variant={invitationsSupported ? "secondary" : "primary"}>Add Member</Button>
      </>} description="People who can sign in to this console. Roles apply to the whole organization: every application and environment." title="Members" />
      {added ? <div className="lw-page-notice"><Notice tone="success">{added}</Notice></div> : null}
      {members.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(members.error)} /></div> : null}
      <div className="lw-toolbar lw-toolbar--wrap">
        <Segmented items={[{ id: "all", label: "All roles" }, ...ROLES.map((role) => ({ id: role, label: ROLE_LABEL[role] }))]} label="Role" onChange={setRoleFilter} value={roleFilter} />
        <Segmented items={[{ id: "all", label: "Any status" }, { id: "active", label: "Active" }, { id: "password", label: "Must set password" }, { id: "disabled", label: "Disabled" }]} label="Status" onChange={setStatusFilter} value={statusFilter} />
      </div>
      {members.isPending ? <p className="lw-page-status" role="status">Loading members…</p> : shown.length ? (
        <DataTable caption="Members" columns={columns} onSelect={(member) => { setAdding(false); open(member.id); }} rowKey={(member) => member.id} rows={shown} selectedKey={search.member} />
      ) : <div className="lw-page-empty"><EmptyState icon="team" orientation="horizontal" title="No members match">Change the filters.</EmptyState></div>}
      <div className="lw-page-foot lw-row">
        <span className="lw-secondary lw-note">{activeOwners} active owner{activeOwners === 1 ? "" : "s"}. {activeOwners <= 1 ? "Add a second owner so the team isn't locked out if one account is lost." : ""}</span>
        {members.hasNextPage ? <Button loading={members.isFetchingNextPage} onClick={() => void members.fetchNextPage()} size="sm">Load More</Button> : null}
      </div>
      {invitationsSupported && organizationID ? <div className="lw-body"><InvitationsCard enabled={me.mutationAllowed} onLink={setLink} organizationID={organizationID} /></div> : null}
      {inviting && me.mutationAllowed && organizationID ? <div className="lw-drawer-dock lw-drawer-dock--wide"><InviteMemberDrawer emailDelivery={delivery.data?.email_delivery ?? false} existing={items} onClose={() => setInviting(false)} onInvited={(created) => { setInviting(false); setLink(created); void queryClient.invalidateQueries({ queryKey: invitationsQueryOptions(organizationID).queryKey }); }} organizationID={organizationID} /></div> : null}
      {link ? <InvitationLinkReveal link={link} onDone={() => setLink(undefined)} /> : null}
      {adding && me.mutationAllowed ? <div className="lw-drawer-dock lw-drawer-dock--wide"><AddMemberDrawer existing={items} onClose={() => setAdding(false)} onCreated={(member) => { setAdding(false); setAdded(`${member.display_name} was added as ${ROLE_LABEL[member.role]}. Share their first password privately; they'll choose their own when they sign in.`); void queryClient.invalidateQueries({ queryKey: ["team", "members"] }); open(member.id); }} /></div> : null}
      {selected ? <div className="lw-drawer-dock lw-drawer-dock--wide"><MemberDrawer activeOwners={activeOwners} key={selected.id} member={selected} onClose={() => open(undefined)} onUpdated={async () => { await Promise.all([members.refetch(), sessions.refetch()]); }} sessions={sessionItems} /></div> : null}
      {search.member && !members.isPending && !selected && !members.hasNextPage ? <div className="lw-page-notice"><Notice title="Member not found" tone="danger">No member has the ID <code className="lw-code-inline">{search.member}</code>. No one else was opened instead.</Notice></div> : null}
    </div>
  );
}

// ─── API tokens ─────────────────────────────────────────────────────────────

const STARTING_POINTS: ReadonlyArray<{ id: string; label: string; name: string; scopes: readonly Capability[] }> = [
  { id: "ci", label: "CI deploys", name: "ci-deploy", scopes: ["activate_configuration", "inspect_users"] },
  { id: "monitoring", label: "Monitoring (read-only)", name: "monitoring", scopes: ["inspect_users"] },
  { id: "incident", label: "Incident bot", name: "incident-bot", scopes: ["inspect_users", "revoke_installations"] },
  { id: "custom", label: "Custom", name: "", scopes: [] }
];

const EXPIRY = [["30", "30 days"], ["90", "90 days"], ["365", "1 year"], ["never", "No expiry"]] as const;

function uniqueName(name: string, taken: readonly string[]): string {
  if (!taken.includes(name)) return name;
  for (let suffix = 2; suffix < 100; suffix += 1) if (!taken.includes(`${name}-${suffix}`)) return `${name}-${suffix}`;
  return name;
}

function CreateTokenDrawer({ onClose, onCreated, taken }: { onClose: () => void; onCreated: (created: CreatedAPIToken) => void; taken: readonly string[] }) {
  const me = useMe();
  const [start, setStart] = useState("monitoring");
  const point = STARTING_POINTS.find((candidate) => candidate.id === start) ?? STARTING_POINTS[0]!;
  const [name, setName] = useState(() => uniqueName("monitoring", taken));
  const [scopes, setScopes] = useState<string[]>(["inspect_users"]);
  const [expiry, setExpiry] = useState<(typeof EXPIRY)[number][0]>("90");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);

  function choose(id: string): void {
    const next = STARTING_POINTS.find((candidate) => candidate.id === id) ?? STARTING_POINTS[0]!;
    setStart(id);
    if (next.name) setName(uniqueName(next.name, taken));
    setScopes(next.scopes.filter((scope) => me.capabilities.includes(scope)));
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      const expiresAt = expiry === "never" ? undefined : new Date(wallClock() + Number(expiry) * 86_400_000).toISOString();
      const created = (await adminRequest("/admin/v1/api-tokens", CreatedAPITokenSchema, { body: { name: name.trim(), scopes, ...(expiresAt ? { expires_at: expiresAt } : {}) }, method: "POST" })).data;
      onCreated(created);
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">A token acts as you and never exceeds your role</span>} title="Create token">
      <form className="lw-stack" onSubmit={(event) => void submit(event)}>
        <Segmented items={STARTING_POINTS.map((candidate) => ({ id: candidate.id, label: candidate.label }))} label="Starting point" onChange={choose} value={point.id} />
        <Field hint={taken.includes(name.trim()) ? "You already have a token with this name." : undefined} id="token-name" label="Name"><Input id="token-name" maxLength={256} mono onChange={(event) => setName(event.target.value)} required value={name} /></Field>
        <fieldset className="lw-fieldset">
          <legend>Can</legend>
          {CAPABILITIES.map((capability) => {
            const allowed = me.capabilities.includes(capability.id);
            return (
              <label className="lw-check" key={capability.id}>
                <input checked={scopes.includes(capability.id)} disabled={!allowed} onChange={(event) => setScopes((current) => (event.target.checked ? [...current, capability.id] : current.filter((scope) => scope !== capability.id)))} type="checkbox" />
                <span>{capability.label}{!allowed ? <span className="lw-faint"> · Needs the {ROLE_LABEL[lowestRoleWith(capability.id)]} role; you&apos;re {me.role ? `${me.role === "admin" || me.role === "operator" || me.role === "owner" ? "an" : "a"} ${ROLE_LABEL[me.role]}` : "not allowed"}</span> : null}</span>
              </label>
            );
          })}
        </fieldset>
        <Field id="token-expiry" label="Expires">
          <select className="lw-select" id="token-expiry" onChange={(event) => setExpiry(event.target.value as typeof expiry)} value={expiry}>{EXPIRY.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
        </Field>
        {expiry === "never" ? <Notice tone="warning">A token without expiry works until someone revokes it. Prefer an expiry and replace it on schedule.</Notice> : null}
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!scopes.length || !name.trim() || !me.mutationAllowed} loading={busy} type="submit" variant="primary">Create Token</Button></div>
      </form>
    </DetailPanel>
  );
}

/** The one time a token's secret is shown. Done unlocks only after the operator confirms they saved it. */
function TokenReveal({ created, onDone }: { created: CreatedAPIToken; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <ConfirmDialog confirmDisabled={!saved} confirmLabel="Done" hideCancel onCancel={onDone} onConfirm={onDone} size="wide" title={`Save ${created.metadata.name} now`}>
      <Notice tone="warning">This is the only time Latchway shows this token. Latchway keeps only a hash. Your clipboard may keep a copy.</Notice>
      <Field id="token-secret" label="Token"><textarea className="lw-json-editor lw-json-editor--short" id="token-secret" readOnly rows={2} value={created.token} /></Field>
      <div className="lw-row"><CopyButton className={buttonClass({ size: "sm" })} label="Copy token" value={created.token}>Copy Token</CopyButton><CopyButton className={buttonClass({ size: "sm", variant: "ghost" })} label="Copy export command" value={`export LATCHWAY_ADMIN_API_TOKEN='${created.token}'`}>Copy export command</CopyButton></div>
      <pre className="lw-code-block">export LATCHWAY_ADMIN_API_TOKEN=&apos;…&apos;</pre>
      <label className="lw-check"><input checked={saved} onChange={(event) => setSaved(event.target.checked)} type="checkbox" /><span>I&apos;ve saved it somewhere safe.</span></label>
    </ConfirmDialog>
  );
}

function TokensView() {
  const me = useMe();
  // Owners can also see everyone's tokens; the server checks manage_owners for that listing.
  const [scope, setScope] = useState<"mine" | "everyone">("mine");
  const everyone = scope === "everyone" && me.canManageOwners;
  const tokens = useQuery({ queryFn: async () => (await adminRequest(everyone ? "/admin/v1/api-tokens?scope=organization" : "/admin/v1/api-tokens", APITokenPageSchema)).data.items, queryKey: ["team", "tokens", everyone ? "everyone" : "mine"], retry: false });
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<{ created: CreatedAPIToken; replaces?: APITokenMetadata }>();
  const [askRevoke, setAskRevoke] = useState<APITokenMetadata>();
  const [revoking, setRevoking] = useState<APITokenMetadata>();
  const [typed, setTyped] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const [now] = useState(wallClock);
  const [allowed, setAllowed] = useState(me.mutationAllowed);
  if (allowed !== me.mutationAllowed) {
    // Losing compatibility scrubs a one-time secret for good; it is never shown again after recovery.
    setAllowed(me.mutationAllowed);
    if (!me.mutationAllowed) {
      setRevealed(undefined);
      setCreating(false);
    }
  }
  const items = tokens.data ?? [];
  const active = items.filter((token) => !token.revoked);
  const revoked = items.filter((token) => token.revoked);
  const expiring = active.filter((token) => { const days = daysUntil(token.expires_at, now); return days !== undefined && days <= 14; });

  async function replace(token: APITokenMetadata): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      const lifetime = token.expires_at ? Date.parse(token.expires_at) - Date.parse(token.created_at) : undefined;
      const created = (await adminRequest("/admin/v1/api-tokens", CreatedAPITokenSchema, { body: { name: token.name, scopes: token.scopes, ...(lifetime && lifetime > 0 ? { expires_at: new Date(wallClock() + lifetime).toISOString() } : {}) }, method: "POST" })).data;
      setRevealed({ created, replaces: token });
      await tokens.refetch();
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(token: APITokenMetadata): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      await adminRequest(`/admin/v1/api-tokens/${token.id}`, z.undefined(), { method: "DELETE" });
      setRevoking(undefined);
      setAskRevoke(undefined);
      await tokens.refetch();
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  const expiresBadge = (token: APITokenMetadata) => {
    const days = daysUntil(token.expires_at, now);
    if (days === undefined) return <Badge color="orange" variant="soft">No expiry</Badge>;
    if (days <= 0) return <Badge color="red" variant="soft">Expired</Badge>;
    if (days <= 14) return <Badge color="orange" variant="soft">In {days} day{days === 1 ? "" : "s"}</Badge>;
    return <span className="lw-note">{new Date(token.expires_at ?? "").toLocaleDateString()}</span>;
  };
  const columns: Array<Column<APITokenMetadata>> = [
    { header: "Token", key: "name", render: (token) => <span className="lw-rq-model"><span className="lw-mono lw-mono--sm">{token.name}</span><span className="lw-faint">{token.id}</span></span> },
    {
      header: "Can",
      key: "scopes",
      render: (token) => {
        const inactive = token.scopes.filter((scope) => !me.capabilities.includes(scope));
        return (
          <span className="lw-stack lw-stack--tight">
            <span className="lw-tags-inline">{token.scopes.map((scope) => <Badge key={scope} variant="soft">{inactive.includes(scope) ? <s>{capabilityLabel(scope)}</s> : capabilityLabel(scope)}</Badge>)}</span>
            {inactive.length ? <span className="lw-faint lw-note">{inactive.length === token.scopes.length ? "Not working: your role no longer allows any of this" : `${inactive.length} inactive: your role no longer allows it`}</span> : null}
          </span>
        );
      }
    },
    ...(everyone ? [{ header: "Owner", key: "owner", render: (token: APITokenMetadata) => <span className="lw-note">{token.administrator?.email ?? "—"}{token.administrator?.id === me.id ? <span className="lw-faint"> (you)</span> : null}</span> }] : []),
    { header: "Created", key: "created", render: (token) => <span className="lw-note">{new Date(token.created_at).toLocaleDateString()}</span> },
    { header: "Last used", key: "used", render: (token) => <span className="lw-note">{token.last_used_at ? when(token.last_used_at) : "Never"}</span> },
    { header: "Expires", key: "expires", render: expiresBadge },
    {
      align: "right",
      header: "",
      key: "actions",
      render: (token) => {
        // Replacing creates a token for you, so it's offered only on your own tokens.
        const mine = !token.administrator || token.administrator.id === me.id;
        return <span className="lw-row lw-row--tight">{mine ? <Button disabled={!me.mutationAllowed || busy} onClick={() => void replace(token)} size="sm" variant="ghost">Replace</Button> : null}<Button destructive disabled={!me.mutationAllowed} onClick={() => { setRevoking(token); setTyped(""); }} size="sm" variant="ghost">Revoke</Button></span>;
      }
    }
  ];

  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={<Button disabled={!me.mutationAllowed} icon="plus" onClick={() => setCreating(true)} variant="primary">Create Token</Button>} description={everyone ? "Every administrator's tokens in this organization. Revoking one stops its scripts at once." : "Your tokens for scripts and the CLI. Each acts as you, with only the capabilities you pick, and never more than your role allows."} title="API tokens" />
      {me.canManageOwners ? <div className="lw-toolbar"><Segmented items={[{ id: "mine", label: "Mine" }, { id: "everyone", label: "Everyone" }]} label="Whose tokens" onChange={setScope} value={scope} /></div> : null}
      {expiring.map((token) => <div className="lw-page-notice" key={token.id}><Notice action={<Button onClick={() => void replace(token)} size="sm">Replace {token.name}</Button>} tone="warning">{token.name} expires {daysUntil(token.expires_at, now)! <= 0 ? "now" : `in ${daysUntil(token.expires_at, now)} days`}.</Notice></div>)}
      {problem ? <div className="lw-page-notice"><ProblemNotice problem={problem} /></div> : null}
      {tokens.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(tokens.error)} /></div> : null}
      {tokens.isPending ? <p className="lw-page-status" role="status">Loading tokens…</p> : active.length ? (
        <DataTable caption="API tokens" columns={columns} rowKey={(token) => token.id} rows={active} />
      ) : <div className="lw-page-empty"><EmptyState icon="key" orientation="horizontal" title="No active tokens">Create one for CI, monitoring or the CLI. It&apos;s shown once.</EmptyState></div>}
      {revoked.length ? <div className="lw-body"><Card icon="ban" meta={`${revoked.length}`} title="Revoked"><ul className="lw-session-list">{revoked.map((token) => <li key={token.id}><span className="lw-mono lw-mono--sm">{token.name}</span><span className="lw-faint lw-note">{token.id}</span></li>)}</ul></Card></div> : null}
      {creating && me.mutationAllowed ? <div className="lw-drawer-dock lw-drawer-dock--wide"><CreateTokenDrawer onClose={() => setCreating(false)} onCreated={(created) => { setCreating(false); setRevealed({ created }); void tokens.refetch(); }} taken={active.map((token) => token.name)} /></div> : null}
      {revealed && me.mutationAllowed ? <TokenReveal created={revealed.created} onDone={() => { const old = revealed.replaces; setRevealed(undefined); if (old) setAskRevoke(old); }} /> : null}
      {askRevoke ? (
        <ConfirmDialog cancelLabel="Later" confirmLabel="Revoke Old Token" description="Until you revoke it, the old token keeps working alongside the new one. You can revoke it later from this table." destructive onCancel={() => setAskRevoke(undefined)} onConfirm={() => void revoke(askRevoke)} pending={busy} title={`Revoke the old ${askRevoke.name} now?`}>
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
      {revoking ? (
        <ConfirmDialog confirmDisabled={typed !== revoking.name} confirmLabel="Revoke" description="Requests using it are refused at once, and self-test schedules bound to it stop. This can't be undone; create a new token if you still need one." destructive onCancel={() => setRevoking(undefined)} onConfirm={() => void revoke(revoking)} pending={busy} title={`Revoke ${revoking.name}?`}>
          <Field id="revoke-confirm" label={<>Type <code className="lw-code-inline">{revoking.name}</code> to confirm</>}><Input autoComplete="off" id="revoke-confirm" mono onChange={(event) => setTyped(event.target.value)} value={typed} /></Field>
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

// ─── Sessions ───────────────────────────────────────────────────────────────

function SessionsView() {
  const me = useMe();
  const sessions = useSessions(me.canManageOwners);
  const [target, setTarget] = useState<AdminSessionMetadata | "others">();
  const [problem, setProblem] = useState<AdminProblem>();
  const [result, setResult] = useState<string>();
  const [busy, setBusy] = useState(false);
  const items = sessions.data?.pages.flatMap((page) => page.items) ?? [];
  const active = items.filter((session) => session.status === "active");
  const others = active.filter((session) => !session.current);
  const people = new Set(others.map((session) => session.administrator.id)).size;

  async function signOut(): Promise<void> {
    if (!target) return;
    setBusy(true);
    setProblem(undefined);
    const list = target === "others" ? others : [target];
    let done = 0;
    try {
      for (const session of list) {
        await adminRequest(`/admin/v1/admin-sessions/${session.id}/revoke`, z.undefined(), { method: "POST" });
        done += 1;
      }
      setResult(target === "others" ? `Signed out ${done} session${done === 1 ? "" : "s"}.` : "Session signed out.");
      setTarget(undefined);
    } catch (failure) {
      setProblem(problemFromError(failure));
      if (target === "others" && done) setResult(`Signed out ${done} of ${list.length} sessions before an error.`);
    } finally {
      setBusy(false);
      await sessions.refetch();
    }
  }

  const columns: Array<Column<AdminSessionMetadata>> = [
    { header: "Member", key: "who", render: (session) => <span>{session.administrator.email}{session.current ? <> <Badge color="accent" variant="soft">This session</Badge></> : null}</span> },
    { header: "Device", key: "device", render: (session) => <span className="lw-note">{session.device_summary ?? "—"}</span> },
    { header: "Signed in", key: "created", render: (session) => <span className="lw-note">{when(session.created_at)}</span> },
    { header: "Last seen", key: "seen", render: (session) => <span className="lw-note">{when(session.last_seen_at)}</span> },
    { header: "Expires", key: "expires", render: (session) => <span className="lw-note">{when(session.expires_at)}</span> },
    { header: "Status", key: "status", render: (session) => session.status === "active" ? <Badge color="success" variant="soft">Active</Badge> : <Badge variant="soft">{session.status === "revoked" ? "Signed out" : "Expired"}</Badge> },
    { align: "right", header: "", key: "action", render: (session) => session.status === "active" ? <Button disabled={!me.mutationAllowed} onClick={() => setTarget(session)} size="sm" variant="ghost">Sign Out</Button> : null }
  ];

  if (!me.canManageOwners) return <div className="lw-page"><PageHeader description="Who is signed in to this console." title="Sessions" /><OwnerOnly what="Listing console sessions" /></div>;
  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={<Button destructive disabled={!me.mutationAllowed || !others.length} onClick={() => setTarget("others")}>Sign Out Everyone Else</Button>} description="Console sign-ins in this organization, each with the time it expires. Signing one out takes effect on its next request. Your app users' sessions are under Client Trust › Sessions." title="Sessions" />
      {result ? <div className="lw-page-notice"><Notice tone="success">{result}</Notice></div> : null}
      {sessions.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(sessions.error)} /></div> : null}
      {sessions.isPending ? <p className="lw-page-status" role="status">Loading sessions…</p> : <DataTable caption="Sessions" columns={columns} rowKey={(session) => session.id} rows={items} />}
      {sessions.hasNextPage ? <div className="lw-page-foot"><Button loading={sessions.isFetchingNextPage} onClick={() => void sessions.fetchNextPage()} size="sm">Load More</Button></div> : null}
      <p className="lw-secondary lw-note lw-page-foot">Device and browser details aren&apos;t recorded; the server keeps only times.</p>
      {target ? (
        <ConfirmDialog confirmLabel={target === "others" ? `Sign Out ${others.length} Session${others.length === 1 ? "" : "s"}` : "Sign Out"} description={target === "others" ? `${others.length} session${others.length === 1 ? "" : "s"} for ${people} ${people === 1 ? "person" : "people"} end now; they'll need to sign in again. Your session stays. API tokens aren't affected; revoke those separately.` : target.current ? "This is your current session: you'll be signed out." : `${target.administrator.email} will need to sign in again on that device.`} destructive onCancel={() => setTarget(undefined)} onConfirm={() => void signOut()} pending={busy} title={target === "others" ? "Sign out everyone else?" : "Sign out this session?"}>
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

// ─── Roles ──────────────────────────────────────────────────────────────────

function RolesView() {
  const me = useMe();
  const members = useMembers(me.canManageOwners);
  const items = members.data?.pages.flatMap((page) => page.items) ?? [];
  const count = (role: Role) => items.filter((member) => member.role === role && member.status === "active").length;
  return (
    <div className="lw-page">
      <PageHeader description="Four fixed roles. They apply to every application and environment in the organization; API tokens never exceed their owner's role." title="Roles" />
      <div className="lw-body lw-stack">
        <div className="lw-table-scroll">
          <table className="lw-mini-table lw-role-matrix">
            <thead><tr><th>Capability</th>{ROLES.map((role) => <th key={role}>{ROLE_LABEL[role]}{me.role === role ? <span className="lw-faint"> (you)</span> : null}{me.canManageOwners && members.data ? <div className="lw-faint lw-note">{count(role)} active</div> : null}</th>)}<th>Unlocks</th></tr></thead>
            <tbody>
              {CAPABILITIES.map((capability) => (
                <tr key={capability.id}>
                  <td>{capability.label}<div className="lw-faint lw-mono lw-mono--sm">{capability.id}</div></td>
                  {ROLES.map((role) => <td aria-label={capability.roles.includes(role) ? "Yes" : "No"} key={role}>{capability.roles.includes(role) ? "✓" : ""}</td>)}
                  <td className="lw-note">{capability.pages}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="lw-secondary lw-note"><code className="lw-code-inline">view_prompt_bodies</code> is reserved: Latchway v1 never stores prompts or responses.</p>
        <p className="lw-secondary lw-note">Roles per application or environment aren&apos;t available yet.</p>
      </div>
    </div>
  );
}

/** Team & Access → Members. */
export function MembersPage() { return <TeamScope><MembersView /></TeamScope>; }
/** Team & Access → API tokens. */
export function TokensPage() { return <TeamScope><TokensView /></TeamScope>; }
/** Team & Access → Sessions. */
export function SessionsPage() { return <TeamScope><SessionsView /></TeamScope>; }
/** Team & Access → Roles. */
export function RolesPage() { return <TeamScope><RolesView /></TeamScope>; }

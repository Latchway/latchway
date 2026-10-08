import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, useRef, useState } from "react";

import { changeOwnPassword, disableTwoFactor, ownSessionsQueryOptions, replaceRecoveryCodes, signOutOwnSessions, twoFactorStatusQueryOptions } from "../../api/account";
import type { OwnAdminSession, SessionEndReason } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { organizationsQueryOptions } from "../../api/workspace";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { PasswordInput } from "../../app/auth/auth-fields";
import { acceptable, passwordStrength, type Strength } from "../../app/auth/password-strength";
import { sessionEndText } from "../../app/auth/session-model";
import { StrengthMeter } from "../../app/auth/strength-meter";
import { RecoveryCodesReveal, TotpSetup } from "../../app/auth/totp-setup";
import { scopeSearch } from "../../app/navigation";
import { PasswordField } from "../../components/password-field";
import { Badge, Button, Card, ConfirmDialog, Field, Notice, PageHeader, Properties } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";
import { ROLE_LABEL } from "../team/roles";

const END_REASON: Readonly<Record<SessionEndReason, string>> = {
  access_disabled: "Access disabled",
  expired: "Expired",
  organization_switch: "Switched organization",
  other: "Ended",
  password_changed: "Password changed",
  password_reset: "Password reset by an owner",
  revoked_by_owner: "Signed out by an owner",
  signed_out: "Signed out",
  signed_out_elsewhere: "Signed out from another session",
  two_factor_reset: "Two-factor reset by an owner"
};

function when(instant: string): string {
  return new Date(instant).toLocaleString(undefined, { day: "numeric", hour: "2-digit", hour12: false, minute: "2-digit", month: "short" });
}

function PasswordCard({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const current = useRef<HTMLInputElement>(null);
  const next = useRef<HTMLInputElement>(null);
  const [strength, setStrength] = useState<Strength>();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [done, setDone] = useState<number>();

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setDone(undefined);
    if (!acceptable(passwordStrength(next.current?.value ?? ""))) {
      setProblem({ code: "request_invalid", detail: "Choose a password rated Good or Strong: at least 12 characters with some variety, or a longer passphrase.", retryable: false, status: 0, title: "Choose a stronger password" });
      next.current?.focus();
      return;
    }
    setPending(true);
    setProblem(undefined);
    try {
      setDone(await changeOwnPassword(current.current, next.current));
      setStrength(undefined);
      await queryClient.invalidateQueries({ queryKey: ownSessionsQueryOptions.queryKey });
    } catch (error) {
      setProblem(problemFromError(error));
      setStrength(undefined);
    } finally {
      setPending(false);
    }
  }

  return (
    <Card description="Changing it signs out your other console sessions in every organization. API tokens keep working." icon="key" title="Password">
      {enabled ? (
        <form aria-busy={pending} className="lw-stack" onSubmit={(event) => void submit(event)}>
          <PasswordInput disabled={pending} id="account-current-password" inputRef={current} label="Current password" />
          <PasswordField id="account-new-password" inputRef={next} label="New password" name="new_password" onValueChange={(value) => setStrength(value ? passwordStrength(value) : undefined)} />
          <StrengthMeter strength={strength} />
          {problem ? <ProblemNotice problem={problem} /> : null}
          {done !== undefined ? <Notice title="Password changed." tone="success">{done === 0 ? "No other sessions were open." : `${done} other ${done === 1 ? "session was" : "sessions were"} signed out.`}</Notice> : null}
          <div><Button loading={pending} type="submit" variant="primary">Change Password</Button></div>
        </form>
      ) : <Notice icon="lock" title="Password changes are unavailable." tone="info">The console is read-only until it can verify the server, or this server predates account self-service.</Notice>}
    </Card>
  );
}

function CodeInput({ id, inputRef }: { id: string; inputRef: React.RefObject<HTMLInputElement | null> }) {
  return (
    <Field id={id} label="Authentication code">
      <div className="lw-input-box"><input autoComplete="one-time-code" className="lw-input lw-input--mono" id={id} inputMode="numeric" maxLength={6} pattern="[0-9]{6}" ref={inputRef} /></div>
    </Field>
  );
}

function TwoFactorCard({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery(twoFactorStatusQueryOptions);
  const [settingUp, setSettingUp] = useState(false);
  const [dialog, setDialog] = useState<"codes" | "off">();
  const [codes, setCodes] = useState<string[]>();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const code = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const on = status.data?.totp_enabled ?? false;
  const required = status.data?.required_by_organization ?? false;

  // Losing the ability to change things closes any step that holds a key, code or password.
  if (!enabled && (settingUp || dialog || codes)) {
    setSettingUp(false);
    setDialog(undefined);
    setCodes(undefined);
  }

  async function run(action: () => Promise<void>): Promise<void> {
    setPending(true);
    setProblem(undefined);
    try {
      await action();
      await queryClient.invalidateQueries({ queryKey: twoFactorStatusQueryOptions.queryKey });
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setPending(false);
    }
  }

  return (
    <Card
      description="A code from an authenticator app, asked for after your password. Recovery codes get you in if you lose the app."
      icon="shield"
      meta={status.data ? <Badge color={on ? "success" : undefined} dot>{on ? "On" : "Off"}</Badge> : undefined}
      title="Two-factor sign-in"
    >
      {status.error ? <ProblemNotice problem={problemFromError(status.error)} /> : null}
      {required && !on ? <Notice tone="warning">This organization requires two-factor sign-in.</Notice> : null}
      {!enabled ? <Notice icon="lock" title="Two-factor changes are unavailable." tone="info">The console is read-only until it can verify the server, or this server predates two-factor sign-in.</Notice> : on ? (
        <div className="lw-stack">
          <Properties columns={1} items={[
            { label: "Turned on", value: status.data?.totp_enabled_at ? when(status.data.totp_enabled_at) : "—" },
            { label: "Recovery codes left", value: `${status.data?.recovery_codes_remaining ?? 0} of 10` }
          ]} />
          {(status.data?.recovery_codes_remaining ?? 10) <= 3 ? <Notice tone="warning">You&apos;re running low on recovery codes. Replace them so you aren&apos;t locked out.</Notice> : null}
          <div className="lw-row lw-row--wrap">
            <Button onClick={() => { setProblem(undefined); setDialog("codes"); }} size="sm">Replace Recovery Codes</Button>
            <Button destructive disabled={required} onClick={() => { setProblem(undefined); setDialog("off"); }} size="sm" title={required ? "Your organization requires two-factor sign-in." : undefined} variant="ghost">Turn Off</Button>
          </div>
        </div>
      ) : settingUp ? <TotpSetup onCancel={() => setSettingUp(false)} onDone={() => setSettingUp(false)} /> : (
        <div><Button onClick={() => setSettingUp(true)} variant="primary">Set Up Two-Factor</Button></div>
      )}
      {dialog === "codes" ? (
        <ConfirmDialog confirmLabel="Replace Codes" description="Your current recovery codes stop working. Enter a code from your authenticator to confirm." onCancel={() => setDialog(undefined)} onConfirm={() => void run(async () => { const issued = await replaceRecoveryCodes(code.current); setDialog(undefined); setCodes(issued); })} pending={pending} title="Replace your recovery codes?">
          <CodeInput id="replace-codes-code" inputRef={code} />
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
      {dialog === "off" ? (
        <ConfirmDialog confirmLabel="Turn Off" description="Signing in will need only your password. Your recovery codes are deleted." destructive onCancel={() => setDialog(undefined)} onConfirm={() => void run(async () => { await disableTwoFactor(password.current, code.current); setDialog(undefined); })} pending={pending} title="Turn off two-factor sign-in?">
          <PasswordInput id="disable-two-factor-password" inputRef={password} />
          <CodeInput id="disable-two-factor-code" inputRef={code} />
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
      {codes ? <RecoveryCodesReveal codes={codes} onDone={() => setCodes(undefined)} /> : null}
    </Card>
  );
}

function SessionsCard({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const sessions = useQuery(ownSessionsQueryOptions);
  const organizations = useQuery(organizationsQueryOptions());
  const names = new Map((organizations.data?.items ?? []).map((item) => [item.id, item.display_name]));
  const [busy, setBusy] = useState<string>();
  const [confirmOthers, setConfirmOthers] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const items = sessions.data?.items ?? [];
  const others = items.filter((item) => item.status === "active" && !item.current);

  async function signOut(target?: OwnAdminSession): Promise<void> {
    setBusy(target?.id ?? "others");
    setProblem(undefined);
    try {
      await signOutOwnSessions(target?.id);
      setConfirmOthers(false);
      await queryClient.invalidateQueries({ queryKey: ownSessionsQueryOptions.queryKey });
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setBusy(undefined);
    }
  }

  return (
    <Card
      actions={enabled && others.length ? <Button destructive disabled={Boolean(busy)} onClick={() => setConfirmOthers(true)} size="sm">Sign Out Other Sessions</Button> : undefined}
      description="Console sessions on your account in every organization, including those that ended in the last 30 days."
      flush
      icon="users"
      title="Your sessions"
    >
      {problem ? <div className="lw-card__body"><ProblemNotice problem={problem} /></div> : null}
      {sessions.error ? <div className="lw-card__body"><ProblemNotice problem={problemFromError(sessions.error)} /></div> : null}
      <div className="lw-table-wrap">
        <table className="lw-table lw-table--dense">
          <thead><tr><th scope="col">Device</th><th scope="col">Organization</th><th scope="col">Signed in</th><th scope="col">Last active</th><th scope="col">Status</th><th scope="col"><span className="lw-sr">Actions</span></th></tr></thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>{item.device_summary ?? "Unknown device"}{item.current ? <> <Badge color="accent">This session</Badge></> : null}</td>
                <td>{names.get(item.organization_id) ?? <span className="lw-mono lw-mono--sm">{item.organization_id}</span>}</td>
                <td className="lw-num">{when(item.created_at)}</td>
                <td className="lw-num">{when(item.last_seen_at)}</td>
                <td>{item.status === "active" ? <Badge color="success" dot>Active</Badge> : <Badge dot>{item.end_reason ? END_REASON[item.end_reason] : "Ended"}</Badge>}</td>
                <td>{enabled && item.status === "active" && !item.current ? <Button disabled={Boolean(busy)} loading={busy === item.id} onClick={() => void signOut(item)} size="sm" variant="ghost">Sign Out</Button> : null}</td>
              </tr>
            ))}
            {!items.length ? <tr><td colSpan={6}>{sessions.isPending ? "Loading sessions…" : "No sessions."}</td></tr> : null}
          </tbody>
        </table>
      </div>
      {confirmOthers ? (
        <ConfirmDialog confirmLabel="Sign Out Other Sessions" description={`${others.length} other ${others.length === 1 ? "session ends" : "sessions end"} now. This session stays signed in.`} destructive onCancel={() => setConfirmOthers(false)} onConfirm={() => void signOut()} pending={busy === "others"} title="Sign out your other sessions?" />
      ) : null}
    </Card>
  );
}

export function AccountPage() {
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const organizations = useQuery(organizationsQueryOptions());
  const admin = session.data?.session;
  if (!admin) return null;
  const supported = compatibility.status?.server_capabilities.includes("admin_account_self_service") ?? false;
  const twoFactorSupported = compatibility.status?.server_capabilities.includes("admin_two_factor") ?? false;
  const enabled = supported && compatibility.mutationAllowed;
  const role = admin.memberships.find((membership) => membership.organization_id === admin.organization_id)?.role;
  const organization = organizations.data?.items.find((item) => item.id === admin.organization_id);
  return (
    <div className="lw-page">
      <PageHeader description="Your profile, password and console sessions. Changes here apply to you only." title="Your account" />
      <div className="lw-body lw-hgrid lw-hgrid--2">
        <Card icon="users" title="Profile">
          <Properties columns={1} items={[
            { label: "Name", value: admin.administrator.display_name ?? "—" },
            { label: "Email", value: admin.administrator.email },
            { label: "Role in this organization", value: role ? ROLE_LABEL[role] : "Unknown" },
            { label: "Organization", value: organization?.display_name ?? admin.organization_id },
            { label: "This session ends", value: admin.expires_at ? sessionEndText(admin.expires_at) : "Not reported" }
          ]} />
          <p className="lw-secondary lw-note">An owner changes names, emails and roles from <Link className="lw-link" search={scopeSearch} to="/administrators">Team › Members</Link>. API tokens are under <Link className="lw-link" search={scopeSearch} to="/api-tokens">Team › API tokens</Link>.</p>
        </Card>
        <PasswordCard enabled={enabled} />
      </div>
      {twoFactorSupported ? <div className="lw-body"><TwoFactorCard enabled={compatibility.mutationAllowed} /></div> : null}
      <div className="lw-body">
        {supported ? <SessionsCard enabled={enabled} /> : <Notice title="Session history needs a newer server.">This server doesn't list your own sessions yet.</Notice>}
      </div>
    </div>
  );
}

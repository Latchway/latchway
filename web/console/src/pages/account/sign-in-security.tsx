import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";

import { disableTwoFactor, passkeysQueryOptions, removePasskey, replaceRecoveryCodes, twoFactorStatusQueryOptions } from "../../api/account";
import type { Passkey } from "../../api/admin";
import { type AdminProblem, adminSignInInfoQueryOptions, problemFromError } from "../../api/auth";
import { passkeysAvailable } from "../../api/webauthn";
import { PasswordInput } from "../../app/auth/auth-fields";
import { AddPasskeyDialog } from "../../app/auth/passkey-setup";
import { RecoveryCodesReveal, TotpSetup } from "../../app/auth/totp-setup";
import { Badge, Button, Card, ConfirmDialog, Field, Notice, Properties } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";

function when(instant: string): string {
  return new Date(instant).toLocaleString(undefined, { day: "numeric", hour: "2-digit", hour12: false, minute: "2-digit", month: "short" });
}

function CodeInput({ id, inputRef }: { id: string; inputRef: React.RefObject<HTMLInputElement | null> }) {
  return (
    <Field id={id} label="Authentication code">
      <div className="lw-input-box"><input autoComplete="one-time-code" className="lw-input lw-input--mono" id={id} inputMode="numeric" maxLength={6} pattern="[0-9]{6}" ref={inputRef} /></div>
    </Field>
  );
}

/** The second step after a password: an authenticator app and passkeys, with recovery codes as the fallback. */
export function TwoFactorCard({ enabled, passkeysSupported }: { enabled: boolean; passkeysSupported: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery(twoFactorStatusQueryOptions);
  const [settingUp, setSettingUp] = useState(false);
  const [dialog, setDialog] = useState<"codes" | "remove-app">();
  const [codes, setCodes] = useState<string[]>();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const code = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const on = status.data?.enabled ?? false;
  const app = status.data?.totp_enabled ?? false;
  const passkeys = status.data?.passkeys ?? 0;
  const required = status.data?.required_by_organization ?? false;
  const appIsLastFactor = required && passkeys === 0;

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
      description={`A second step after your password: a code from an authenticator app${passkeysSupported ? " or one of your passkeys" : ""}. Recovery codes get you in if you lose them.`}
      icon="shield"
      meta={status.data ? <Badge color={on ? "success" : undefined} dot>{on ? "On" : "Off"}</Badge> : undefined}
      title="Two-factor sign-in"
    >
      {status.error ? <ProblemNotice problem={problemFromError(status.error)} /> : null}
      {required && !on ? <Notice tone="warning">This organization requires two-factor sign-in.</Notice> : null}
      {!enabled ? <Notice icon="lock" title="Two-factor changes are unavailable." tone="info">The console is read-only until it can verify the server, or this server predates two-factor sign-in.</Notice> : (
        <div className="lw-stack">
          <Properties columns={1} items={[
            { label: "Authenticator app", value: app ? `On since ${status.data?.totp_enabled_at ? when(status.data.totp_enabled_at) : "—"}` : "Not set up" },
            ...(passkeysSupported ? [{ label: "Passkeys", value: passkeys === 0 ? "None" : `${passkeys} — see Passkeys below` }] : []),
            ...(on ? [{ label: "Recovery codes left", value: `${status.data?.recovery_codes_remaining ?? 0} of 10` }] : [])
          ]} />
          {on && (status.data?.recovery_codes_remaining ?? 10) <= 3 ? <Notice tone="warning">You&apos;re running low on recovery codes. Replace them so you aren&apos;t locked out.</Notice> : null}
          {settingUp ? <TotpSetup autoStart onCancel={() => setSettingUp(false)} onDone={() => setSettingUp(false)} /> : (
            <div className="lw-row lw-row--wrap">
              {app ? null : <Button onClick={() => setSettingUp(true)} size="sm" variant={on ? "secondary" : "primary"}>Set Up Authenticator App</Button>}
              {on ? <Button onClick={() => { setProblem(undefined); setDialog("codes"); }} size="sm">Replace Recovery Codes</Button> : null}
              {app ? <Button destructive disabled={appIsLastFactor} onClick={() => { setProblem(undefined); setDialog("remove-app"); }} size="sm" title={appIsLastFactor ? "Your organization requires two-factor sign-in. Add a passkey first." : undefined} variant="ghost">Remove Authenticator App</Button> : null}
            </div>
          )}
        </div>
      )}
      {dialog === "codes" ? (
        <ConfirmDialog confirmLabel="Replace Codes" description={`Your current recovery codes stop working. ${app ? "Enter a code from your authenticator app" : "Enter your password"} to confirm.`} onCancel={() => setDialog(undefined)} onConfirm={() => void run(async () => { const issued = await replaceRecoveryCodes(app ? { code: code.current } : { password: password.current }); setDialog(undefined); setCodes(issued); })} pending={pending} title="Replace your recovery codes?">
          {app ? <CodeInput id="replace-codes-code" inputRef={code} /> : <PasswordInput id="replace-codes-password" inputRef={password} />}
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
      {dialog === "remove-app" ? (
        <ConfirmDialog confirmLabel="Remove" description={passkeys > 0 ? "Your passkeys stay as your second step." : "Signing in will need only your password. Your recovery codes are deleted."} destructive onCancel={() => setDialog(undefined)} onConfirm={() => void run(async () => { await disableTwoFactor(password.current, code.current); setDialog(undefined); })} pending={pending} title="Remove your authenticator app?">
          <PasswordInput id="disable-two-factor-password" inputRef={password} />
          <CodeInput id="disable-two-factor-code" inputRef={code} />
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
      {codes ? <RecoveryCodesReveal codes={codes} onDone={() => setCodes(undefined)} /> : null}
    </Card>
  );
}

/** The administrator's passkeys: each signs in on its own and also answers the second step after a password. */
export function PasskeysCard({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const info = useQuery(adminSignInInfoQueryOptions);
  const passkeys = useQuery(passkeysQueryOptions);
  const status = useQuery(twoFactorStatusQueryOptions);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Passkey>();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const password = useRef<HTMLInputElement>(null);
  const items = passkeys.data?.items ?? [];
  const serverAccepts = info.data?.sign_in_methods.includes("passkey") ?? false;
  const browserCan = passkeysAvailable();
  const lastFactor = (status.data?.required_by_organization ?? false) && !(status.data?.totp_enabled ?? false) && items.length === 1;

  if (!enabled && (adding || removing)) {
    setAdding(false);
    setRemoving(undefined);
  }

  async function remove(target: Passkey): Promise<void> {
    setPending(true);
    setProblem(undefined);
    try {
      await removePasskey(target.id, password.current);
      setRemoving(undefined);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: passkeysQueryOptions.queryKey }),
        queryClient.invalidateQueries({ queryKey: twoFactorStatusQueryOptions.queryKey })
      ]);
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setPending(false);
    }
  }

  return (
    <Card
      actions={enabled && serverAccepts && browserCan ? <Button icon="plus" onClick={() => setAdding(true)} size="sm">Add Passkey</Button> : undefined}
      description="Sign in with your fingerprint, face or device PIN instead of a password. Each passkey also works as your second step after a password."
      flush
      icon="key"
      title="Passkeys"
    >
      {!info.isPending && !serverAccepts ? <div className="lw-card__body"><Notice title="This server doesn't accept passkeys here." tone="info">Passkeys need the console to be served from a domain name over HTTPS. Ask whoever runs the server to set its public origin to one.</Notice></div> : null}
      {serverAccepts && !browserCan ? <div className="lw-card__body"><Notice title="This browser can't use passkeys." tone="info">Use a current version of Chrome, Edge, Firefox or Safari to add or use one.</Notice></div> : null}
      {passkeys.error ? <div className="lw-card__body"><ProblemNotice problem={problemFromError(passkeys.error)} /></div> : null}
      <div className="lw-table-wrap">
        <table className="lw-table lw-table--dense">
          <thead><tr><th scope="col">Name</th><th scope="col">Added</th><th scope="col">Last used</th><th scope="col">Storage</th><th scope="col"><span className="lw-sr">Actions</span></th></tr></thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>{item.name}</td>
                <td className="lw-num">{when(item.created_at)}</td>
                <td className="lw-num">{item.last_used_at ? when(item.last_used_at) : "Never"}</td>
                <td>{item.synced ? <Badge color="accent">Synced</Badge> : <Badge>This device only</Badge>}</td>
                <td>{enabled ? <Button destructive onClick={() => { setProblem(undefined); setRemoving(item); }} size="sm" variant="ghost">Remove</Button> : null}</td>
              </tr>
            ))}
            {!items.length ? <tr><td colSpan={5}>{passkeys.isPending ? "Loading passkeys…" : "No passkeys yet."}</td></tr> : null}
          </tbody>
        </table>
      </div>
      {adding ? <AddPasskeyDialog onCancel={() => setAdding(false)} onDone={() => setAdding(false)} suggestedName={`Passkey ${items.length + 1}`} /> : null}
      {removing ? (
        <ConfirmDialog confirmDisabled={lastFactor} confirmLabel="Remove" description={lastFactor ? "Your organization requires two-factor sign-in and this is your only second step. Add another passkey or an authenticator app first." : `"${removing.name}" stops working for this account. Remove it from the device or password manager too.`} destructive onCancel={() => setRemoving(undefined)} onConfirm={() => void remove(removing)} pending={pending} title="Remove this passkey?">
          {lastFactor ? null : <PasswordInput id="remove-passkey-password" inputRef={password} />}
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </Card>
  );
}

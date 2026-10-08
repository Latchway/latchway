import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useRef, useState } from "react";

import { confirmTotpEnrollment, startTotpEnrollment, twoFactorStatusQueryOptions } from "../../api/account";
import type { TotpEnrollment } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { QrCode } from "../../components/qr-code";
import { Button, ConfirmDialog, Field } from "../../ui";
import { AuthProblem } from "./auth-fields";

function copy(text: string, done: (state: "copied" | "failed") => void): void {
  const write = navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject(new Error("clipboard unavailable"));
  write.then(() => done("copied"), () => done("failed"));
}

/**
 * Shows recovery codes exactly once. There's no Cancel: the dialog closes only after the operator confirms they saved
 * them, and the codes are dropped from memory when it does.
 */
export function RecoveryCodesReveal({ codes, onDone }: { codes: readonly string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const text = codes.join("\n");
  return (
    <ConfirmDialog confirmDisabled={!saved} confirmLabel="Done" description="Each code signs you in once if you lose your authenticator. They won't be shown again." hideCancel onCancel={onDone} onConfirm={onDone} size="wide" title="Save your recovery codes">
      <ol className="lw-recovery-codes">{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ol>
      <div className="lw-row lw-row--wrap">
        <Button icon="copy" onClick={() => copy(text, setCopied)} size="sm">{copied === "copied" ? "Copied" : "Copy All"}</Button>
        <a className="lw-btn lw-btn--secondary lw-btn--sm" download="latchway-recovery-codes.txt" href={`data:text/plain;charset=utf-8,${encodeURIComponent(text + "\n")}`}>Download</a>
      </div>
      {copied === "failed" ? <p className="lw-note lw-secondary">Copying isn&apos;t available here; select the codes and copy them.</p> : copied === "copied" ? <p className="lw-note lw-secondary">Your clipboard may keep them; paste them somewhere safe, then clear it.</p> : null}
      <label className="lw-check"><input checked={saved} onChange={(event) => setSaved(event.target.checked)} type="checkbox" /><span>I&apos;ve saved these codes somewhere safe.</span></label>
    </ConfirmDialog>
  );
}

/**
 * Sets up an authenticator app: the server's key is shown as a QR code and as text, confirmed with a current code,
 * and answered with one-time recovery codes. The key is held only while this step is open.
 */
export function TotpSetup({ onCancel, onDone }: { onCancel?: () => void; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [enrollment, setEnrollment] = useState<TotpEnrollment>();
  const [codes, setCodes] = useState<string[]>();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const code = useRef<HTMLInputElement>(null);

  async function start(): Promise<void> {
    setPending(true);
    setProblem(undefined);
    try {
      setEnrollment(await startTotpEnrollment());
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setPending(false);
    }
  }

  async function confirm(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setPending(true);
    setProblem(undefined);
    try {
      const issued = await confirmTotpEnrollment(code.current);
      setEnrollment(undefined);
      setCodes(issued);
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setPending(false);
    }
  }

  if (codes) {
    return <RecoveryCodesReveal codes={codes} onDone={() => { setCodes(undefined); void queryClient.invalidateQueries({ queryKey: twoFactorStatusQueryOptions.queryKey }); onDone(); }} />;
  }
  if (!enrollment) {
    return (
      <div className="lw-stack">
        {problem ? <AuthProblem problem={problem} /> : null}
        <div className="lw-row lw-row--wrap">
          <Button loading={pending} onClick={() => void start()} variant="primary">Set Up Authenticator</Button>
          {onCancel ? <Button disabled={pending} onClick={onCancel}>Cancel</Button> : null}
        </div>
      </div>
    );
  }
  return (
    <div className="lw-totp-setup">
      <QrCode label="QR code for your authenticator app" value={enrollment.uri} />
      <form aria-busy={pending} className="lw-stack" onSubmit={(event) => void confirm(event)}>
        <ol className="lw-issue-items">
          <li>Scan the code with an authenticator app such as 1Password, Google Authenticator or Authy.</li>
          <li>Or enter this key by hand: <code className="lw-code-inline lw-totp-key">{enrollment.secret.replace(/(.{4})/g, "$1 ").trim()}</code> <Button icon="copy" onClick={() => copy(enrollment.secret, setCopied)} size="sm" variant="ghost">{copied === "copied" ? "Copied" : "Copy Key"}</Button></li>
          <li>Enter the six-digit code it shows.</li>
        </ol>
        <p className="lw-note lw-secondary">On a phone, <a className="lw-link" href={enrollment.uri}>open the key in your authenticator</a>.</p>
        <Field id="totp-confirm-code" label="Authentication code">
          <div className="lw-input-box"><input autoComplete="one-time-code" autoFocus className="lw-input lw-input--mono" disabled={pending} id="totp-confirm-code" inputMode="numeric" maxLength={6} pattern="[0-9]{6}" ref={code} required /></div>
        </Field>
        {problem ? <AuthProblem problem={problem} /> : null}
        <div className="lw-row lw-row--wrap">
          <Button loading={pending} type="submit" variant="primary">Turn On Two-Factor</Button>
          <Button disabled={pending} onClick={() => { setEnrollment(undefined); onCancel?.(); }}>Cancel</Button>
        </div>
      </form>
    </div>
  );
}

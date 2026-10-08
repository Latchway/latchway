import { type FormEvent, useRef, useState } from "react";

import type { AdminProblem, SecondFactorAnswer, SecondFactorMethod } from "../../api/auth";
import { passkeysAvailable } from "../../api/webauthn";
import { Button, Field } from "../../ui";
import { AuthProblem } from "./auth-fields";

type Mode = "totp" | "passkey" | "recovery";

const SWITCH_LABEL: Readonly<Record<Mode, string>> = {
  passkey: "Use a passkey",
  recovery: "Use a recovery code",
  totp: "Use an authentication code"
};

/** The ways this browser can answer, in the order offered. */
function modesFor(methods: readonly SecondFactorMethod[]): Mode[] {
  const modes: Mode[] = [];
  if (methods.includes("passkey") && passkeysAvailable()) modes.push("passkey");
  if (methods.includes("totp")) modes.push("totp");
  modes.push("recovery");
  return modes;
}

/**
 * The second step of a two-factor sign-in: a passkey, an authenticator code or a recovery code, as the account allows.
 * Codes stay in their input and are read and cleared on submit.
 */
export function SecondFactorForm({ autoFocus = true, idPrefix, methods = ["totp", "recovery_code"], onCancel, onSubmit, pending, problem, submitLabel = "Verify" }: {
  autoFocus?: boolean;
  idPrefix: string;
  methods?: readonly SecondFactorMethod[];
  onCancel?: () => void;
  onSubmit: (answer: SecondFactorAnswer) => void;
  pending: boolean;
  problem?: AdminProblem;
  submitLabel?: string;
}) {
  const modes = modesFor(methods);
  const [mode, setMode] = useState<Mode>(modes[0] ?? "recovery");
  const input = useRef<HTMLInputElement>(null);
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (mode === "passkey") {
      onSubmit({ passkey: true });
      return;
    }
    const value = input.current?.value.trim() ?? "";
    if (input.current) input.current.value = "";
    if (!value) return;
    onSubmit(mode === "recovery" ? { recovery_code: value } : { code: value });
  }
  return (
    <form aria-busy={pending} className="lw-auth__form" onSubmit={submit}>
      {mode === "passkey" ? (
        <p className="lw-auth__fine">Your browser asks for one of the passkeys on this account, then your fingerprint, face or device PIN.</p>
      ) : mode === "recovery" ? (
        <Field hint="Each recovery code works once." id={`${idPrefix}-recovery`} label="Recovery code">
          <div className="lw-input-box"><input autoCapitalize="none" autoComplete="off" autoFocus={autoFocus} className="lw-input lw-input--mono" disabled={pending} id={`${idPrefix}-recovery`} key="recovery" maxLength={64} placeholder="xxxx-xxxx-xxxx" ref={input} spellCheck={false} /></div>
        </Field>
      ) : (
        <Field hint="The six-digit code your authenticator app shows for this server." id={`${idPrefix}-code`} label="Authentication code">
          <div className="lw-input-box"><input autoComplete="one-time-code" autoFocus={autoFocus} className="lw-input lw-input--mono" disabled={pending} id={`${idPrefix}-code`} inputMode="numeric" key="code" maxLength={6} pattern="[0-9]{6}" placeholder="123456" ref={input} /></div>
        </Field>
      )}
      {problem ? <AuthProblem problem={problem} /> : null}
      <Button autoFocus={autoFocus && mode === "passkey"} className="lw-auth__submit" icon={mode === "passkey" ? "key" : undefined} loading={pending} type="submit" variant="primary">{mode === "passkey" ? "Use Your Passkey" : submitLabel}</Button>
      <div className="lw-row lw-row--wrap lw-row--spread">
        <div className="lw-row lw-row--wrap">
          {modes.filter((other) => other !== mode).map((other) => <Button disabled={pending} key={other} onClick={() => setMode(other)} size="sm" variant="ghost">{SWITCH_LABEL[other]}</Button>)}
        </div>
        {onCancel ? <Button disabled={pending} onClick={onCancel} size="sm" variant="ghost">Cancel</Button> : null}
      </div>
    </form>
  );
}

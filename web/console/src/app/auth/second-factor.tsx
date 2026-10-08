import { type FormEvent, useRef, useState } from "react";

import type { AdminProblem } from "../../api/auth";
import { Button, Field } from "../../ui";
import { AuthProblem } from "./auth-fields";

export interface SecondFactorAnswer {
  code?: string;
  recovery_code?: string;
}

/**
 * The authenticator code (or a recovery code) that finishes a two-factor sign-in. Values stay in their input and are
 * read and cleared on submit.
 */
export function SecondFactorForm({ autoFocus = true, idPrefix, onCancel, onSubmit, pending, problem, submitLabel = "Verify" }: {
  autoFocus?: boolean;
  idPrefix: string;
  onCancel?: () => void;
  onSubmit: (answer: SecondFactorAnswer) => void;
  pending: boolean;
  problem?: AdminProblem;
  submitLabel?: string;
}) {
  const [recovery, setRecovery] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const value = input.current?.value.trim() ?? "";
    if (input.current) input.current.value = "";
    if (!value) return;
    onSubmit(recovery ? { recovery_code: value } : { code: value });
  }
  return (
    <form aria-busy={pending} className="lw-auth__form" onSubmit={submit}>
      {recovery ? (
        <Field hint="Each recovery code works once." id={`${idPrefix}-recovery`} label="Recovery code">
          <div className="lw-input-box"><input autoCapitalize="none" autoComplete="off" autoFocus={autoFocus} className="lw-input lw-input--mono" disabled={pending} id={`${idPrefix}-recovery`} key="recovery" maxLength={64} placeholder="xxxx-xxxx-xxxx" ref={input} spellCheck={false} /></div>
        </Field>
      ) : (
        <Field hint="The six-digit code your authenticator app shows for this server." id={`${idPrefix}-code`} label="Authentication code">
          <div className="lw-input-box"><input autoComplete="one-time-code" autoFocus={autoFocus} className="lw-input lw-input--mono" disabled={pending} id={`${idPrefix}-code`} inputMode="numeric" key="code" maxLength={6} pattern="[0-9]{6}" placeholder="123456" ref={input} /></div>
        </Field>
      )}
      {problem ? <AuthProblem problem={problem} /> : null}
      <Button className="lw-auth__submit" loading={pending} type="submit" variant="primary">{submitLabel}</Button>
      <div className="lw-row lw-row--wrap lw-row--spread">
        <Button disabled={pending} onClick={() => setRecovery((current) => !current)} size="sm" variant="ghost">{recovery ? "Use an authentication code" : "Use a recovery code"}</Button>
        {onCancel ? <Button disabled={pending} onClick={onCancel} size="sm" variant="ghost">Cancel</Button> : null}
      </div>
    </form>
  );
}

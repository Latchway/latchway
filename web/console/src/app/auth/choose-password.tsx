import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useRef, useState } from "react";

import { changeOwnPassword } from "../../api/account";
import { type AdminProblem, type AdminSession, problemFromError } from "../../api/auth";
import { consoleSessionQueryOptions } from "../../api/session";
import { PasswordField } from "../../components/password-field";
import { Button } from "../../ui";
import { AuthProblem, PasswordInput } from "./auth-fields";
import { AuthLayout } from "./auth-layout";
import { acceptable, passwordStrength, type Strength } from "./password-strength";
import { StrengthMeter } from "./strength-meter";

/**
 * Shown instead of the console when an owner set this administrator's password: the server allows nothing else until
 * they choose their own.
 */
export function ChoosePasswordScreen({ onSignOut, session }: { onSignOut: () => void; session: AdminSession }) {
  const queryClient = useQueryClient();
  const current = useRef<HTMLInputElement>(null);
  const next = useRef<HTMLInputElement>(null);
  const [strength, setStrength] = useState<Strength>();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!acceptable(passwordStrength(next.current?.value ?? ""))) {
      setProblem({ code: "request_invalid", detail: "Choose a password rated Good or Strong: at least 12 characters with some variety, or a longer passphrase.", retryable: false, status: 0, title: "Choose a stronger password" });
      next.current?.focus();
      return;
    }
    setPending(true);
    setProblem(undefined);
    try {
      await changeOwnPassword(current.current, next.current);
      await queryClient.invalidateQueries({ exact: true, queryKey: consoleSessionQueryOptions.queryKey });
    } catch (error) {
      setProblem(problemFromError(error));
      setStrength(undefined);
      setPending(false);
    }
  }

  return (
    <AuthLayout description={`An owner set a temporary password for ${session.administrator.email}. Choose your own before you continue; your other sessions will be signed out.`} title="Choose your password">
      <form aria-busy={pending} className="lw-auth__form" onSubmit={(event) => void submit(event)}>
        <PasswordInput autoFocus disabled={pending} id="current-password" inputRef={current} label="Temporary password" />
        <PasswordField id="new-password" inputRef={next} label="New password" name="new_password" onValueChange={(value) => setStrength(value ? passwordStrength(value) : undefined)} />
        <StrengthMeter strength={strength} />
        {problem ? <AuthProblem problem={problem} /> : null}
        <Button className="lw-auth__submit" loading={pending} type="submit" variant="primary">{pending ? "Saving…" : "Save Password"}</Button>
      </form>
      <Button className="lw-auth__link" disabled={pending} onClick={onSignOut} size="sm" variant="ghost">Sign out</Button>
    </AuthLayout>
  );
}

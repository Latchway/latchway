import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";

import { addPasskey, passkeysQueryOptions, twoFactorStatusQueryOptions } from "../../api/account";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { ConfirmDialog, Field, Input } from "../../ui";
import { AuthProblem, PasswordInput } from "./auth-fields";
import { RecoveryCodesReveal } from "./totp-setup";

/**
 * Adds a passkey: a name and the password start the browser's prompt. When it's the account's first second factor the
 * server answers with recovery codes, shown once before the dialog closes.
 */
export function AddPasskeyDialog({ onCancel, onDone, suggestedName }: { onCancel: () => void; onDone: () => void; suggestedName: string }) {
  const queryClient = useQueryClient();
  const password = useRef<HTMLInputElement>(null);
  const [name, setName] = useState(suggestedName);
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [codes, setCodes] = useState<string[]>();

  async function finish(): Promise<void> {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: passkeysQueryOptions.queryKey }),
      queryClient.invalidateQueries({ queryKey: twoFactorStatusQueryOptions.queryKey })
    ]);
    onDone();
  }

  async function add(): Promise<void> {
    if (!name.trim()) {
      setProblem({ code: "request_invalid", detail: "Give the passkey a name you'll recognize, like the device it's on.", retryable: false, status: 0, title: "Name the passkey" });
      return;
    }
    setPending(true);
    setProblem(undefined);
    try {
      const added = await addPasskey(password.current, name);
      if (added.recovery_codes) {
        setCodes(added.recovery_codes);
        setPending(false);
        return;
      }
      await finish();
    } catch (error) {
      setProblem(problemFromError(error));
      setPending(false);
    }
  }

  if (codes) return <RecoveryCodesReveal codes={codes} onDone={() => { setCodes(undefined); void finish(); }} />;
  return (
    <ConfirmDialog confirmLabel="Continue" description="Your browser asks where to save the passkey, then for your fingerprint, face or device PIN. A passkey signs you in on its own and also works as your second step after a password." onCancel={onCancel} onConfirm={() => void add()} pending={pending} title="Add a passkey">
      <Field hint="Shown in your list of passkeys, so you can tell them apart." id="passkey-name" label="Name">
        <Input disabled={pending} id="passkey-name" maxLength={64} onChange={(event) => setName(event.target.value)} value={name} />
      </Field>
      <PasswordInput disabled={pending} id="passkey-password" inputRef={password} label="Current password" />
      {problem ? <AuthProblem problem={problem} /> : null}
    </ConfirmDialog>
  );
}

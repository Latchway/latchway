import { type RefObject, useState } from "react";

import { generatePassword } from "../pages/team/roles";
import { Button, Field } from "../ui";

/**
 * A write-only password input. The value lives only in the DOM input: Generate and Copy read and write the element
 * through its ref, so the password never enters React state, storage or the URL. Callers read it on submit and clear
 * the element right after.
 */
export function PasswordField({ hint, id, inputRef, label, name = "password" }: { hint?: string; id: string; inputRef: RefObject<HTMLInputElement | null>; label: string; name?: string }) {
  const [shown, setShown] = useState(false);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  function generate(): void {
    if (!inputRef.current) return;
    inputRef.current.value = generatePassword();
    setShown(true);
    setCopy("idle");
  }
  function copyValue(): void {
    const value = inputRef.current?.value ?? "";
    if (!value) return;
    const write = navigator.clipboard ? navigator.clipboard.writeText(value) : Promise.reject(new Error("clipboard unavailable"));
    write.then(() => setCopy("copied"), () => setCopy("failed"));
  }
  return (
    <Field hint={copy === "copied" ? "Copied. Your clipboard may keep it; share it privately." : copy === "failed" ? "Copying isn't available here; select the password and copy it." : hint} id={id} label={label}>
      <div className="lw-row lw-row--tight lw-password">
        <div className="lw-input-box lw-password__box">
          <input autoComplete="new-password" className="lw-input lw-input--mono" id={id} maxLength={1024} minLength={12} name={name} ref={inputRef} required spellCheck={false} type={shown ? "text" : "password"} />
        </div>
        <Button onClick={generate} size="sm">Generate</Button>
        <Button onClick={() => setShown((current) => !current)} size="sm" variant="ghost">{shown ? "Hide" : "Show"}</Button>
        <Button icon="copy" onClick={copyValue} size="sm" variant="ghost">Copy</Button>
      </div>
    </Field>
  );
}

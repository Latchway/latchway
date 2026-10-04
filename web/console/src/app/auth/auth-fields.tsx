import { type KeyboardEvent, type ReactNode, type RefObject, useId, useRef, useState } from "react";

import type { AdminProblem } from "../../api/auth";
import { Field, Icon, Notice, useFocusTrap } from "../../ui";

/** A request failure as the server described it, with its request ID for support. */
export function AuthProblem({ problem }: { problem: AdminProblem }) {
  return (
    <Notice title={problem.title} tone="danger">
      {problem.detail}
      {problem.requestId ? <> Request <span className="lw-code-inline">{problem.requestId}</span></> : null}
    </Notice>
  );
}

/**
 * A password input whose value stays in the DOM: the Show toggle and the Caps Lock warning are the only state, and
 * callers read the element through its ref on submit.
 */
export function PasswordInput({ autoComplete = "current-password", autoFocus, disabled, id, inputRef, label = "Password" }: { autoComplete?: string; autoFocus?: boolean; disabled?: boolean; id: string; inputRef: RefObject<HTMLInputElement | null>; label?: string }) {
  const [shown, setShown] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  function track(event: KeyboardEvent<HTMLInputElement>): void {
    setCapsLock(event.getModifierState("CapsLock"));
  }
  return <>
    <Field id={id} label={label}>
      <div className="lw-input-box" data-disabled={disabled ? "" : undefined}>
        <input autoComplete={autoComplete} autoFocus={autoFocus} className="lw-input" disabled={disabled} id={id} maxLength={1024} name="password" onBlur={() => setCapsLock(false)} onKeyDown={track} onKeyUp={track} ref={inputRef} required spellCheck={false} type={shown ? "text" : "password"} />
        <button aria-controls={id} aria-label="Show password" aria-pressed={shown} className="lw-pw-toggle" disabled={disabled} onClick={() => setShown((current) => !current)} type="button">{shown ? "Hide" : "Show"}</button>
      </div>
    </Field>
    {capsLock ? <span className="lw-caps" role="status"><Icon name="alert" size={12} />Caps Lock is on</span> : null}
  </>;
}

/** A modal surface for account dialogs. Without `onEscape` it can't be dismissed, e.g. while a session has ended. */
export function AccountDialogFrame({ children, description, onEscape, title }: { children: ReactNode; description?: ReactNode; onEscape?: () => void; title: string }) {
  const surface = useRef<HTMLDivElement>(null);
  const titleID = useId();
  const descriptionID = useId();
  useFocusTrap(surface, onEscape);
  return (
    <div className="lw-overlay">
      <div aria-describedby={description ? descriptionID : undefined} aria-labelledby={titleID} aria-modal="true" className="lw-confirm" ref={surface} role="dialog" tabIndex={-1}>
        <div>
          <h2 className="lw-confirm__title" id={titleID}>{title}</h2>
          {description ? <p className="lw-confirm__desc" id={descriptionID}>{description}</p> : null}
        </div>
        {children}
      </div>
    </div>
  );
}

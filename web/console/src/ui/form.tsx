import type { InputHTMLAttributes, ReactNode } from "react";

import { cx } from "./cx";
import { Icon, type IconName } from "./icon";

interface FieldProps {
  badge?: ReactNode;
  children: ReactNode;
  className?: string;
  error?: ReactNode;
  hint?: ReactNode;
  id: string;
  label?: ReactNode;
}

/** Label, control and one line of help; an error replaces the hint. */
export function Field({ badge, children, className, error, hint, id, label }: FieldProps) {
  return (
    <div className={cx("lw-field", className)}>
      {label ? <label className="lw-field__label" htmlFor={id}>{label}{badge}</label> : null}
      {children}
      {error ? <span className="lw-field__error" id={`${id}-error`}>{error}</span> : hint ? <span className="lw-field__hint" id={`${id}-hint`}>{hint}</span> : null}
    </div>
  );
}

interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "prefix"> {
  boxClassName?: string;
  invalid?: boolean;
  mono?: boolean;
  prefix?: IconName;
  suffix?: ReactNode;
}

export function Input({ boxClassName, className, disabled, invalid, mono, prefix, suffix, ...rest }: InputProps) {
  return (
    <div className={cx("lw-input-box", boxClassName)} data-disabled={disabled ? "" : undefined} data-invalid={invalid ? "" : undefined}>
      {prefix ? <Icon name={prefix} /> : null}
      <input {...rest} aria-invalid={invalid ? true : undefined} className={cx("lw-input", mono && "lw-input--mono", className)} disabled={disabled} />
      {suffix}
    </div>
  );
}

import type { ButtonHTMLAttributes, ReactNode } from "react";

import { buttonClass, type ButtonSize, type ButtonVariant } from "./button-class";
import { Icon, type IconName } from "./icon";

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  children?: ReactNode;
  destructive?: boolean;
  icon?: IconName;
  loading?: boolean;
  rightIcon?: IconName;
  size?: ButtonSize;
  variant?: ButtonVariant;
}

/**
 * Galva button. One primary per view; destructive actions are secondary or ghost until their review, where the
 * confirming action becomes a destructive primary. An icon-only button needs an aria-label.
 */
export function Button({ children, className, destructive, disabled, icon, loading, rightIcon, size = "lg", type = "button", variant = "secondary", ...rest }: ButtonProps) {
  const iconOnly = Boolean(icon) && children == null;
  return (
    <button
      {...rest}
      aria-busy={loading ? true : undefined}
      className={buttonClass({ destructive, iconOnly, lead: Boolean(icon) && !iconOnly && size === "lg" && !loading, loading, size, variant }, className)}
      disabled={disabled || loading}
      type={type}
    >
      {loading ? <Icon name="spinner" size={12} spin /> : icon ? <Icon name={icon} /> : null}
      {children}
      {rightIcon ? <Icon name={rightIcon} size={12} /> : null}
    </button>
  );
}

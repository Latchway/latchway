import { cx } from "./cx";

export type ButtonVariant = "primary" | "secondary" | "ghost";
export type ButtonSize = "lg" | "md" | "sm";

interface ButtonStyleOptions {
  destructive?: boolean;
  iconOnly?: boolean;
  lead?: boolean;
  loading?: boolean;
  size?: ButtonSize;
  variant?: ButtonVariant;
}

/** Galva button classes, for elements that must be a link (router Link) but look like a button. */
export function buttonClass({ destructive, iconOnly, lead, loading, size = "lg", variant = "secondary" }: ButtonStyleOptions = {}, className?: string): string {
  return cx(
    "lw-btn",
    `lw-btn--${variant}`,
    size !== "lg" && `lw-btn--${size}`,
    iconOnly && "lw-btn--icon",
    destructive && "lw-btn--destructive",
    loading && "lw-btn--loading",
    lead && "lw-btn--lead",
    className
  );
}

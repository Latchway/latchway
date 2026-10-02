import type { ReactNode } from "react";

import { cx } from "./cx";
import { Icon, type IconName } from "./icon";

export type BadgeColor = "success" | "danger" | "warning" | "accent" | "violet" | "cyan" | "green" | "red" | "orange";

interface BadgeProps {
  children?: ReactNode;
  className?: string;
  color?: BadgeColor;
  dot?: boolean;
  icon?: IconName;
  title?: string;
  variant?: "ghost" | "soft" | "filled";
}

export function Badge({ children, className, color, dot, icon, title, variant = "ghost" }: BadgeProps) {
  return (
    <span className={cx("lw-badge", variant !== "ghost" && `lw-badge--${variant}`, color && `lw-badge--${color}`, className)} title={title}>
      {dot ? <span aria-hidden="true" className="lw-badge__dot" /> : null}
      {icon ? <Icon name={icon} /> : null}
      {children != null ? <span>{children}</span> : null}
    </span>
  );
}

export type Status =
  | "succeeded" | "failed" | "denied" | "canceled" | "unknown"
  | "active" | "disabled" | "blocked" | "revoked" | "expired"
  | "draft" | "valid" | "invalid" | "superseded" | "published"
  | "available" | "degraded" | "unavailable"
  | "passed" | "running" | "live";

const STATUS: Record<Status, [BadgeColor | undefined, string]> = {
  active: ["success", "Active"], available: ["success", "Available"], blocked: ["danger", "Blocked"], canceled: [undefined, "Canceled"],
  degraded: ["warning", "Degraded"], denied: ["warning", "Denied"], disabled: [undefined, "Disabled"], draft: ["warning", "Draft"],
  expired: [undefined, "Expired"], failed: ["danger", "Failed"], invalid: ["danger", "Invalid"], live: ["accent", "Live"],
  passed: ["success", "Passed"], published: ["accent", "Published"], revoked: ["danger", "Revoked"], running: ["accent", "Running"],
  succeeded: ["success", "Succeeded"], superseded: [undefined, "Superseded"], unavailable: ["danger", "Unavailable"],
  unknown: [undefined, "Unknown"], valid: ["success", "Valid"]
};

/** Status with a colored dot. The dot is decorative; the word carries the meaning. */
export function StatusBadge({ children, className, status }: { children?: ReactNode; className?: string; status: Status }) {
  const [color, label] = STATUS[status];
  return <Badge className={className} color={color} dot>{children ?? label}</Badge>;
}

export type EnvironmentKind = "production" | "staging" | "development";
const ENVIRONMENT: Record<EnvironmentKind, ["filled" | "soft", BadgeColor, string]> = {
  development: ["soft", "violet", "Development"],
  production: ["filled", "warning", "Production"],
  staging: ["soft", "cyan", "Staging"]
};

/** Environment kind in words: Production is filled orange so it's never mistaken for a test environment. */
export function EnvironmentBadge({ children, className, kind }: { children?: ReactNode; className?: string; kind: string }) {
  const [variant, color, label] = ENVIRONMENT[kind as EnvironmentKind] ?? ENVIRONMENT.development;
  return <Badge className={className} color={color} variant={variant}>{children ?? label}</Badge>;
}

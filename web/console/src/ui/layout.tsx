import type { CSSProperties, ReactNode } from "react";

import { cx } from "./cx";
import { Icon, type IconName } from "./icon";

interface CardProps {
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  description?: ReactNode;
  flush?: boolean;
  footer?: ReactNode;
  icon?: IconName;
  meta?: ReactNode;
  style?: CSSProperties;
  title?: ReactNode;
}

export function Card({ actions, children, className, description, flush, footer, icon, meta, style, title }: CardProps) {
  const hasHead = Boolean(title || actions || meta);
  return (
    <section aria-label={typeof title === "string" ? title : undefined} className={cx("lw-card", className)} style={style}>
      {hasHead ? (
        <header className="lw-card__head">
          <div style={{ minWidth: 0 }}>
            <div className="lw-card__title-wrap">
              {icon ? <Icon className="lw-card__icon" name={icon} /> : null}
              {title ? <h2 className="lw-card__title">{title}</h2> : null}
            </div>
            {description ? <p className="lw-card__desc">{description}</p> : null}
          </div>
          {meta || actions ? <div className="lw-card__meta">{meta}{actions}</div> : null}
        </header>
      ) : null}
      {flush ? children : <div className="lw-card__body">{children}</div>}
      {footer ? <div className="lw-card__foot">{footer}</div> : null}
    </section>
  );
}

interface PageHeaderProps {
  actions?: ReactNode;
  badge?: ReactNode;
  className?: string;
  description?: ReactNode;
  /** Section tabs sit under the title and replace the bottom rule. */
  tabs?: ReactNode;
  title: ReactNode;
}

export function PageHeader({ actions, badge, className, description, tabs, title }: PageHeaderProps) {
  return (
    <div className={cx("lw-page-head", !tabs && "lw-page-head--rule", className)}>
      <div className="lw-page-head__top">
        <div className="lw-page-head__text">
          <div className="lw-page-head__title-row"><h1 className="lw-page-head__title">{title}</h1>{badge}</div>
          {description ? <p className="lw-page-head__desc">{description}</p> : null}
        </div>
        {actions ? <div className="lw-page-head__actions">{actions}</div> : null}
      </div>
      {tabs}
    </div>
  );
}

export type NoticeTone = "info" | "warning" | "danger" | "success";
const NOTICE_ICON: Record<NoticeTone, IconName> = { danger: "alert", info: "info", success: "check", warning: "alert" };

interface NoticeProps {
  action?: ReactNode;
  children?: ReactNode;
  className?: string;
  icon?: IconName;
  title?: ReactNode;
  tone?: NoticeTone;
}

/** Inline banner. Danger and warning announce as alerts; info and success as status. */
export function Notice({ action, children, className, icon, title, tone = "info" }: NoticeProps) {
  return (
    <div className={cx("lw-banner", `lw-banner--${tone}`, className)} role={tone === "danger" || tone === "warning" ? "alert" : "status"}>
      <Icon name={icon ?? NOTICE_ICON[tone]} />
      <div className="lw-banner__body">
        {title ? <strong className="lw-banner__title">{title}</strong> : null}
        {children ? <span className="lw-banner__text">{children}</span> : null}
      </div>
      {action ? <div className="lw-banner__action">{action}</div> : null}
    </div>
  );
}

interface EmptyStateProps {
  action?: ReactNode;
  children?: ReactNode;
  className?: string;
  icon?: IconName;
  orientation?: "vertical" | "horizontal";
  title: ReactNode;
}

export function EmptyState({ action, children, className, icon = "search", orientation = "vertical", title }: EmptyStateProps) {
  return (
    <div className={cx("lw-empty", orientation === "horizontal" && "lw-empty--horizontal", className)}>
      <span className="lw-empty__art lw-empty__art--icon"><Icon name={icon} /></span>
      <div className="lw-empty__text">
        <div><p className="lw-empty__title">{title}</p>{children ? <p className="lw-empty__desc">{children}</p> : null}</div>
        {action ? <div className="lw-row">{action}</div> : null}
      </div>
    </div>
  );
}

interface ToastProps {
  className?: string;
  description?: ReactNode;
  title: ReactNode;
  variant?: "success" | "warning" | "error";
}

export function Toast({ className, description, title, variant }: ToastProps) {
  return (
    <div className={cx("lw-toast", variant && `lw-toast--${variant}`, className)} role="status">
      <span className="lw-toast__title">{title}</span>
      {description ? <span className="lw-toast__desc">{description}</span> : null}
    </div>
  );
}

export interface PropertyItem {
  label: ReactNode;
  /** A small on/off dot before the label. */
  state?: "on" | "off";
  value: ReactNode;
}

export function Properties({ columns = 1, items }: { columns?: 1 | 2; items: readonly PropertyItem[] }) {
  return (
    <div className={cx("lw-fields", columns === 2 && "lw-fields--grid")}>
      {items.map((item, index) => (
        <div className="lw-dfield" key={index}>
          <p className="lw-dfield__label">
            {item.state ? <span className="lw-dfield__status" style={{ background: item.state === "on" ? "var(--success)" : "var(--destructive)" }} /> : null}
            {item.label}
          </p>
          <div className="lw-dfield__value">{item.value}</div>
        </div>
      ))}
    </div>
  );
}

export function Toolbar({ children, className, search }: { children?: ReactNode; className?: string; search?: ReactNode }) {
  return <div className={cx("lw-toolbar", className)}><div className="lw-toolbar__filters">{children}</div>{search}</div>;
}

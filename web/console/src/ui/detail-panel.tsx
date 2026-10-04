import { Fragment, type ReactNode } from "react";

import { Button } from "./button";
import { cx } from "./cx";
import { Icon } from "./icon";

export interface DetailSection {
  content: ReactNode;
  title?: ReactNode;
}

interface DetailPanelProps {
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  footer?: ReactNode;
  mono?: boolean;
  onClose?: () => void;
  onCopyLink?: () => void;
  sections?: readonly DetailSection[];
  subtitle?: ReactNode;
  title: ReactNode;
}

/** Right-hand drawer for one record. The list it opened from stays usable beside it. */
export function DetailPanel({ actions, children, className, footer, mono, onClose, onCopyLink, sections = [], subtitle, title }: DetailPanelProps) {
  return (
    <aside aria-label={typeof title === "string" ? title : undefined} className={cx("lw-drawer", className)}>
      <div className="lw-drawer__head">
        <div className="lw-drawer__lead">
          {onClose ? <button aria-label="Close" className="lw-drawer__close" onClick={onClose} type="button"><Icon name="x" /></button> : null}
          <div className="lw-drawer__titles">
            <h2 className={cx("lw-drawer__title", mono && "lw-mono")}>{title}</h2>
            {subtitle ? <div className="lw-drawer__subtitle">{subtitle}</div> : null}
          </div>
        </div>
        {actions || onCopyLink ? (
          <div className="lw-drawer__actions">
            {onCopyLink ? <Button aria-label="Copy link" icon="copy" onClick={onCopyLink} title="Copy link" variant="ghost" /> : null}
            {actions}
          </div>
        ) : null}
      </div>
      <div className="lw-drawer__body">
        {sections.map((section, index) => (
          <Fragment key={index}>
            {index ? <div className="lw-divider" /> : null}
            <section className="lw-dsection">
              {section.title ? <h3 className="lw-dsection__title">{section.title}</h3> : null}
              {section.content}
            </section>
          </Fragment>
        ))}
        {children}
      </div>
      {footer ? <div className="lw-drawer__foot">{footer}</div> : null}
    </aside>
  );
}

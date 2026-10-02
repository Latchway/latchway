import { type ReactNode, useId, useRef, useState } from "react";

import { Button } from "./button";
import { cx } from "./cx";
import { Field, Input } from "./form";
import { Icon } from "./icon";
import { Notice } from "./layout";
import { useFocusTrap } from "./use-focus-trap";

interface ConfirmDialogProps {
  cancelLabel?: string;
  children?: ReactNode;
  confirmDisabled?: boolean;
  confirmLabel?: string;
  description?: ReactNode;
  destructive?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  pending?: boolean;
  size?: "md" | "wide" | "xl";
  title: ReactNode;
}

/**
 * Modal confirmation. Focus is trapped while open and returns to the opener on close; Escape cancels unless a
 * request is pending.
 */
export function ConfirmDialog({ cancelLabel = "Cancel", children, confirmDisabled, confirmLabel = "Confirm", description, destructive, onCancel, onConfirm, pending, size = "md", title }: ConfirmDialogProps) {
  const surface = useRef<HTMLDivElement>(null);
  const titleID = useId();
  const descriptionID = useId();
  useFocusTrap(surface, pending ? undefined : onCancel);
  return (
    <div className="lw-overlay">
      <div
        aria-describedby={description ? descriptionID : undefined}
        aria-labelledby={titleID}
        aria-modal="true"
        className={cx("lw-confirm", size === "wide" && "lw-confirm--wide", size === "xl" && "lw-confirm--xl")}
        ref={surface}
        role="alertdialog"
        tabIndex={-1}
      >
        <div>
          <h2 className="lw-confirm__title" id={titleID}>{title}</h2>
          {description ? <p className="lw-confirm__desc" id={descriptionID}>{description}</p> : null}
        </div>
        {children ? <div className="lw-confirm__body">{children}</div> : null}
        <div className="lw-confirm__foot">
          <Button disabled={pending} onClick={onCancel} size="sm">{cancelLabel}</Button>
          <Button destructive={destructive} disabled={confirmDisabled} loading={pending} onClick={onConfirm} size="sm" variant="primary">{confirmLabel}</Button>
        </div>
      </div>
    </div>
  );
}

export interface Impact {
  /** The count when the dialog opened, shown struck-through when it has since changed. */
  before?: number;
  count: number;
  label: string;
}

interface ImpactDialogProps {
  acknowledgement?: ReactNode;
  children?: ReactNode;
  confirmLabel: string;
  description?: ReactNode;
  facts?: ReadonlyArray<readonly [string, ReactNode]>;
  impacts: readonly Impact[];
  maxReason?: number;
  minReason?: number;
  onCancel: () => void;
  onConfirm: (input: { confirm: string; reason: string }) => void;
  pending?: boolean;
  preserved?: ReactNode;
  scope?: ReactNode;
  /** Set when the impact counts changed after the dialog opened. */
  stale?: ReactNode;
  targetId: string;
  title: ReactNode;
}

/**
 * Destructive confirmation for actions with a wide blast radius: the operator sees counts, types the target's ID,
 * gives a reason (saved to the audit log), and acknowledges the consequence before the action enables.
 */
export function ImpactDialog({ acknowledgement = "I understand this takes effect immediately and revoked credentials are never restored.", children, confirmLabel, description, facts, impacts, maxReason = 500, minReason = 4, onCancel, onConfirm, pending, preserved, scope, stale, targetId, title }: ImpactDialogProps) {
  const reasonID = useId();
  const confirmID = useId();
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const ready = typed === targetId && reason.trim().length >= minReason && reason.length <= maxReason && acknowledged && !stale;
  return (
    <ConfirmDialog
      confirmDisabled={!ready}
      confirmLabel={confirmLabel}
      description={description}
      destructive
      onCancel={onCancel}
      onConfirm={() => onConfirm({ confirm: typed, reason: reason.trim() })}
      pending={pending}
      size="wide"
      title={title}
    >
      {stale ? <Notice title="Counts changed since you opened this" tone="warning">{stale}</Notice> : null}
      {scope ? <div className="lw-impact__scope"><Icon name="domains" size={16} /><span>{scope}</span></div> : null}
      <div className="lw-stack" style={{ gap: 8 }}>
        <div className="lw-impact">
          {impacts.map((impact) => {
            const changed = impact.before != null && impact.before !== impact.count;
            return (
              <div data-changed={changed ? "" : undefined} key={impact.label}>
                <strong>{changed ? <><span className="lw-impact__before">{impact.before} → </span>{impact.count}</> : impact.count}</strong>
                <span>{impact.label}</span>
              </div>
            );
          })}
        </div>
        {preserved ? <p className="lw-impact__keep">Not affected: {preserved}</p> : null}
      </div>
      {facts?.length ? (
        <dl className="lw-impact__facts">
          {facts.map(([term, detail]) => <div key={term}><dt>{term}</dt><dd>{detail}</dd></div>)}
        </dl>
      ) : null}
      {children}
      <Field hint="Saved to the audit log. Don't paste tokens or personal data." id={reasonID} label="Reason">
        <Input autoComplete="off" id={reasonID} maxLength={maxReason} onChange={(event) => setReason(event.target.value)} value={reason} />
      </Field>
      <Field id={confirmID} label={<>Type <code className="lw-code-inline">{targetId}</code> to confirm</>}>
        <Input autoComplete="off" id={confirmID} mono onChange={(event) => setTyped(event.target.value)} spellCheck={false} value={typed} />
      </Field>
      <label className="lw-check">
        <input checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" />
        <span>{acknowledgement}</span>
      </label>
    </ConfirmDialog>
  );
}

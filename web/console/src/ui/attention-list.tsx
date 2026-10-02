import { type ReactNode, useState } from "react";

import { type AttentionItem, type Severity, sortAttention } from "./attention";
import { Button } from "./button";
import { cx } from "./cx";
import { Icon } from "./icon";

const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", info: "Info", warning: "Warning" };

interface AttentionListProps {
  className?: string;
  /** Drops details and uses link-style actions, for popovers. */
  compact?: boolean;
  emptyText?: ReactNode;
  emptyTitle?: ReactNode;
  groups?: ReadonlyArray<{ id: string; label: ReactNode }>;
  items: readonly AttentionItem[];
  limit?: number;
}

/** One list for "is anything wrong?", sorted by severity and capped with "Show all N". */
export function AttentionList({ className, compact, emptyText, emptyTitle = "Nothing needs attention", groups, items, limit }: AttentionListProps) {
  const [showAll, setShowAll] = useState(false);
  const sorted = sortAttention(items);
  const shown = limit && !showAll ? sorted.slice(0, limit) : sorted;

  if (!sorted.length) {
    return (
      <div className="lw-alist__empty">
        <span aria-hidden="true" className="lw-alist__ok"><Icon name="check" size={14} /></span>
        <span><strong>{emptyTitle}</strong>{emptyText ? <span>{emptyText}</span> : null}</span>
      </div>
    );
  }

  const row = (item: AttentionItem) => (
    <li className={cx("lw-alist__item", `is-${item.severity}`, compact && "is-compact")} key={item.id}>
      <span className="lw-alist__sev" title={SEVERITY_LABEL[item.severity]}>
        <Icon name={item.severity === "info" ? "info" : "alert"} size={14} />
        <span className="lw-sr">{SEVERITY_LABEL[item.severity]}: </span>
      </span>
      <span className="lw-alist__text">
        <strong>{item.title}</strong>
        {!compact && item.detail ? <span className="lw-alist__detail">{item.detail}</span> : null}
        {!compact && item.source ? <span className="lw-alist__source">{item.source}</span> : null}
      </span>
      {item.actionLabel ? (compact
        ? <button className="lw-alist__link" onClick={item.onAction} type="button">{item.actionLabel}</button>
        : <Button onClick={item.onAction} size="sm">{item.actionLabel}</Button>) : null}
    </li>
  );

  const body = groups && (!limit || showAll)
    ? groups.map((group) => {
      const groupItems = shown.filter((item) => item.group === group.id);
      if (!groupItems.length) return null;
      return (
        <section className="lw-alist__group" key={group.id}>
          <h3 className="lw-alist__head">{group.label}<span>{groupItems.length}</span></h3>
          <ul className="lw-alist__list">{groupItems.map(row)}</ul>
        </section>
      );
    })
    : <ul className="lw-alist__list">{shown.map(row)}</ul>;

  return (
    <div className={cx("lw-alist", compact && "lw-alist--compact", className)}>
      {body}
      {limit && sorted.length > limit ? (
        <button aria-expanded={showAll} className="lw-alist__more" onClick={() => setShowAll(!showAll)} type="button">
          {showAll ? "Show fewer" : `Show all ${sorted.length}`}
        </button>
      ) : null}
    </div>
  );
}

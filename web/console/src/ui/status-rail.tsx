import { type ReactNode, useState } from "react";

import { cx } from "./cx";
import { Icon, type IconName } from "./icon";

export type StatusTone = "danger" | "warning" | "draft" | "live" | "preview" | "info";

export interface StatusItem {
  actions?: ReactNode;
  /** Short label for the chip when this state is waiting behind another. */
  chip?: string;
  icon?: IconName;
  id: string;
  text?: ReactNode;
  title: string;
  tone: StatusTone;
}

/**
 * One rail under the header in place of stacked bars: the most urgent state shows in full and the rest wait as
 * chips. Choosing a chip brings that state forward. Pass items in priority order.
 */
export function StatusRail({ items, label = "Status" }: { items: readonly StatusItem[]; label?: string }) {
  const [picked, setPicked] = useState<string | null>(null);
  const current = items.find((item) => item.id === picked) ?? items[0];
  if (!current) return null;
  const others = items.filter((item) => item !== current);
  return (
    <div aria-label={label} className={cx("lw-status", `lw-status--${current.tone}`)} role="region">
      <div className="lw-status__main" role="status">
        {current.icon ? <Icon className="lw-status__icon" name={current.icon} size={16} /> : null}
        <span className="lw-status__text"><strong>{current.title}</strong>{current.text ? <> {current.text}</> : null}</span>
        {current.actions ? <span className="lw-status__actions">{current.actions}</span> : null}
      </div>
      {others.length ? (
        <div aria-label="Also active" className="lw-status__chips" role="group">
          {others.map((item) => (
            <button className={cx("lw-status__chip", `is-${item.tone}`)} key={item.id} onClick={() => setPicked(item.id)} title={`Show: ${item.title}`} type="button">
              <span aria-hidden="true" className="lw-status__dot" />
              {item.chip ?? item.title}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

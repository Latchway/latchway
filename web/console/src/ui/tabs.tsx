import type { ReactNode } from "react";

import { Button } from "./button";
import { cx } from "./cx";
import { Icon, type IconName } from "./icon";

export interface TabItem<T extends string> {
  count?: ReactNode;
  icon?: IconName;
  id: T;
  label: ReactNode;
}

/** In-page tabs that switch a view. Section tabs that change the URL use links styled with `lw-tab` instead. */
export function Tabs<T extends string>({ className, items, label, onChange, value }: { className?: string; items: readonly TabItem<T>[]; label?: string; onChange: (id: T) => void; value: T }) {
  return (
    <div aria-label={label} className={cx("lw-tabs", className)} role="tablist">
      {items.map((tab) => (
        <button aria-selected={value === tab.id} className="lw-tab" key={tab.id} onClick={() => onChange(tab.id)} role="tab" type="button">
          {tab.icon ? <Icon name={tab.icon} size={16} /> : null}
          {tab.label}
          {tab.count != null ? <span className="lw-tab__count">{tab.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

export interface SegmentItem<T extends string> {
  id: T;
  label: ReactNode;
}

/** A small set of mutually exclusive options shown as pills. */
export function Segmented<T extends string>({ items, label, onChange, value }: { items: readonly SegmentItem<T>[]; label: string; onChange: (id: T) => void; value: T }) {
  return (
    <div aria-label={label} className="lw-pills" role="group">
      {items.map((item) => (
        <button aria-pressed={value === item.id} className="lw-pill" key={item.id} onClick={() => onChange(item.id)} type="button">{item.label}</button>
      ))}
    </div>
  );
}

interface FilterChipProps {
  emptyLabel?: string;
  label: string;
  onClear?: () => void;
  onClick?: () => void;
  value?: ReactNode;
}

export function FilterChip({ emptyLabel = "Any", label, onClear, onClick, value }: FilterChipProps) {
  const set = value != null && value !== "";
  return (
    <span className="lw-filter">
      <button aria-haspopup="menu" className="lw-filter__trigger" onClick={onClick} type="button">
        <span>{label}: </span>
        <span className={set ? "lw-filter__value" : undefined}>{set ? value : emptyLabel}</span>
        <Icon name="chevronDown" />
      </button>
      {set && onClear ? <Button aria-label={`Remove ${label} filter`} icon="x" onClick={onClear} size="sm" variant="ghost" /> : null}
    </span>
  );
}

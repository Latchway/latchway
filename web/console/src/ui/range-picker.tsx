import { useEffect, useId, useRef, useState } from "react";

import { Button } from "./button";
import { cx } from "./cx";
import { Field, Input } from "./form";
import { Notice } from "./layout";
import { checkCustomRange, DAY_MS, isCustomRange, type RangeValue, rangeText } from "./range";
import { Segmented } from "./tabs";

interface RangePickerProps {
  className?: string;
  /** Days kept by retention, mentioned when a custom range starts before `retainedFrom`. */
  keptDays?: number;
  label?: string;
  /** Enables "Custom…" whole-day ranges of up to this many days. */
  maxDays?: number;
  now?: number;
  onChange: (value: RangeValue) => void;
  /** Preset ids, shown as-is, or `{ id, label }` when the id isn't readable on its own. */
  presets: ReadonlyArray<string | { id: string; label: string }>;
  retainedFrom?: number;
  value: RangeValue;
}

/** One control for every page with a time range: preset pills plus an optional custom whole-day range. */
export function RangePicker({ className, keptDays, label = "Time range", maxDays, now, onChange, presets, retainedFrom, value }: RangePickerProps) {
  // The clock is read when the custom panel opens, never during render.
  const [openedAt, setOpenedAt] = useState<number | null>(null);
  const open = openedAt != null;
  const setOpen = (next: boolean) => setOpenedAt(next ? (now ?? Date.now()) : null);
  const root = useRef<HTMLDivElement>(null);
  const items = presets.map((preset) => (typeof preset === "string" ? { id: preset, label: preset } : preset));
  if (maxDays) items.push({ id: "custom", label: isCustomRange(value) ? rangeText(value) : "Custom…" });

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent): void {
      if (root.current && event.target instanceof Node && !root.current.contains(event.target)) setOpenedAt(null);
    }
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape") setOpenedAt(null);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <div className={cx("lw-range", className)} ref={root}>
      <Segmented
        items={items}
        label={label}
        onChange={(id) => {
          if (id === "custom") {
            setOpen(!open);
            return;
          }
          setOpen(false);
          onChange({ id });
        }}
        value={value.id}
      />
      {openedAt != null && maxDays ? (
        <CustomRange
          keptDays={keptDays}
          maxDays={maxDays}
          now={openedAt}
          onApply={(range) => {
            setOpen(false);
            onChange(range);
          }}
          onCancel={() => setOpen(false)}
          retainedFrom={retainedFrom}
          value={value}
        />
      ) : null}
    </div>
  );
}

interface CustomRangeProps {
  keptDays?: number;
  maxDays: number;
  now: number;
  onApply: (value: RangeValue) => void;
  onCancel: () => void;
  retainedFrom?: number;
  value: RangeValue;
}

const isoDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);

function CustomRange({ keptDays, maxDays, now, onApply, onCancel, retainedFrom, value }: CustomRangeProps) {
  const id = useId();
  const today = Math.floor(now / DAY_MS) * DAY_MS;
  const initial = isCustomRange(value) ? value : { end: today + DAY_MS, start: today - 13 * DAY_MS };
  const [from, setFrom] = useState(isoDay(initial.start));
  const [to, setTo] = useState(isoDay(initial.end - DAY_MS));
  const [tried, setTried] = useState(false);
  const check = checkCustomRange(from, to, maxDays, now);
  const tooLong = Boolean(check.errors.to && check.days > maxDays);
  const clipped = !check.errors.from && retainedFrom != null && check.start < retainedFrom;
  const long: Intl.DateTimeFormatOptions = { day: "numeric", month: "short", timeZone: "UTC", year: "numeric" };

  function apply(): void {
    setTried(true);
    if (!check.errors.from && !check.errors.to) onApply({ end: check.end, id: "custom", start: check.start });
  }

  return (
    <div aria-label="Custom range" className="lw-range__pop" role="dialog">
      <div>
        <strong className="lw-range__title">Custom range</strong>
        <p className="lw-range__hint">Whole days in UTC, both dates included. Up to {maxDays} days.</p>
      </div>
      <div className="lw-range__fields">
        <Field error={tried ? check.errors.from : undefined} id={`${id}-from`} label="From">
          <Input id={`${id}-from`} invalid={tried && Boolean(check.errors.from)} onChange={(event) => setFrom(event.target.value)} type="date" value={from} />
        </Field>
        <Field error={tried || tooLong ? check.errors.to : undefined} id={`${id}-to`} label="To">
          <Input id={`${id}-to`} invalid={(tried || tooLong) && Boolean(check.errors.to)} onChange={(event) => setTo(event.target.value)} type="date" value={to} />
        </Field>
      </div>
      {clipped && retainedFrom != null ? (
        <Notice title="Part of this range was removed" tone="info">
          {keptDays ? `Kept ${keptDays} days. ` : ""}Nothing before {new Date(retainedFrom).toLocaleDateString("en-US", long)} remains.
        </Notice>
      ) : null}
      <div className="lw-range__foot">
        <Button onClick={onCancel} size="sm">Cancel</Button>
        <Button onClick={apply} size="sm" variant="primary">Apply</Button>
      </div>
    </div>
  );
}

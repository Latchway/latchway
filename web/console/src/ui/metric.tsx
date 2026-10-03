import type { ReactNode } from "react";

import { cx } from "./cx";
import { Icon } from "./icon";

export function StatStrip({ children, className, flush }: { children: ReactNode; className?: string; flush?: boolean }) {
  return <div className={cx("lw-stats", flush && "lw-stats--flush", className)}>{children}</div>;
}

interface MetricTileProps {
  className?: string;
  /** Legend color, matching the series this tile totals in a chart. */
  color?: string;
  /** Change against the previous period; omitted when there's nothing to compare. */
  delta?: number;
  deltaUnit?: string;
  footnote?: ReactNode;
  /** Whether a rise is good news. Decides the delta's color, never its sign. */
  higherIsBetter?: boolean;
  label: ReactNode;
  onClick?: () => void;
  unit?: ReactNode;
  value: ReactNode;
}

/** One number with its label, an optional change and a footnote. A zero change shows no arrow. */
export function MetricTile({ className, color, delta, deltaUnit = "%", footnote, higherIsBetter = true, label, onClick, unit, value }: MetricTileProps) {
  const direction = delta === undefined || delta === 0 ? undefined : delta > 0 ? "up" : "down";
  const positive = direction !== undefined && (direction === "up") === higherIsBetter;
  const body = <>
    <span className="lw-stat__label">{color ? <span aria-hidden="true" className="lw-swatch" style={{ background: color }} /> : null}{label}</span>
    <span className="lw-stat__value-row">
      <span className="lw-stat__value">{value}{unit ? <span className="lw-stat__unit">{unit}</span> : null}</span>
      {delta === 0 ? <span className="lw-stat__delta lw-stat__delta--flat">No change</span> : null}
      {direction ? (
        <span className={cx("lw-stat__delta", positive ? "lw-stat__delta--positive" : "lw-stat__delta--negative")}>
          <span className="lw-sr">{direction === "up" ? "Up " : "Down "}</span>
          {Math.abs(delta ?? 0).toLocaleString()}{deltaUnit}
          <Icon name={direction === "up" ? "arrowUp" : "arrowDown"} />
        </span>
      ) : null}
    </span>
    {footnote ? <span className="lw-stat__foot">{footnote}</span> : null}
  </>;
  return onClick
    ? <button className={cx("lw-stat", className)} onClick={onClick} type="button">{body}</button>
    : <div className={cx("lw-stat", className)}>{body}</div>;
}

import { useId } from "react";

import { compactCount, niceScale } from "./chart-scale";

export interface ChartPoint {
  label: string;
  /** Longer label for the tooltip and accessible name, e.g. the full date. */
  title?: string;
  values: Readonly<Record<string, number>>;
}

const SERIES_COLOR: Readonly<Record<string, string>> = {
  canceled: "var(--grey)",
  denied: "var(--orange)",
  failed: "var(--destructive)",
  input: "var(--accent-primary)",
  output: "var(--accent-subtle)",
  recovered: "var(--success)",
  succeeded: "var(--accent-subtle)",
  total: "var(--accent-subtle)"
};

interface VolumeChartProps {
  /** Stacked bar series, bottom first. */
  bars: readonly string[];
  colors?: Readonly<Record<string, string>>;
  dashed?: readonly string[];
  format?: (value: number) => string;
  height?: number;
  label: string;
  labels?: Readonly<Record<string, string>>;
  legendFormat?: (value: number) => string;
  lines?: readonly string[];
  onSelect?: (point: ChartPoint, index: number) => void;
  /** Hatches the last bucket, which is still counting. */
  partialLast?: boolean;
  points: readonly ChartPoint[];
  tickEvery?: number;
}

/** Galva trend chart: soft stacked bars plus optional lines on one scale, with a legend of totals. */
export function VolumeChart({ bars, colors = {}, dashed = [], format = compactCount, height = 300, label, labels = {}, legendFormat = (value) => value.toLocaleString(), lines = [], onSelect, partialLast, points, tickEvery }: VolumeChartProps) {
  const patternID = `lw-hatch-${useId().replace(/[^a-zA-Z0-9]/g, "")}`;
  const color = (key: string, fallback = "var(--accent-subtle)") => colors[key] ?? SERIES_COLOR[key] ?? fallback;
  const width = 960;
  const padLeft = 56;
  const padRight = 16;
  const padTop = 24;
  const padBottom = 32;
  const totals = points.map((point) => bars.reduce((sum, key) => sum + (point.values[key] ?? 0), 0));
  const lineMax = Math.max(0, ...points.flatMap((point) => [...lines, ...dashed].map((key) => point.values[key] ?? 0)));
  const maximum = Math.max(0, lineMax, ...totals);
  // An empty range draws one zero baseline rather than a stack of identical "0" ticks.
  const scale = maximum > 0 ? niceScale(maximum) : { step: 1, ticks: [0], top: 1 };
  const plotWidth = width - padLeft - padRight;
  const plotHeight = height - padTop - padBottom;
  const band = plotWidth / Math.max(points.length, 1);
  const gap = band * 0.09;
  const y = (value: number) => padTop + plotHeight * (1 - value / scale.top);
  const series = [...bars, ...lines, ...dashed];
  const sums = series.map((key) => points.reduce((sum, point) => sum + (point.values[key] ?? 0), 0));
  const path = (key: string) => points.map((point, index) => `${index ? "L" : "M"}${(padLeft + index * band + band / 2).toFixed(1)} ${y(point.values[key] ?? 0).toFixed(1)}`).join(" ");
  const describe = (point: ChartPoint, partial: boolean, separator: string) =>
    `${point.title ?? point.label}${separator === ", " ? ": " : " · "}${bars.map((key) => `${labels[key] ?? key} ${legendFormat(point.values[key] ?? 0)}`).join(separator)}${partial ? (separator === ", " ? " (still counting)" : " · still counting") : ""}`;

  return (
    <figure style={{ margin: 0 }}>
      <svg aria-label={label} className="lw-chart" role={onSelect ? "group" : "img"} viewBox={`0 0 ${width} ${height}`}>
        {partialLast ? (
          <defs>
            <pattern height={6} id={patternID} patternTransform="rotate(45)" patternUnits="userSpaceOnUse" width={6}>
              <rect fill="var(--background-l1)" height={6} width={6} />
              <rect fill={color(bars[0] ?? "")} height={6} width={3} />
            </pattern>
          </defs>
        ) : null}
        {scale.ticks.map((tick) => (
          <g key={tick}>
            <line className="lw-chart__grid" x1={padLeft} x2={width - padRight} y1={y(tick)} y2={y(tick)} />
            <text className="lw-chart__axis" textAnchor="end" x={padLeft - 12} y={y(tick) + 4}>{format(tick)}</text>
          </g>
        ))}
        {points.map((point, index) => {
          const partial = Boolean(partialLast) && index === points.length - 1;
          let stacked = 0;
          return (
            <g className={onSelect ? "lw-chart__col" : undefined} key={index}>
              {bars.map((key) => {
                const value = point.values[key] ?? 0;
                if (!value) return null;
                const bottom = y(stacked);
                stacked += value;
                const top = y(stacked);
                return <rect fill={partial ? `url(#${patternID})` : color(key)} height={Math.max(bottom - top, 0.5)} key={key} width={Math.max(band - gap, 1)} x={padLeft + index * band + gap / 2} y={top} />;
              })}
              {tickEvery && index % tickEvery === 0 ? <text className="lw-chart__axis" textAnchor="middle" x={padLeft + index * band + band / 2} y={height - 10}>{point.label}</text> : null}
              {onSelect ? (
                <rect
                  aria-label={describe(point, partial, ", ")}
                  className="lw-chart__hit"
                  height={plotHeight}
                  onClick={() => onSelect(point, index)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelect(point, index);
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  width={band}
                  x={padLeft + index * band}
                  y={padTop}
                >
                  <title>{describe(point, partial, " · ")}</title>
                </rect>
              ) : null}
            </g>
          );
        })}
        {lines.map((key) => <path d={path(key)} fill="none" key={key} pointerEvents="none" stroke={color(key, "var(--orange)")} strokeLinejoin="round" strokeWidth={2} />)}
        {dashed.map((key) => <path d={path(key)} fill="none" key={key} pointerEvents="none" stroke={color(key, "var(--foreground-secondary)")} strokeDasharray="4 4" strokeLinejoin="round" strokeWidth={1.5} />)}
      </svg>
      <ul className="lw-legend">
        {series.map((key, index) => {
          const isDashed = dashed.includes(key);
          return (
            <li key={key}>
              <span className={isDashed ? "lw-swatch lw-swatch--dashed" : "lw-swatch"} style={{ background: isDashed ? undefined : color(key), borderColor: color(key, "var(--foreground-secondary)") }} />
              {labels[key] ?? key}
              <span className="lw-legend__value">{legendFormat(sums[index] ?? 0)}</span>
            </li>
          );
        })}
        {partialLast ? <li><span className="lw-swatch lw-swatch--hatch" />Still counting</li> : null}
      </ul>
    </figure>
  );
}

export interface ProportionSegment {
  color: string;
  display?: string;
  key?: string;
  label: string;
  value: number;
}

/** A single 100% bar of parts, with a legend. */
export function ProportionBar({ segments, showValues }: { segments: readonly ProportionSegment[]; showValues?: boolean }) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  return (
    <div className="lw-proportion">
      <div aria-label={segments.map((segment) => `${segment.label} ${segment.display ?? segment.value}`).join(", ")} className="lw-proportion__bar" role="img">
        {segments.map((segment) => <div key={segment.key ?? segment.label} style={{ background: segment.color, width: total ? `${(segment.value / total) * 100}%` : "0%" }} />)}
      </div>
      <ul className="lw-legend">
        {segments.map((segment) => (
          <li key={segment.key ?? segment.label}>
            <span className="lw-swatch" style={{ background: segment.color }} />
            {segment.label}
            {showValues ? <span className="lw-legend__value">{segment.display ?? segment.value}</span> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

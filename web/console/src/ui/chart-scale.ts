export interface Scale {
  step: number;
  ticks: number[];
  top: number;
}

/** A 1/2/5 × 10ⁿ axis with about four steps whose top tick is at or above `max`. */
export function niceScale(max: number): Scale {
  const safeMax = Math.max(max, 1e-9);
  const magnitude = 10 ** Math.floor(Math.log10(safeMax / 4));
  const normalized = safeMax / 4 / magnitude;
  const step = (normalized < 1.5 ? 1 : normalized < 3.5 ? 2 : normalized < 7.5 ? 5 : 10) * magnitude;
  const top = Math.ceil(safeMax / step - 1e-9) * step;
  const ticks: number[] = [];
  for (let index = 0; index * step <= top + step / 1e6; index += 1) ticks.push(index * step);
  return { step, ticks, top };
}

/** 1200 → "1.2k", 3000 → "3k", 42 → "42". */
export function compactCount(value: number): string {
  return value >= 1000 ? `${(value / 1000).toFixed(value % 1000 ? 1 : 0)}k` : String(Math.round(value));
}

export const DAY_MS = 86_400_000;

/** A preset like `{ id: "7d" }`, or whole UTC days `[start, end)` in epoch milliseconds. */
export type RangeValue = { id: string } | { end: number; id: "custom"; label?: string; start: number };

export function isCustomRange(value: RangeValue): value is Extract<RangeValue, { id: "custom" }> {
  return value.id === "custom" && "start" in value;
}

/** "7d", or "Mar 3 – Mar 9" for a custom range (inclusive end date, in UTC). */
export function rangeText(value: RangeValue): string {
  if (!isCustomRange(value)) return value.id;
  if (value.label) return value.label;
  const options: Intl.DateTimeFormatOptions = { day: "numeric", month: "short", timeZone: "UTC" };
  const first = new Date(value.start).toLocaleDateString("en-US", options);
  const last = new Date(value.end - DAY_MS).toLocaleDateString("en-US", options);
  return first === last ? first : `${first} – ${last}`;
}

export interface CustomRangeCheck {
  days: number;
  end: number;
  errors: { from?: string; to?: string };
  start: number;
}

/** Validates a From/To pair of `YYYY-MM-DD` dates as whole UTC days, both included, ending today or earlier. */
export function checkCustomRange(from: string, to: string, maxDays: number, now: number): CustomRangeCheck {
  const today = Math.floor(now / DAY_MS) * DAY_MS;
  const start = Date.parse(`${from}T00:00:00Z`);
  const end = Date.parse(`${to}T00:00:00Z`) + DAY_MS;
  const errors: CustomRangeCheck["errors"] = {};
  if (Number.isNaN(start)) errors.from = "Choose a start date.";
  if (Number.isNaN(end)) errors.to = "Choose an end date.";
  else if (end > today + DAY_MS) errors.to = "Choose today or earlier.";
  if (!errors.from && !errors.to && end <= start) errors.to = "End on or after the start date.";
  const days = Math.round((end - start) / DAY_MS);
  if (!errors.from && !errors.to && days > maxDays) errors.to = `Choose at most ${maxDays} days (${days} selected).`;
  return { days, end, errors, start };
}

/** How long before a session ends the console offers to start a new one. */
export const ENDING_SOON_MS = 5 * 60 * 1000;

/** A session end in the operator's local time with its zone, so it can't be misread. */
export function sessionEndText(instant: string): string {
  return new Date(instant).toLocaleString(undefined, { day: "numeric", hour: "2-digit", hour12: false, minute: "2-digit", month: "short", timeZoneName: "short" });
}

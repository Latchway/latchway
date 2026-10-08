import { STRENGTH_TEXT, type Strength } from "./password-strength";

const STRENGTH_BARS: Readonly<Record<Strength, number>> = { good: 2, strong: 3, "too-short": 0, weak: 1 };
const STRENGTH_COLOR: Readonly<Record<Strength, string>> = { good: "var(--success)", strong: "var(--success)", "too-short": "var(--foreground-secondary)", weak: "var(--destructive)" };

export function StrengthMeter({ strength }: { strength?: Strength }) {
  const filled = strength ? STRENGTH_BARS[strength] : 0;
  const color = strength ? STRENGTH_COLOR[strength] : "var(--foreground-secondary)";
  return (
    <div className="lw-strength">
      <div aria-hidden="true" className="lw-strength__bars">
        {[0, 1, 2].map((bar) => <span key={bar} style={{ background: bar < filled ? color : "var(--border)" }} />)}
      </div>
      <span aria-live="polite" className="lw-strength__label" style={{ color }}>{strength ? `Strength: ${STRENGTH_TEXT[strength]}` : "Use at least 12 characters; Good or better is required."}</span>
    </div>
  );
}

/**
 * A local estimate for choosing a password. The server only requires 12 characters; the console also asks for some
 * variety or length so a first owner doesn't pick "aaaaaaaaaaaa".
 */
export type Strength = "too-short" | "weak" | "good" | "strong";

export const STRENGTH_TEXT: Readonly<Record<Strength, string>> = {
  good: "Good",
  strong: "Strong",
  "too-short": "Too short",
  weak: "Weak"
};

export const MINIMUM_PASSWORD_LENGTH = 12;

export function passwordStrength(password: string): Strength {
  if (password.length < MINIMUM_PASSWORD_LENGTH) return "too-short";
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length;
  const distinct = new Set(password).size;
  if (distinct < 6) return "weak";
  if (password.length >= 20 || (password.length >= 16 && classes >= 3)) return "strong";
  if (classes >= 3 || password.length >= 16) return "good";
  return "weak";
}

export function acceptable(strength: Strength): boolean {
  return strength === "good" || strength === "strong";
}

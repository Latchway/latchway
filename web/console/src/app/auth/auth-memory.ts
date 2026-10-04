/**
 * Sign-in facts the console keeps between screens, in memory only: nothing here reaches storage or the URL, and a
 * reload forgets all of it. None of it is secret.
 */

export const wallClock = (): number => Date.now();

function normalizedEmail(email: string): string {
  return email.trim().toLowerCase();
}

let signedOutEmail: string | undefined;

/** Keeps the address of an operator who just signed out so "Sign In Again" can offer it. */
export function rememberSignedOutEmail(email: string | undefined): void {
  signedOutEmail = email;
}

export function lastSignedOutEmail(): string | undefined {
  return signedOutEmail;
}

let pause: { email: string; until: number } | undefined;

/** The server pauses sign-in per email address; this remembers the pause it reported. */
export function pauseSignIn(email: string, seconds: number): void {
  pause = { email: normalizedEmail(email), until: wallClock() + seconds * 1000 };
}

/** When sign-in for this address may resume, or undefined if the server reported no pause for it. */
export function signInPausedUntil(email: string): number | undefined {
  return pause && pause.email === normalizedEmail(email) ? pause.until : undefined;
}

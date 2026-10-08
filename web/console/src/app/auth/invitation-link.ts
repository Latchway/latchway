/**
 * Invitation links look like `/invitation#lwinv_…`. The token sits in the fragment, so it never reaches a server log
 * or a referrer. At startup the console takes it out of the address (and so out of history) and keeps it only in
 * memory until the invitation is accepted, claimed or dismissed.
 */

const TOKEN = /^lwinv_[A-Za-z0-9_-]{43}$/;

export type PendingInvitation = { token: string } | { invalid: true };

let pending: PendingInvitation | undefined;

export function captureInvitationLink(location: Location = window.location, history: History = window.history): void {
  if (location.pathname !== "/invitation") return;
  const token = location.hash.slice(1);
  pending = TOKEN.test(token) ? { token } : { invalid: true };
  history.replaceState(history.state, "", "/");
}

export function pendingInvitation(): PendingInvitation | undefined {
  return pending;
}

export function forgetInvitation(): void {
  pending = undefined;
}

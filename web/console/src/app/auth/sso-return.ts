/**
 * The identity provider's redirect back lands on `/?sso_error=<reason>` when single sign-on fails. The reason is read
 * once at startup and removed from the address so a reload or a shared link doesn't repeat it; the sign-in screen shows
 * the message until a sign-in succeeds.
 */

const MESSAGES: Readonly<Record<string, string>> = {
  conflict: "Your Latchway account is already linked to a different identity at this provider. Ask an owner to check the single sign-on settings.",
  denied: "The sign-in was cancelled or refused at your identity provider.",
  domain: "Your email address isn't in a domain this organization allows for single sign-on.",
  expired: "That single sign-on attempt expired or was finished in another browser. Start it again.",
  failed: "Your identity provider's answer couldn't be verified. Try again, or ask an owner to check the single sign-on settings.",
  no_account: "Your identity provider signed you in, but there's no Latchway account for you in that organization. Ask an owner to add you.",
  unavailable: "Single sign-on isn't available for that organization right now.",
  unverified_email: "Your identity provider didn't confirm your email address, so it couldn't be matched to an account."
};

let pending: string | undefined;

/** Reads and removes the failure reason from the address. Unknown reasons get the generic message. */
export function captureSSOReturn(location: Location = window.location, history: History = window.history): void {
  const params = new URLSearchParams(location.search);
  const reason = params.get("sso_error");
  if (reason === null) return;
  params.delete("sso_error");
  const search = params.toString();
  history.replaceState(history.state, "", `${location.pathname}${search ? `?${search}` : ""}${location.hash}`);
  pending = MESSAGES[reason] ?? MESSAGES.failed;
}

export function ssoReturnMessage(): string | undefined {
  return pending;
}

export function forgetSSOReturn(): void {
  pending = undefined;
}

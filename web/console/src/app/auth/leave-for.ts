/** Sends the whole page to another site, as single sign-on does; kept apart so tests can observe it. */
export function leaveFor(url: string): void {
  window.location.assign(url);
}

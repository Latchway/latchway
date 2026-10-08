import { afterEach, describe, expect, it, vi } from "vitest";

import { captureInvitationLink, forgetInvitation, pendingInvitation } from "./invitation-link";

function at(path: string) {
  const url = new URL(path, "https://console.example.test");
  const history = { replaceState: vi.fn(), state: null } as unknown as History;
  return { history, location: { hash: url.hash, pathname: url.pathname, search: url.search } as Location };
}

const TOKEN = `lwinv_${"a".repeat(43)}`;

describe("invitation links", () => {
  afterEach(() => forgetInvitation());

  it("keeps the token in memory and takes it out of the address", () => {
    const { history, location } = at(`/invitation#${TOKEN}`);
    captureInvitationLink(location, history);
    expect(pendingInvitation()).toEqual({ token: TOKEN });
    expect(history.replaceState).toHaveBeenCalledWith(null, "", "/");
  });

  it("marks a damaged link instead of guessing", () => {
    const { history, location } = at("/invitation#lwinv_short");
    captureInvitationLink(location, history);
    expect(pendingInvitation()).toEqual({ invalid: true });
    expect(history.replaceState).toHaveBeenCalledWith(null, "", "/");
  });

  it("ignores every other address", () => {
    const { history, location } = at(`/members#${TOKEN}`);
    captureInvitationLink(location, history);
    expect(pendingInvitation()).toBeUndefined();
    expect(history.replaceState).not.toHaveBeenCalled();
  });
});

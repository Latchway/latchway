import { afterEach, describe, expect, it, vi } from "vitest";

import { captureSSOReturn, forgetSSOReturn, ssoReturnMessage } from "./sso-return";

function at(path: string) {
  const url = new URL(path, "https://console.example.test");
  const history = { replaceState: vi.fn(), state: { key: "k" } } as unknown as History;
  return { history, location: { hash: url.hash, pathname: url.pathname, search: url.search } as Location };
}

describe("single sign-on return", () => {
  afterEach(() => forgetSSOReturn());

  it("reads the reason once and removes it from the address, keeping everything else", () => {
    const { history, location } = at("/applications?organization=acme&sso_error=no_account#top");
    captureSSOReturn(location, history);
    expect(history.replaceState).toHaveBeenCalledWith({ key: "k" }, "", "/applications?organization=acme#top");
    expect(ssoReturnMessage()).toMatch(/no Latchway account for you/);
    forgetSSOReturn();
    expect(ssoReturnMessage()).toBeUndefined();
  });

  it("gives unknown reasons the generic message and leaves other addresses alone", () => {
    const strange = at("/?sso_error=<script>");
    captureSSOReturn(strange.location, strange.history);
    expect(strange.history.replaceState).toHaveBeenCalledWith({ key: "k" }, "", "/");
    expect(ssoReturnMessage()).toMatch(/couldn't be verified/);
    forgetSSOReturn();
    const plain = at("/settings?tab=general");
    captureSSOReturn(plain.location, plain.history);
    expect(plain.history.replaceState).not.toHaveBeenCalled();
    expect(ssoReturnMessage()).toBeUndefined();
  });
});

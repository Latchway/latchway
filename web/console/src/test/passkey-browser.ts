import { onTestFinished, vi } from "vitest";

/** jsdom has no WebAuthn; these stand in for the browser objects the console checks with instanceof. */
class FakePublicKeyCredential {
  readonly rawId: ArrayBuffer;
  readonly response: unknown;
  readonly type = "public-key";
  constructor(rawId: Uint8Array, response: unknown) {
    this.rawId = rawId.slice().buffer;
    this.response = response;
  }
}

class FakeAttestationResponse {
  readonly attestationObject: ArrayBuffer;
  readonly clientDataJSON: ArrayBuffer;
  constructor(clientDataJSON: string, attestationObject: Uint8Array) {
    this.clientDataJSON = new TextEncoder().encode(clientDataJSON).buffer;
    this.attestationObject = attestationObject.slice().buffer;
  }
  getTransports(): string[] {
    return ["internal"];
  }
}

class FakeAssertionResponse {
  readonly authenticatorData: ArrayBuffer;
  readonly clientDataJSON: ArrayBuffer;
  readonly signature: ArrayBuffer;
  readonly userHandle: ArrayBuffer | null;
  constructor(clientDataJSON: string, authenticatorData: Uint8Array, signature: Uint8Array, userHandle: Uint8Array | null) {
    this.clientDataJSON = new TextEncoder().encode(clientDataJSON).buffer;
    this.authenticatorData = authenticatorData.slice().buffer;
    this.signature = signature.slice().buffer;
    this.userHandle = userHandle ? userHandle.slice().buffer : null;
  }
}

export const fakeCredentialID = new Uint8Array([1, 2, 3, 250, 251, 252]);

export function fakeAttestation(): unknown {
  return new FakePublicKeyCredential(fakeCredentialID, new FakeAttestationResponse('{"type":"webauthn.create"}', new Uint8Array([9, 8, 7])));
}

export function fakeAssertion(userHandle: Uint8Array | null = new Uint8Array([4, 5, 6])): unknown {
  return new FakePublicKeyCredential(fakeCredentialID, new FakeAssertionResponse('{"type":"webauthn.get"}', new Uint8Array([7, 7]), new Uint8Array([48, 1]), userHandle));
}

/** Installs a browser with passkey support for one test; credentials.get and create are the returned mocks. */
export function installPasskeyBrowser() {
  const get = vi.fn<(options: CredentialRequestOptions) => Promise<unknown>>(() => Promise.resolve(fakeAssertion()));
  const create = vi.fn<(options: CredentialCreationOptions) => Promise<unknown>>(() => Promise.resolve(fakeAttestation()));
  vi.stubGlobal("PublicKeyCredential", FakePublicKeyCredential);
  vi.stubGlobal("AuthenticatorAttestationResponse", FakeAttestationResponse);
  vi.stubGlobal("AuthenticatorAssertionResponse", FakeAssertionResponse);
  Object.defineProperty(navigator, "credentials", { configurable: true, value: { create, get } });
  onTestFinished(() => {
    Reflect.deleteProperty(navigator, "credentials");
  });
  return { create, get };
}

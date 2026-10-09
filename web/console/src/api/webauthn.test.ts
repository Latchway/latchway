import { describe, expect, it } from "vitest";

import { installPasskeyBrowser } from "../test/passkey-browser";
import {
  createPasskey,
  decodeBase64URL,
  encodeBase64URL,
  getPasskey,
  type PasskeyCreationOptions,
  PasskeyCreationOptionsSchema,
  PasskeyPromptError,
  type PasskeyRequestOptions,
  PasskeyRequestOptionsSchema,
  passkeysAvailable
} from "./webauthn";

const challenge = encodeBase64URL(new Uint8Array(32).fill(7));

const creation: PasskeyCreationOptions = {
  public_key: {
    attestation: "none",
    authenticatorSelection: { requireResidentKey: true, residentKey: "required", userVerification: "required" },
    challenge,
    excludeCredentials: [{ id: "AQID", type: "public-key" }],
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    rp: { id: "console.example.test", name: "Latchway (console.example.test)" },
    timeout: 300_000,
    user: { displayName: "Owner", id: encodeBase64URL(new Uint8Array(32).fill(3)), name: "owner@example.test" }
  }
};

const request: PasskeyRequestOptions = {
  public_key: { allowCredentials: [], challenge, rpId: "console.example.test", timeout: 300_000, userVerification: "required" }
};

describe("webauthn", () => {
  it("round-trips unpadded base64url, including bytes that need - and _", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const encoded = encodeBase64URL(bytes);
    expect(encoded).toBe("AAEC-vv8_f7_");
    expect(Array.from(decodeBase64URL(encoded))).toEqual(Array.from(bytes));
    expect(Array.from(decodeBase64URL("AQ"))).toEqual([1]);
  });

  it("accepts only the server's exact option shapes", () => {
    expect(PasskeyCreationOptionsSchema.safeParse(creation).success).toBe(true);
    expect(PasskeyRequestOptionsSchema.safeParse(request).success).toBe(true);
    expect(PasskeyCreationOptionsSchema.safeParse({ public_key: { ...creation.public_key, attestation: "direct" } }).success).toBe(false);
    expect(PasskeyRequestOptionsSchema.safeParse({ public_key: { ...request.public_key, userVerification: "preferred" } }).success).toBe(false);
    expect(PasskeyRequestOptionsSchema.safeParse({ public_key: { ...request.public_key, extra: true } }).success).toBe(false);
  });

  it("is unavailable without browser support", async () => {
    expect(passkeysAvailable()).toBe(false);
    await expect(getPasskey(request)).rejects.toEqual(new PasskeyPromptError("unsupported"));
  });

  it("passes binary options to the browser and encodes the registration it returns", async () => {
    const browser = installPasskeyBrowser();
    const registration = await createPasskey(creation);
    const publicKey = browser.create.mock.calls[0]?.[0].publicKey;
    expect(Array.from(new Uint8Array(publicKey?.challenge as ArrayBuffer))).toEqual(Array(32).fill(7));
    expect(Array.from(new Uint8Array(publicKey?.user.id as ArrayBuffer))).toEqual(Array(32).fill(3));
    expect(Array.from(new Uint8Array(publicKey?.excludeCredentials?.[0]?.id as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(publicKey?.authenticatorSelection).toEqual({ requireResidentKey: true, residentKey: "required", userVerification: "required" });
    expect(registration).toEqual({
      clientExtensionResults: {},
      id: "AQID-vv8",
      rawId: "AQID-vv8",
      response: { attestationObject: "CQgH", clientDataJSON: encodeBase64URL(new TextEncoder().encode('{"type":"webauthn.create"}')), transports: ["internal"] },
      type: "public-key"
    });
  });

  it("encodes an assertion with its user handle", async () => {
    installPasskeyBrowser();
    const assertion = await getPasskey(request);
    expect(assertion.response).toEqual({ authenticatorData: "Bwc", clientDataJSON: encodeBase64URL(new TextEncoder().encode('{"type":"webauthn.get"}')), signature: "MAE", userHandle: "BAUG" });
  });

  it("reports a closed or timed-out prompt as cancelled", async () => {
    const browser = installPasskeyBrowser();
    browser.get.mockRejectedValueOnce(new DOMException("The operation either timed out or was not allowed.", "NotAllowedError"));
    await expect(getPasskey(request)).rejects.toEqual(new PasskeyPromptError("cancelled"));
    browser.get.mockResolvedValueOnce(null);
    await expect(getPasskey(request)).rejects.toEqual(new PasskeyPromptError("failed"));
  });
});

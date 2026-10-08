import { z } from "zod";

/**
 * Passkey ceremonies in the browser. The server sends options and accepts responses in the WebAuthn Level 3 JSON
 * encoding (binary values as unpadded base64url); this module converts between that and navigator.credentials.
 */

const Base64URL = z.string().regex(/^[A-Za-z0-9_-]*$/).max(8192);

const DescriptorSchema = z.object({ id: Base64URL, type: z.literal("public-key") }).strict();

export const PasskeyCreationOptionsSchema = z
  .object({
    public_key: z
      .object({
        attestation: z.literal("none"),
        authenticatorSelection: z
          .object({ requireResidentKey: z.literal(true), residentKey: z.literal("required"), userVerification: z.literal("required") })
          .strict(),
        challenge: Base64URL.min(22),
        excludeCredentials: z.array(DescriptorSchema).max(100),
        pubKeyCredParams: z.array(z.object({ alg: z.literal(-7), type: z.literal("public-key") }).strict()).min(1).max(4),
        rp: z.object({ id: z.string().min(1).max(253), name: z.string().min(1).max(300) }).strict(),
        timeout: z.number().int().positive().max(600_000),
        user: z.object({ displayName: z.string().max(320), id: Base64URL.min(1), name: z.string().max(320) }).strict()
      })
      .strict()
  })
  .strict();

export const PasskeyRequestOptionsSchema = z
  .object({
    public_key: z
      .object({
        allowCredentials: z.array(DescriptorSchema).max(100),
        challenge: Base64URL.min(22),
        rpId: z.string().min(1).max(253),
        timeout: z.number().int().positive().max(600_000),
        userVerification: z.literal("required")
      })
      .strict()
  })
  .strict();

export type PasskeyCreationOptions = z.infer<typeof PasskeyCreationOptionsSchema>;
export type PasskeyRequestOptions = z.infer<typeof PasskeyRequestOptionsSchema>;

export interface PasskeyRegistrationJSON {
  clientExtensionResults: Record<string, never>;
  id: string;
  rawId: string;
  response: { attestationObject: string; clientDataJSON: string; transports?: string[] };
  type: "public-key";
}

export interface PasskeyAssertionJSON {
  clientExtensionResults: Record<string, never>;
  id: string;
  rawId: string;
  response: { authenticatorData: string; clientDataJSON: string; signature: string; userHandle?: string };
  type: "public-key";
}

/** Why a passkey prompt produced nothing for the server. */
export class PasskeyPromptError extends Error {
  readonly reason: "cancelled" | "unsupported" | "failed";
  constructor(reason: "cancelled" | "unsupported" | "failed") {
    super(`passkey prompt ${reason}`);
    this.name = "PasskeyPromptError";
    this.reason = reason;
  }
}

export function encodeBase64URL(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64URL(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/** True when this browser can run passkey ceremonies at all; the server separately says whether it accepts them. */
export function passkeysAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && typeof navigator.credentials?.get === "function";
}

function descriptors(items: readonly z.infer<typeof DescriptorSchema>[]): PublicKeyCredentialDescriptor[] {
  return items.map((item) => ({ id: decodeBase64URL(item.id), type: item.type }));
}

function promptError(error: unknown): PasskeyPromptError {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) return new PasskeyPromptError("cancelled");
  if (error instanceof DOMException && (error.name === "NotSupportedError" || error.name === "SecurityError")) return new PasskeyPromptError("unsupported");
  return new PasskeyPromptError("failed");
}

/** Runs navigator.credentials.create() for the server's options and returns the response to send back. */
export async function createPasskey(options: PasskeyCreationOptions, signal?: AbortSignal): Promise<PasskeyRegistrationJSON> {
  if (!passkeysAvailable()) throw new PasskeyPromptError("unsupported");
  const publicKey = options.public_key;
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.create({
      publicKey: {
        attestation: publicKey.attestation,
        authenticatorSelection: publicKey.authenticatorSelection,
        challenge: decodeBase64URL(publicKey.challenge),
        excludeCredentials: descriptors(publicKey.excludeCredentials),
        pubKeyCredParams: publicKey.pubKeyCredParams,
        rp: publicKey.rp,
        timeout: publicKey.timeout,
        user: { displayName: publicKey.user.displayName, id: decodeBase64URL(publicKey.user.id), name: publicKey.user.name }
      },
      signal
    });
  } catch (error) {
    throw promptError(error);
  }
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new PasskeyPromptError("failed");
  const response = credential.response;
  const id = encodeBase64URL(credential.rawId);
  return {
    clientExtensionResults: {},
    id,
    rawId: id,
    response: {
      attestationObject: encodeBase64URL(response.attestationObject),
      clientDataJSON: encodeBase64URL(response.clientDataJSON),
      ...(typeof response.getTransports === "function" ? { transports: response.getTransports() } : {})
    },
    type: "public-key"
  };
}

/** Runs navigator.credentials.get() for the server's options and returns the assertion to send back. */
export async function getPasskey(options: PasskeyRequestOptions, signal?: AbortSignal): Promise<PasskeyAssertionJSON> {
  if (!passkeysAvailable()) throw new PasskeyPromptError("unsupported");
  const publicKey = options.public_key;
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({
      publicKey: {
        allowCredentials: descriptors(publicKey.allowCredentials),
        challenge: decodeBase64URL(publicKey.challenge),
        rpId: publicKey.rpId,
        timeout: publicKey.timeout,
        userVerification: publicKey.userVerification
      },
      signal
    });
  } catch (error) {
    throw promptError(error);
  }
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new PasskeyPromptError("failed");
  const response = credential.response;
  const id = encodeBase64URL(credential.rawId);
  return {
    clientExtensionResults: {},
    id,
    rawId: id,
    response: {
      authenticatorData: encodeBase64URL(response.authenticatorData),
      clientDataJSON: encodeBase64URL(response.clientDataJSON),
      signature: encodeBase64URL(response.signature),
      ...(response.userHandle ? { userHandle: encodeBase64URL(response.userHandle) } : {})
    },
    type: "public-key"
  };
}

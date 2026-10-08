import { queryOptions } from "@tanstack/react-query";

import { z } from "zod";

import {
  AddedPasskeySchema,
  adminRequest,
  AdministratorSchema,
  OwnAdminSessionListSchema,
  PasskeyListSchema,
  SSOConfigurationSchema,
  RecoveryCodesSchema,
  SignedOutSessionsSchema,
  TotpEnrollmentSchema,
  TwoFactorRequirementSchema,
  TwoFactorStatusSchema
} from "./admin";
import { createPasskey, PasskeyCreationOptionsSchema } from "./webauthn";

/** Sends a password change; both values are read from their inputs and cleared whatever happens. */
export async function changeOwnPassword(current: HTMLInputElement | null, next: HTMLInputElement | null): Promise<number> {
  const body = { current_password: current?.value ?? "", new_password: next?.value ?? "" };
  try {
    return (await adminRequest("/admin/v1/auth/password", SignedOutSessionsSchema, { body, method: "POST" })).data.signed_out_sessions;
  } finally {
    if (current) current.value = "";
    if (next) next.value = "";
  }
}

export const ownSessionsQueryOptions = queryOptions({
  queryFn: async ({ signal }) => (await adminRequest("/admin/v1/auth/sessions", OwnAdminSessionListSchema, { signal })).data,
  queryKey: ["account", "sessions"] as const,
  staleTime: 15_000
});

/** Signs out one of your own sessions, or every other one when no ID is given. */
export async function signOutOwnSessions(sessionID?: string): Promise<number> {
  const path = sessionID ? `/admin/v1/auth/sessions/${sessionID}/revoke` : "/admin/v1/auth/sessions/revoke-others";
  return (await adminRequest(path, SignedOutSessionsSchema, { method: "POST" })).data.signed_out_sessions;
}

export const twoFactorStatusQueryOptions = queryOptions({
  queryFn: async ({ signal }) => (await adminRequest("/admin/v1/auth/two-factor", TwoFactorStatusSchema, { signal })).data,
  queryKey: ["account", "two-factor"] as const,
  staleTime: 15_000
});

/** Starts authenticator setup; the key comes back once and is never readable again. */
export async function startTotpEnrollment() {
  return (await adminRequest("/admin/v1/auth/two-factor/totp", TotpEnrollmentSchema, { method: "POST" })).data;
}

/** Reads a code from its input, clears it, and confirms the authenticator; returns the one-time recovery codes. */
export async function confirmTotpEnrollment(code: HTMLInputElement | null): Promise<string[]> {
  const value = code?.value.trim() ?? "";
  if (code) code.value = "";
  return (await adminRequest("/admin/v1/auth/two-factor/totp/confirm", RecoveryCodesSchema, { body: { code: value }, method: "POST" })).data.recovery_codes;
}

/** Replaces every recovery code after checking a current authenticator code or, without an authenticator app, the password. */
export async function replaceRecoveryCodes(proof: { code: HTMLInputElement | null } | { password: HTMLInputElement | null }): Promise<string[]> {
  const input = "code" in proof ? proof.code : proof.password;
  const value = "code" in proof ? (input?.value.trim() ?? "") : (input?.value ?? "");
  if (input) input.value = "";
  const body = "code" in proof ? { code: value } : { password: value };
  return (await adminRequest("/admin/v1/auth/two-factor/recovery-codes", RecoveryCodesSchema, { body, method: "POST" })).data.recovery_codes;
}

export const passkeysQueryOptions = queryOptions({
  queryFn: async ({ signal }) => (await adminRequest("/admin/v1/auth/passkeys", PasskeyListSchema, { signal })).data,
  queryKey: ["account", "passkeys"] as const,
  staleTime: 15_000
});

/**
 * Adds a passkey: the password (read from its input and cleared) starts the browser's prompt, and the prompt's answer
 * registers it. The first second factor also returns one-time recovery codes.
 */
export async function addPasskey(password: HTMLInputElement | null, name: string) {
  const value = password?.value ?? "";
  if (password) password.value = "";
  const options = (await adminRequest("/admin/v1/auth/passkeys/registration-options", PasskeyCreationOptionsSchema, { body: { password: value }, method: "POST" })).data;
  const credential = await createPasskey(options);
  return (await adminRequest("/admin/v1/auth/passkeys", AddedPasskeySchema, { body: { credential, name: name.trim() }, method: "POST" })).data;
}

/** Removes one of your passkeys after checking the password, which is read from its input and cleared. */
export async function removePasskey(passkeyID: string, password: HTMLInputElement | null): Promise<void> {
  const value = password?.value ?? "";
  if (password) password.value = "";
  await adminRequest(`/admin/v1/auth/passkeys/${passkeyID}/remove`, z.undefined(), { body: { password: value }, method: "POST" });
}

/** Removes the authenticator app with the password and a current code, both read from and cleared in their inputs. */
export async function disableTwoFactor(password: HTMLInputElement | null, code: HTMLInputElement | null): Promise<void> {
  const body = { code: code?.value.trim() ?? "", password: password?.value ?? "" };
  try {
    await adminRequest("/admin/v1/auth/two-factor/disable", z.undefined(), { body, method: "POST" });
  } finally {
    if (password) password.value = "";
    if (code) code.value = "";
  }
}

export async function setTwoFactorRequirement(organizationID: string, required: boolean): Promise<boolean> {
  return (await adminRequest(`/admin/v1/organizations/${organizationID}/two-factor-requirement`, TwoFactorRequirementSchema, { body: { required }, method: "PUT" })).data.required;
}

export async function resetMemberTwoFactor(adminUserID: string) {
  return (await adminRequest(`/admin/v1/administrators/${adminUserID}/reset-two-factor`, AdministratorSchema, { method: "POST" })).data;
}

export function ssoConfigurationQueryOptions(organizationID: string) {
  return queryOptions({
    queryFn: async ({ signal }) => (await adminRequest(`/admin/v1/organizations/${organizationID}/sso`, SSOConfigurationSchema, { signal })).data,
    queryKey: ["organization", organizationID, "sso"] as const,
    staleTime: 15_000
  });
}

export interface SSOProviderInput {
  allowed_email_domains: string[];
  client_id: string;
  enabled: boolean;
  issuer: string;
  provision_role: "admin" | "operator" | "viewer" | null;
  require_sso: boolean;
}

/** Saves the identity provider. A client secret, when typed, is read from its input and cleared; blank keeps the stored one. */
export async function saveSSOProvider(organizationID: string, input: SSOProviderInput, secret: HTMLInputElement | null) {
  const value = secret?.value ?? "";
  if (secret) secret.value = "";
  const body = value ? { ...input, client_secret: value } : input;
  return (await adminRequest(`/admin/v1/organizations/${organizationID}/sso`, SSOConfigurationSchema, { body, method: "PUT" })).data;
}

export async function removeSSOProvider(organizationID: string): Promise<void> {
  await adminRequest(`/admin/v1/organizations/${organizationID}/sso`, z.undefined(), { method: "DELETE" });
}

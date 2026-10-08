import { queryOptions } from "@tanstack/react-query";

import { z } from "zod";

import {
  adminRequest,
  AdministratorSchema,
  OwnAdminSessionListSchema,
  RecoveryCodesSchema,
  SignedOutSessionsSchema,
  TotpEnrollmentSchema,
  TwoFactorRequirementSchema,
  TwoFactorStatusSchema
} from "./admin";

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

/** Replaces every recovery code after checking a current authenticator code. */
export async function replaceRecoveryCodes(code: HTMLInputElement | null): Promise<string[]> {
  const value = code?.value.trim() ?? "";
  if (code) code.value = "";
  return (await adminRequest("/admin/v1/auth/two-factor/recovery-codes", RecoveryCodesSchema, { body: { code: value }, method: "POST" })).data.recovery_codes;
}

/** Turns off two-factor sign-in with the password and a current code, both read from and cleared in their inputs. */
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

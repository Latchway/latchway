import { queryOptions } from "@tanstack/react-query";

import { adminRequest, OwnAdminSessionListSchema, SignedOutSessionsSchema } from "./admin";

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

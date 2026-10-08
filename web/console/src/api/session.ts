import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  AdminSessionSchema,
  adminAuthEndpoints,
  responseProblem,
  type AdminSession
} from "./auth";

export const adminSessionEndpoint = adminAuthEndpoints.session;

export type ConsoleMode = "configured" | "signed-out" | "unknown";

export interface ConsoleSessionState {
  /**
   * The session ended while the console was open (it expired, was revoked or the password was reset). The last
   * session stays so the page underneath keeps its context until the operator signs in again.
   */
  expired?: boolean;
  /** The server's explanation when a session it recognised has ended (signed out elsewhere, password changed…). */
  endReason?: string;
  mode: ConsoleMode;
  session?: AdminSession;
  userLabel?: string;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

async function parseJSON(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text.trim()) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export function consoleStateFromAdminSession(
  session: AdminSession
): ConsoleSessionState {
  return rememberConsoleSession({
    mode: "configured",
    session,
    userLabel: session.administrator.email
  });
}

export async function fetchConsoleSession(
  signal?: AbortSignal,
  fetcher: typeof fetch = globalThis.fetch
): Promise<ConsoleSessionState> {
  try {
    const response = await fetcher(adminSessionEndpoint, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      method: "GET",
      redirect: "error",
      referrerPolicy: "same-origin",
      signal
    });
    const payload = await parseJSON(response);

    if (response.ok) {
      const parsed = AdminSessionSchema.safeParse(payload);
      if (!parsed.success) {
        return { mode: "unknown" };
      }
      return consoleStateFromAdminSession(parsed.data);
    }

    if (response.status === 401) {
      const problem = responseProblem(response, payload);
      return problem.code === "session_expired" || problem.code === "session_revoked"
        ? { endReason: problem.detail, mode: "signed-out" }
        : { mode: "signed-out" };
    }
    return { mode: "unknown" };
  } catch (error) {
    if (isAbortError(error)) {
      throw error;
    }
    return { mode: "unknown" };
  }
}

/** The last confirmed session, kept in memory only, so an ending session can be resumed instead of discarded. */
let lastConfigured: ConsoleSessionState | undefined;

/** Called on an explicit sign-out: the next signed-out answer really means "signed out". */
export function forgetConsoleSession(): void {
  lastConfigured = undefined;
}

export function lastConsoleSession(): ConsoleSessionState | undefined {
  return lastConfigured;
}

async function observeConsoleSession(signal?: AbortSignal): Promise<ConsoleSessionState> {
  const state = await fetchConsoleSession(signal);
  if (state.mode === "configured") {
    lastConfigured = state;
    return state;
  }
  if (state.mode === "signed-out" && lastConfigured) return { ...lastConfigured, endReason: state.endReason, expired: true };
  return state;
}

/** Records a session the operator just established, e.g. after sign-in. */
export function rememberConsoleSession(state: ConsoleSessionState): ConsoleSessionState {
  lastConfigured = state.mode === "configured" ? { ...state, endReason: undefined, expired: undefined } : undefined;
  return state;
}

export const SESSION_ENDED_EVENT = "latchway:session-ended";

export const consoleSessionQueryOptions = queryOptions({
  queryKey: ["admin-session"] as const,
  queryFn: ({ signal }) => observeConsoleSession(signal),
  retry: false,
  staleTime: 30_000
});

export function useConsoleSession() {
  const queryClient = useQueryClient();
  const query = useQuery(consoleSessionQueryOptions);
  // QueryState's counter advances for every accepted session observation even
  // when two updates share a timestamp or structurally equal response body.
  // Keeping it in the compatibility key prevents a previous session
  // generation from lending mutation authority to a replacement generation.
  const generation = queryClient.getQueryState(
    consoleSessionQueryOptions.queryKey
  )?.dataUpdateCount ?? 0;
  return { ...query, generation };
}

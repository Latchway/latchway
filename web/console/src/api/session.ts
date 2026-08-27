import { queryOptions, useQuery } from "@tanstack/react-query";

import {
  AdminSessionSchema,
  adminAuthEndpoints,
  type AdminSession
} from "./auth";

export const adminSessionEndpoint = adminAuthEndpoints.session;

export type ConsoleMode = "configured" | "signed-out" | "unknown";

export interface ConsoleSessionState {
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
  return {
    mode: "configured",
    session,
    userLabel: session.administrator.email
  };
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
      return { mode: "signed-out" };
    }
    return { mode: "unknown" };
  } catch (error) {
    if (isAbortError(error)) {
      throw error;
    }
    return { mode: "unknown" };
  }
}

export const consoleSessionQueryOptions = queryOptions({
  queryKey: ["admin-session"] as const,
  queryFn: ({ signal }) => fetchConsoleSession(signal),
  retry: false,
  staleTime: 30_000
});

export function useConsoleSession() {
  return useQuery(consoleSessionQueryOptions);
}

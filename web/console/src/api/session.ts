import { queryOptions, useQuery } from "@tanstack/react-query";
import { z } from "zod";

export const adminSessionEndpoint = "/admin/v1/auth/session";

export type ConsoleMode =
  | "configured"
  | "setup-required"
  | "signed-out"
  | "unknown";

export interface ConsoleSessionState {
  mode: ConsoleMode;
  userLabel?: string;
}

const UserSchema = z
  .object({
    display_name: z.string().optional(),
    email: z.string().optional(),
    name: z.string().optional()
  })
  .passthrough();

const SessionSchema = z
  .object({
    authenticated: z.boolean().optional(),
    setup_required: z.boolean().optional(),
    user: UserSchema.optional()
  })
  .passthrough();

const ProblemSchema = z
  .object({
    setup_required: z.boolean().optional()
  })
  .passthrough();

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
      signal
    });
    const payload = await parseJSON(response);

    if (response.ok) {
      const parsed = SessionSchema.safeParse(payload);
      if (!parsed.success) {
        return { mode: "unknown" };
      }
      if (parsed.data.setup_required) {
        return { mode: "setup-required" };
      }
      const user = parsed.data.user;
      const userLabel = user?.display_name ?? user?.name ?? user?.email;
      return {
        mode: parsed.data.authenticated === false ? "signed-out" : "configured",
        ...(userLabel ? { userLabel } : {})
      };
    }

    const problem = ProblemSchema.safeParse(payload);
    if (problem.success && problem.data.setup_required) {
      return { mode: "setup-required" };
    }
    if (response.status === 401 || response.status === 403) {
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

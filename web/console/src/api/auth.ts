import { z } from "zod";

export const adminAuthEndpoints = {
  bootstrap: "/admin/v1/auth/bootstrap",
  login: "/admin/v1/auth/login",
  logout: "/admin/v1/auth/logout",
  session: "/admin/v1/auth/session"
} as const;

const AdministratorSchema = z
  .object({
    email: z.email().max(320),
    enabled: z.boolean(),
    id: z.string().regex(/^adm_[A-Za-z0-9_-]{16,128}$/)
  })
  .strict();

const MembershipSchema = z
  .object({
    organization_id: z.string().regex(/^org_[A-Za-z0-9_-]{16,128}$/),
    role: z.enum(["owner", "admin", "operator", "viewer"])
  })
  .strict();

export const AdminSessionSchema = z
  .object({
    administrator: AdministratorSchema,
    capabilities: z.array(z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/)),
    expires_at: z.union([z.iso.datetime({ offset: true }), z.null()]),
    memberships: z.array(MembershipSchema),
    organization_id: z.string().regex(/^org_[A-Za-z0-9_-]{16,128}$/)
  })
  .strict();

export type AdminSession = z.infer<typeof AdminSessionSchema>;

export interface BootstrapOwnerInput {
  bootstrap_token: string;
  display_name: string;
  email: string;
  organization_name: string;
  organization_slug: string;
  password: string;
}

export interface AdministratorLoginInput {
  email: string;
  organization_id?: string;
  password: string;
}

export interface AdminProblem {
  code: string;
  detail: string;
  requestId?: string;
  retryable: boolean;
  status: number;
  title: string;
}

const ProblemSchema = z
  .object({
    code: z.string().min(1).max(128),
    detail: z.string().min(1).max(2048),
    request_id: z.string().min(8).max(128),
    retryable: z.boolean(),
    status: z.number().int().min(400).max(599),
    title: z.string().min(1).max(256),
    type: z.url()
  })
  .passthrough();

export class AdminRequestError extends Error {
  readonly problem: AdminProblem;

  constructor(problem: AdminProblem) {
    super(problem.title);
    this.name = "AdminRequestError";
    this.problem = problem;
  }
}

const csrfTokenPattern = /^[A-Za-z0-9._~-]{32,512}$/;
let rememberedCSRFToken: string | undefined;

export function rememberAdminCSRFToken(response: Response): void {
  const token = response.headers.get("X-CSRF-Token")?.trim();
  if (token && csrfTokenPattern.test(token)) {
    rememberedCSRFToken = token;
  }
}

export function adminCSRFToken(): string | undefined {
  if (rememberedCSRFToken) {
    return rememberedCSRFToken;
  }
  if (typeof document === "undefined") {
    return undefined;
  }
  for (const part of document.cookie.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (rawName !== "__Host-latchway_csrf") {
      continue;
    }
    try {
      const token = decodeURIComponent(rawValue.join("=")).trim();
      if (csrfTokenPattern.test(token)) {
        rememberedCSRFToken = token;
        return token;
      }
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function safeText(value: string, limit: number): string {
  return value.trim().replaceAll(/\s+/g, " ").slice(0, limit);
}

export async function parseAdminJSON(
  response: Response,
  maximumBytes = 2 * 1024 * 1024
): Promise<unknown> {
  if (!response.body) {
    return undefined;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maximumBytes) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const encoded = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    encoded.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(encoded);
  } catch {
    return undefined;
  }
  if (!text.trim()) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function fallbackProblem(status: number): AdminProblem {
  if (status === 401) {
    return {
      code: "authentication_required",
      detail: "Check the credentials and try again.",
      retryable: false,
      status,
      title: "Authentication failed"
    };
  }
  if (status === 409) {
    return {
      code: "bootstrap_disabled",
      detail: "This installation may already have an owner. Sign in instead.",
      retryable: false,
      status,
      title: "First-owner setup unavailable"
    };
  }
  if (status === 429) {
    return {
      code: "rate_limited",
      detail: "Wait before trying again.",
      retryable: true,
      status,
      title: "Too many attempts"
    };
  }
  return {
    code: "request_failed",
    detail: "The console could not complete this request.",
    retryable: status >= 500,
    status,
    title: "Request failed"
  };
}

export function responseProblem(response: Response, payload: unknown): AdminProblem {
  const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
  const parsed = contentType.includes("application/problem+json")
    ? ProblemSchema.safeParse(payload)
    : undefined;

  if (!parsed?.success || parsed.data.status !== response.status) {
    return fallbackProblem(response.status);
  }

  return {
    code: safeText(parsed.data.code, 128),
    detail: safeText(parsed.data.detail, 2048),
    requestId: safeText(parsed.data.request_id, 128),
    retryable: parsed.data.retryable,
    status: response.status,
    title: safeText(parsed.data.title, 256)
  };
}

async function submitCredentials(
  endpoint: string,
  input: BootstrapOwnerInput | AdministratorLoginInput,
  signal?: AbortSignal,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminSession> {
  let response: Response;
  try {
    response = await fetcher(endpoint, {
      body: JSON.stringify(input),
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        Accept: "application/json, application/problem+json",
        "Content-Type": "application/json"
      },
      method: "POST",
      redirect: "error",
      referrerPolicy: "same-origin",
      signal
    });
  } catch (error) {
    if (isAbortError(error)) {
      throw error;
    }
    throw new AdminRequestError({
      code: "network_error",
      detail: "The gateway could not be reached. Check system health and try again.",
      retryable: true,
      status: 0,
      title: "Connection failed"
    });
  }

  const payload = await parseAdminJSON(response);
  if (!response.ok) {
    throw new AdminRequestError(responseProblem(response, payload));
  }

  rememberAdminCSRFToken(response);

  const parsed = AdminSessionSchema.safeParse(payload);
  if (!parsed.success) {
    throw new AdminRequestError({
      code: "invalid_response",
      detail: "The gateway returned an invalid administrator session.",
      retryable: true,
      status: response.status,
      title: "Invalid server response"
    });
  }
  return parsed.data;
}

export function bootstrapFirstOwner(
  input: BootstrapOwnerInput,
  signal?: AbortSignal,
  fetcher?: typeof fetch
): Promise<AdminSession> {
  return submitCredentials(adminAuthEndpoints.bootstrap, input, signal, fetcher);
}

export function loginAdministrator(
  input: AdministratorLoginInput,
  signal?: AbortSignal,
  fetcher?: typeof fetch
): Promise<AdminSession> {
  return submitCredentials(adminAuthEndpoints.login, input, signal, fetcher);
}

export async function logoutAdministrator(
  signal?: AbortSignal,
  fetcher: typeof fetch = globalThis.fetch
): Promise<void> {
  const csrf = adminCSRFToken();
  if (!csrf) {
    throw new AdminRequestError({
      code: "csrf_token_required",
      detail: "Refresh the administrator session before signing out.",
      retryable: true,
      status: 0,
      title: "Session confirmation required"
    });
  }
  const response = await fetcher(adminAuthEndpoints.logout, {
    cache: "no-store",
    credentials: "same-origin",
    headers: {
      Accept: "application/json, application/problem+json",
      "X-CSRF-Token": csrf
    },
    method: "POST",
    redirect: "error",
    referrerPolicy: "same-origin",
    signal
  });
  if (response.status !== 204) {
    const payload = await parseAdminJSON(response);
    throw new AdminRequestError(responseProblem(response, payload));
  }
  rememberedCSRFToken = undefined;
}

export function problemFromError(error: unknown): AdminProblem {
  if (error instanceof AdminRequestError) {
    return error.problem;
  }
  return {
    code: "request_failed",
    detail: "The console could not complete this request.",
    retryable: false,
    status: 0,
    title: "Request failed"
  };
}

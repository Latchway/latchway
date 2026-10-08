import { queryOptions } from "@tanstack/react-query";
import { z } from "zod";

import { getPasskey, type PasskeyAssertionJSON, PasskeyPromptError, PasskeyRequestOptionsSchema } from "./webauthn";

export const adminAuthEndpoints = {
  bootstrap: "/admin/v1/auth/bootstrap",
  info: "/admin/v1/auth/info",
  login: "/admin/v1/auth/login",
  secondFactor: "/admin/v1/auth/login/two-factor",
  logout: "/admin/v1/auth/logout",
  organization: "/admin/v1/auth/organization",
  passkeySecondFactorOptions: "/admin/v1/auth/login/two-factor/passkey-options",
  passkeySignIn: "/admin/v1/auth/passkeys/sign-in",
  passkeySignInOptions: "/admin/v1/auth/passkeys/sign-in-options",
  session: "/admin/v1/auth/session"
} as const;

const AdministratorSchema = z
  .object({
    display_name: z.string().min(1).max(200).optional(),
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
    organization_id: z.string().regex(/^org_[A-Za-z0-9_-]{16,128}$/),
    /** An owner set the password; only the password change, sign-out and session read work until it changes. */
    password_reset_required: z.boolean().optional(),
    /** The organization requires a second factor this administrator hasn't set up; only enrollment works. */
    two_factor_enrollment_required: z.boolean().optional()
  })
  .strict();

export const AdminSignInInfoSchema = z
  .object({
    contract_version: z.string().max(64),
    protocol_versions: z.array(z.number().int().min(1)).max(16),
    setup_open: z.boolean(),
    sign_in_methods: z.array(z.enum(["password", "passkey"])).max(8)
  })
  .strict();

export type AdminSignInInfo = z.infer<typeof AdminSignInInfoSchema>;

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
  documentationURL?: string;
  operationId?: string;
  requestId?: string;
  /** Seconds until a rate-limited request may be retried, from the Retry-After header. */
  retryAfterSeconds?: number;
  retryable: boolean;
  status: number;
  title: string;
}

const ProblemSchema = z
  .object({
    code: z.string().regex(/^[a-z][a-z0-9_]{0,127}$/),
    detail: z.string().min(1).max(2048),
    documentation_url: z.url(),
    operation_id: z.string().regex(/^arq_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$/).optional(),
    request_id: z.string().min(8).max(128),
    retryable: z.boolean(),
    status: z.number().int().min(400).max(599),
    title: z.string().min(1).max(256),
    type: z.url()
  })
  .passthrough()
  .superRefine((problem, context) => {
    const expected = `https://docs.latchway.dev/errors/${problem.code.replaceAll("_", "-")}`;
    if (problem.type !== expected || problem.documentation_url !== expected) {
      context.addIssue({
        code: "custom",
        message: "Problem documentation URLs must match the canonical error code."
      });
    }
    if (problem.code === "operation_indeterminate" && !problem.operation_id) {
      context.addIssue({
        code: "custom",
        message: "Indeterminate operations must include their canonical correlation ID.",
        path: ["operation_id"]
      });
    }
    if (problem.code !== "operation_indeterminate" && problem.operation_id) {
      context.addIssue({
        code: "custom",
        message: "Only indeterminate operations may include a correlation ID.",
        path: ["operation_id"]
      });
    }
  });

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

function invalidStructuredProblem(status: number): AdminProblem {
  return {
    code: "request_failed",
    detail: "The console could not complete this request.",
    documentationURL: undefined,
    retryable: false,
    status,
    title: "Request failed"
  };
}

export function responseProblem(response: Response, payload: unknown): AdminProblem {
  const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
  const isStructuredProblem = contentType.includes("application/problem+json");
  const parsed = isStructuredProblem
    ? ProblemSchema.safeParse(payload)
    : undefined;

  if (!parsed?.success || parsed.data.status !== response.status) {
    if (isStructuredProblem) {
      return invalidStructuredProblem(response.status);
    }
    return fallbackProblem(response.status);
  }

  const retryAfter = Number(response.headers.get("Retry-After"));
  return {
    ...(Number.isSafeInteger(retryAfter) && retryAfter > 0 && retryAfter <= 86_400 ? { retryAfterSeconds: retryAfter } : {}),
    code: safeText(parsed.data.code, 128),
    detail: safeText(parsed.data.detail, 2048),
    documentationURL: parsed.data.documentation_url,
    ...(parsed.data.operation_id ? { operationId: parsed.data.operation_id } : {}),
    requestId: safeText(parsed.data.request_id, 128),
    retryable: parsed.data.retryable,
    status: response.status,
    title: safeText(parsed.data.title, 256)
  };
}

export const SecondFactorChallengeSchema = z
  .object({
    challenge: z.string().regex(/^lwsic_[A-Za-z0-9_-]{43}$/),
    expires_at: z.iso.datetime({ offset: true }),
    methods: z.array(z.enum(["totp", "passkey", "recovery_code"])).min(1).max(4),
    status: z.literal("two_factor_required")
  })
  .strict();

export type SecondFactorChallenge = z.infer<typeof SecondFactorChallengeSchema>;

/** A password sign-in either opens a session or, with two-factor on, asks for the second factor. */
export type SignInResult = { kind: "session"; session: AdminSession } | { challenge: SecondFactorChallenge; kind: "challenge" };

export interface SecondFactorInput {
  challenge: string;
  code?: string;
  passkey?: PasskeyAssertionJSON;
  recovery_code?: string;
}

function invalidSession(status: number): AdminRequestError {
  return new AdminRequestError({
    code: "invalid_response",
    detail: "The gateway returned an invalid administrator session.",
    retryable: true,
    status,
    title: "Invalid server response"
  });
}

async function postCredentials(
  endpoint: string,
  input: object,
  signal?: AbortSignal,
  fetcher: typeof fetch = globalThis.fetch
): Promise<{ payload: unknown; response: Response }> {
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
  return { payload, response };
}

function sessionFrom(response: Response, payload: unknown): AdminSession {
  rememberAdminCSRFToken(response);
  const parsed = AdminSessionSchema.safeParse(payload);
  if (!parsed.success) throw invalidSession(response.status);
  return parsed.data;
}

async function submitCredentials(
  endpoint: string,
  input: object,
  signal?: AbortSignal,
  fetcher: typeof fetch = globalThis.fetch
): Promise<AdminSession> {
  const { payload, response } = await postCredentials(endpoint, input, signal, fetcher);
  if (response.status === 202) throw invalidSession(response.status);
  return sessionFrom(response, payload);
}

/** Signs in with a password; a 202 means the account has two-factor on and the challenge finishes the sign-in. */
export async function startAdministratorSignIn(input: AdministratorLoginInput, signal?: AbortSignal, fetcher?: typeof fetch): Promise<SignInResult> {
  const { payload, response } = await postCredentials(adminAuthEndpoints.login, input, signal, fetcher);
  if (response.status === 202) {
    const parsed = SecondFactorChallengeSchema.safeParse(payload);
    if (!parsed.success) throw invalidSession(response.status);
    return { challenge: parsed.data, kind: "challenge" };
  }
  return { kind: "session", session: sessionFrom(response, payload) };
}

/** Finishes a two-factor sign-in with an authenticator code, a passkey assertion or a recovery code. */
export function completeSecondFactor(input: SecondFactorInput, signal?: AbortSignal, fetcher?: typeof fetch): Promise<AdminSession> {
  return submitCredentials(adminAuthEndpoints.secondFactor, input, signal, fetcher);
}

async function passkeyPrompt(endpoint: string, input: object, signal?: AbortSignal, fetcher?: typeof fetch): Promise<PasskeyAssertionJSON> {
  const { payload, response } = await postCredentials(endpoint, input, signal, fetcher);
  const options = PasskeyRequestOptionsSchema.safeParse(payload);
  if (!options.success) {
    throw new AdminRequestError({ code: "invalid_response", detail: "The gateway returned invalid passkey options.", retryable: true, status: response.status, title: "Invalid server response" });
  }
  return getPasskey(options.data, signal);
}

/** Finishes a two-factor sign-in with one of the account's passkeys. */
export async function completeSecondFactorWithPasskey(challenge: string, signal?: AbortSignal, fetcher?: typeof fetch): Promise<AdminSession> {
  const passkey = await passkeyPrompt(adminAuthEndpoints.passkeySecondFactorOptions, { challenge }, signal, fetcher);
  return completeSecondFactor({ challenge, passkey }, signal, fetcher);
}

export type SecondFactorMethod = SecondFactorChallenge["methods"][number];

/** How the operator answered the second-factor step; a passkey answer runs the browser prompt when sent. */
export type SecondFactorAnswer = { code: string } | { recovery_code: string } | { passkey: true };

export function finishSecondFactor(challenge: string, answer: SecondFactorAnswer, signal?: AbortSignal): Promise<AdminSession> {
  return "passkey" in answer ? completeSecondFactorWithPasskey(challenge, signal) : completeSecondFactor({ challenge, ...answer }, signal);
}

/** Signs in with a passkey alone; the browser offers this site's passkeys. */
export async function signInWithPasskey(signal?: AbortSignal, fetcher?: typeof fetch): Promise<AdminSession> {
  const credential = await passkeyPrompt(adminAuthEndpoints.passkeySignInOptions, {}, signal, fetcher);
  return submitCredentials(adminAuthEndpoints.passkeySignIn, { credential }, signal, fetcher);
}

/**
 * What the sign-in screen needs before anyone signs in: the server's advertised contract and whether first-owner
 * setup is still open. Returns undefined when the server predates this endpoint or can't answer.
 */
export async function fetchAdminSignInInfo(signal?: AbortSignal, fetcher: typeof fetch = globalThis.fetch): Promise<AdminSignInInfo | undefined> {
  try {
    const response = await fetcher(adminAuthEndpoints.info, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      method: "GET",
      redirect: "error",
      referrerPolicy: "same-origin",
      signal
    });
    if (!response.ok) return undefined;
    const parsed = AdminSignInInfoSchema.safeParse(await parseAdminJSON(response));
    return parsed.success ? parsed.data : undefined;
  } catch (error) {
    if (isAbortError(error)) throw error;
    return undefined;
  }
}

/** The sign-in information as a query; null when the server can't say, since queries can't hold undefined. */
export const adminSignInInfoQueryOptions = queryOptions({
  queryFn: async ({ signal }) => (await fetchAdminSignInInfo(signal)) ?? null,
  queryKey: ["admin-sign-in-info"] as const,
  retry: false,
  staleTime: 60_000
});

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

/**
 * Replaces the signed-in console session with one for another organization the administrator belongs to. The server
 * revokes the old session in the same step, so no password is needed.
 */
export async function switchAdminOrganization(organizationID: string, signal?: AbortSignal, fetcher: typeof fetch = globalThis.fetch): Promise<AdminSession> {
  const csrf = adminCSRFToken();
  if (!csrf) {
    throw new AdminRequestError({ code: "csrf_token_required", detail: "Refresh the administrator session before switching organization.", retryable: true, status: 0, title: "Session confirmation required" });
  }
  let response: Response;
  try {
    response = await fetcher(adminAuthEndpoints.organization, {
      body: JSON.stringify({ organization_id: organizationID }),
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json, application/problem+json", "Content-Type": "application/json", "X-CSRF-Token": csrf },
      method: "POST",
      redirect: "error",
      referrerPolicy: "same-origin",
      signal
    });
  } catch (error) {
    if (isAbortError(error)) throw error;
    throw new AdminRequestError({ code: "network_error", detail: "The gateway could not be reached. Check system health and try again.", retryable: true, status: 0, title: "Connection failed" });
  }
  const payload = await parseAdminJSON(response);
  if (!response.ok) throw new AdminRequestError(responseProblem(response, payload));
  rememberAdminCSRFToken(response);
  const parsed = AdminSessionSchema.safeParse(payload);
  if (!parsed.success) {
    throw new AdminRequestError({ code: "invalid_response", detail: "The gateway returned an invalid administrator session.", retryable: true, status: response.status, title: "Invalid server response" });
  }
  return parsed.data;
}

const PASSKEY_PROMPT_PROBLEMS: Readonly<Record<PasskeyPromptError["reason"], AdminProblem>> = {
  cancelled: { code: "passkey_cancelled", detail: "The passkey prompt was closed or timed out. Try again when you're ready.", retryable: true, status: 0, title: "Passkey not used" },
  failed: { code: "passkey_failed", detail: "The browser couldn't complete the passkey prompt. Try again, or use another way to sign in.", retryable: true, status: 0, title: "Passkey didn't work" },
  unsupported: { code: "passkey_unsupported", detail: "This browser or device can't use passkeys for this site.", retryable: false, status: 0, title: "Passkeys unavailable" }
};

export function problemFromError(error: unknown): AdminProblem {
  if (error instanceof AdminRequestError) {
    return error.problem;
  }
  if (error instanceof PasskeyPromptError) {
    return PASSKEY_PROMPT_PROBLEMS[error.reason];
  }
  return {
    code: "request_failed",
    detail: "The console could not complete this request.",
    retryable: false,
    status: 0,
    title: "Request failed"
  };
}

import type { z } from "zod";

import type { LogicalRequest, UsageValuesSchema } from "../../api/admin";
import type { Status } from "../../ui";

type Usage = z.infer<typeof UsageValuesSchema>;
type Attempt = LogicalRequest["attempts"][number];
type Stage = LogicalRequest["decision_stages"][number];
export type ProviderErrorCategory = NonNullable<NonNullable<Attempt["provider_error"]>["category"]>;

export const PLATFORM_LABEL: Readonly<Record<string, string>> = {
  android: "Android",
  ios: "iOS",
  node: "Node.js",
  react_native_android: "React Native Android",
  react_native_ios: "React Native iOS",
  web: "Web"
};

export const TRUST_LABEL: Readonly<Record<string, string>> = {
  debug: "Debug",
  delegated_direct_attested: "Delegated, direct attested",
  delegated_from_attested_root: "Delegated from attested root",
  delegated_identity_only: "Delegated, identity only",
  direct_attested: "Direct attested",
  identity_only: "Identity only",
  web_risk_verified: "Web risk verified"
};

/** The server's decision stages, in words, in the order it records them. */
export const STAGE_LABEL: Readonly<Record<Stage["stage"], string>> = {
  client_context_validated: "Client checked",
  client_trust_verified: "App verified",
  configuration_loaded: "Configuration loaded",
  identity_verified: "Signed in",
  lifecycle_recovered: "Recovered after restart",
  policy_evaluated: "Access checked",
  quota_reserved: "Quota reserved",
  quota_rule_evaluated: "Limit checked",
  request_inspected: "Request inspected",
  route_selected: "Route selected"
};

/**
 * Plain-language outcomes for the registered problem codes a logical request can end with (api/error-codes.yaml) and
 * the closed public failure values. Codes without a sentence fall back to the code itself and its documentation.
 */
export const OUTCOME_TEXT: Readonly<Record<string, string>> = {
  attestation_invalid: "App verification didn't vouch for the app, so the request was refused.",
  attestation_required: "The app didn't present the app verification this feature requires.",
  attestation_stale: "The app's verification had expired, so the request was refused.",
  attestation_step_up_required: "The feature needs stronger app verification than the app presented.",
  canceled: "The app canceled it before it finished.",
  component_feature_not_granted: "This app component isn't allowed to call the feature.",
  component_revoked: "The calling app component was revoked.",
  concurrency_exceeded: "A concurrency limit refused it: the user already had the most requests running at once.",
  feature_not_allowed: "The feature's access rule doesn't include this user.",
  feature_not_found: "The feature doesn't exist in the revision that was live.",
  identity_reauthentication_required: "The user had to sign in again.",
  installation_family_revoked: "The installation family was revoked.",
  installation_revoked: "The installation was revoked.",
  internal_error: "Latchway hit an internal error.",
  model_not_allowed: "The feature doesn't allow the requested model.",
  output_limit_exceeded: "The request asked for more output than the feature allows.",
  pricing_unavailable: "No price was configured for the model, so the request couldn't be costed.",
  quota_exceeded: "A limit refused it: the user had reached a limit in their plan.",
  request_invalid: "The request didn't pass validation.",
  route_not_found: "No route in the feature matched the request.",
  session_expired: "The app's session had expired.",
  session_revoked: "The app's session was revoked.",
  unknown: "Latchway couldn't classify the failure.",
  upstream_protocol_error: "The provider's response didn't follow its protocol.",
  upstream_rejected: "The provider refused the request.",
  upstream_timeout: "Every AI connection the route allowed timed out.",
  upstream_unavailable: "No AI connection the route allowed was available."
};

/** Codes offered in the Error filter: request outcomes plus the provider categories attempts record. */
export const ERROR_FILTER_SUGGESTIONS: readonly string[] = [
  ...Object.keys(OUTCOME_TEXT).filter((code) => code !== "canceled"),
  "rate_limit_exceeded",
  "context_length_exceeded",
  "provider_overloaded",
  "timeout"
];

export const ATTEMPT_FAILURE_TEXT: Readonly<Record<string, string>> = {
  canceled: "Canceled",
  gateway_error: "Gateway error",
  protocol_error: "Protocol error",
  timeout: "Timed out",
  unavailable: "Unavailable",
  unknown: "Unknown",
  upstream_rejected: "Rejected by the provider"
};

export const PROVIDER_ERROR_TEXT: Readonly<Record<ProviderErrorCategory, string>> = {
  authentication: "The provider didn't accept the connection's credentials.",
  content_policy_violation: "The provider's content policy refused the request.",
  context_length_exceeded: "The prompt was longer than the model's context window.",
  image_download_failed: "The provider couldn't download an image.",
  image_not_found: "An image the request referenced wasn't found.",
  image_too_large: "An image was larger than the provider allows.",
  image_too_small: "An image was smaller than the provider allows.",
  invalid_image: "The provider couldn't read an image.",
  invalid_prompt: "The provider said the prompt was invalid.",
  invalid_request: "The provider said the request was invalid.",
  max_tokens_exceeded: "The requested output was more than the model allows.",
  not_found: "The provider didn't find the model or endpoint.",
  payload_too_large: "The request body was larger than the provider allows.",
  payment_required: "The provider account needs payment.",
  permission_denied: "The provider key isn't allowed to use this model or endpoint.",
  precondition_failed: "A precondition the provider checks wasn't met.",
  provider_overloaded: "The provider said it was overloaded.",
  provider_unavailable: "The provider said it was unavailable.",
  rate_limit_exceeded: "The provider was rate-limiting this key.",
  refusal: "The model refused to answer.",
  server: "The provider returned a server error.",
  string_too_long: "A text field was longer than the provider allows.",
  timeout: "No response arrived in time.",
  token_limit_exceeded: "The request used more tokens than the provider allows.",
  unknown: "The provider returned an error Latchway couldn't classify.",
  unmapped: "The provider returned an error Latchway doesn't map yet.",
  unprocessable: "The provider couldn't process the request.",
  unsupported_image_format: "An image's format isn't supported."
};

export function errorDocumentationURL(code: string): string {
  return `https://docs.latchway.dev/errors/${code.replaceAll("_", "-")}`;
}

/** Badge status for a request outcome; canceled and unknown are not failures. */
export function outcomeStatus(status: LogicalRequest["status"]): Status {
  if (status === "canceled") return "canceled";
  if (status === "unknown") return "unknown";
  return status;
}

export function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

export function words(value: string): string {
  return value.replaceAll("_", " ");
}

export function elapsedMs(from: string, to: string | undefined): number | undefined {
  if (!to) return undefined;
  const value = Date.parse(to) - Date.parse(from);
  return Number.isFinite(value) && value >= 0 ? value : undefined;
}

/** 840 ms, 2.4 s, 1 m 12 s. */
export function formatMs(value: number | undefined): string {
  if (value === undefined) return "—";
  if (value < 1_000) return `${Math.round(value).toLocaleString()} ms`;
  if (value < 60_000) return `${(value / 1_000).toLocaleString(undefined, { maximumFractionDigits: value < 10_000 ? 2 : 1 })} s`;
  const minutes = Math.floor(value / 60_000);
  return `${minutes} m ${Math.round((value % 60_000) / 1_000)} s`;
}

/**
 * Integer nano-USD as dollars without float accumulation: $0, $0.0021, $12.40. Up to three significant digits after
 * leading zeros, so tiny per-request costs stay readable.
 */
export function formatUsd(nanoUsd: number): string {
  if (nanoUsd === 0) return "$0";
  const whole = Math.floor(nanoUsd / 1_000_000_000);
  const fraction = String(nanoUsd % 1_000_000_000).padStart(9, "0");
  if (whole >= 1) return `$${whole.toLocaleString()}.${fraction.slice(0, 2)}`;
  const firstSignificant = fraction.search(/[1-9]/);
  const digits = fraction.slice(0, Math.min(9, firstSignificant + 3)).replace(/0+$/, "");
  return `$0.${digits}`;
}

/** usr_01J9ZK…7TFW */
export function shortId(id: string): string {
  return id.length > 18 ? `${id.slice(0, 10)}…${id.slice(-4)}` : id;
}

/** Local time; the date is included unless it's today. */
export function formatClock(value: string, now: number): string {
  const date = new Date(value);
  const sameDay = date.toDateString() === new Date(now).toDateString();
  return sameDay
    ? date.toLocaleTimeString(undefined, { hour: "2-digit", hour12: false, minute: "2-digit", second: "2-digit" })
    : date.toLocaleString(undefined, { day: "numeric", hour: "2-digit", hour12: false, minute: "2-digit", month: "short" });
}

export function formatUtc(value: string): string {
  return `${value.replace("T", " ").replace(/\.\d+/, "").replace("Z", "")} UTC`;
}

export interface MetricCell {
  /** Display text; "—" when nothing was recorded. */
  text: string;
  estimated: boolean;
  recorded: boolean;
}

/** One usage metric for a table cell: recorded units, flagged when any part is estimated. */
export function metricCell(usage: Usage | undefined, metric: "total_tokens" | "cost_nano_usd"): MetricCell {
  if (!usage) return { estimated: false, recorded: false, text: "—" };
  const details = usage.details?.[metric];
  if (details && details.recorded_units === null) return { estimated: false, recorded: false, text: "—" };
  const units = details?.recorded_units ?? usage[metric];
  const estimated = Boolean(details?.provenance.includes("estimated") || details?.unknown_units);
  const text = metric === "cost_nano_usd" ? formatUsd(units) : units.toLocaleString();
  return { estimated, recorded: true, text: `${estimated ? "~" : ""}${text}` };
}

/** Time to first token for the attempt that answered, measured from the request start. */
export function timeToFirstToken(request: LogicalRequest): number | undefined {
  const answered = [...request.attempts].reverse().find((attempt) => attempt.first_token_at);
  return answered?.first_token_at ? elapsedMs(request.started_at, answered.first_token_at) : undefined;
}

export function requestDuration(request: LogicalRequest): number | undefined {
  return elapsedMs(request.started_at, request.completed_at);
}

/** The outcome in one sentence, from recorded fields only. */
export function outcomeSentence(request: LogicalRequest): string {
  const failedAttempts = request.attempts.filter((attempt) => attempt.status === "failed").length;
  const answeredBy = [...request.attempts].reverse().find((attempt) => attempt.status === "succeeded")?.upstream;
  if (request.status === "succeeded") {
    if (!answeredBy) return "Succeeded.";
    return failedAttempts ? `Answered by ${answeredBy} after ${failedAttempts} failed attempt${failedAttempts === 1 ? "" : "s"}.` : `Answered by ${answeredBy}.`;
  }
  if (request.status === "canceled") return OUTCOME_TEXT.canceled ?? "Canceled.";
  if (request.status === "unknown") return "The outcome wasn't recorded; the request may still have been running.";
  if (request.failure_code) return OUTCOME_TEXT[request.failure_code] ?? `It ended with ${request.failure_code}.`;
  return request.status === "denied" ? "It was refused." : "It failed.";
}

/** The "Model on connection" cell. */
export function routeSummary(request: LogicalRequest): { kind: "routed" | "not-sent" | "not-routed"; model?: string; upstream?: string } {
  if (request.attempts.length) {
    const last = request.attempts.at(-1);
    return { kind: "routed", model: request.selected_model ?? last?.model, upstream: last?.upstream ?? request.selected_upstream };
  }
  if (request.selected_model) return { kind: "not-sent", model: request.selected_model, upstream: request.selected_upstream };
  return { kind: "not-routed" };
}

/** The limit a quota stage evaluated, as a sentence. */
export function limitSentence(stage: Stage): string | undefined {
  if (!stage.limit_metric || stage.limit_maximum === undefined) return stage.limit_plan_key ? `${stage.limit_plan_key} plan` : undefined;
  const algorithm = stage.limit_algorithm === "per_request" ? " per request" : stage.limit_algorithm === "concurrency" ? " at once" : "";
  const amount = `${stage.limit_maximum.toLocaleString()} ${words(stage.limit_metric)}${algorithm}`;
  return stage.limit_plan_key ? `${amount} · ${stage.limit_plan_key} plan` : amount;
}

/** Detail line for one decision stage, from the fields that stage records. */
export function stageDetail(stage: Stage): string | undefined {
  if (stage.stage === "configuration_loaded") return stage.config_revision_id;
  if (stage.stage === "route_selected" && stage.route) return `${stage.route} → ${stage.model} on ${stage.upstream}`;
  if (stage.stage === "quota_rule_evaluated" || stage.stage === "quota_reserved") return limitSentence(stage);
  if (stage.stage === "policy_evaluated" && stage.policy_rule_key) return `Rule: ${stage.policy_rule_key}`;
  return undefined;
}

const CSV_SAFE = /^[A-Za-z0-9_.:+\- ]*$/;

function csvField(value: string): string {
  // Leading formula characters are neutralized so spreadsheets never evaluate exported values.
  const neutral = /^[=+\-@]/.test(value) ? `'${value}` : value;
  return CSV_SAFE.test(neutral) ? neutral : `"${neutral.replaceAll("\"", "\"\"")}"`;
}

/** CSV of the loaded rows. User IDs are excluded unless asked for. */
export function requestsCsv(requests: readonly LogicalRequest[], includeUsers: boolean): string {
  const header = ["request_id", "started_at", "status", "failure_code", "feature", ...(includeUsers ? ["user_id"] : []), "model", "upstream", "attempts", "duration_ms", "total_tokens", "cost_nano_usd"];
  const rows = requests.map((request) => {
    const route = routeSummary(request);
    const tokens = metricCell(request.usage, "total_tokens");
    const cost = request.usage?.details?.cost_nano_usd?.recorded_units ?? (request.usage?.details ? null : request.usage?.cost_nano_usd);
    return [
      request.id, request.started_at, request.status, request.failure_code ?? "", request.feature,
      ...(includeUsers ? [request.user_id] : []),
      route.model ?? "", route.upstream ?? "", String(request.attempts.length), String(requestDuration(request) ?? ""),
      tokens.recorded ? String(request.usage?.details?.total_tokens?.recorded_units ?? request.usage?.total_tokens ?? "") : "",
      cost === null || cost === undefined ? "" : String(cost)
    ].map(csvField).join(",");
  });
  return `${[header.join(","), ...rows].join("\n")}\n`;
}

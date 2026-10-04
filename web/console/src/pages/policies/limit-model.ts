import type { JSONRecord } from "../configuration-slice";

/**
 * Limit plans as sentences. Everything here mirrors the server's activation rules
 * (internal/configuration/limits.go and internal/limitmetric): which metric supports which algorithm, which fields
 * each algorithm takes, the scope dimensions and their canonical order, and the cost retry pairing rule.
 */
export type Algorithm = "calendar" | "token_bucket" | "concurrency" | "per_request";

export const KIND_LABEL: Readonly<Record<Algorithm, string>> = {
  calendar: "Per period",
  concurrency: "At once",
  per_request: "Per request",
  token_bucket: "Burst rate"
};

interface MetricInfo {
  algorithms: readonly Algorithm[];
  /** Singular and plural nouns, e.g. "request" / "requests". */
  one: string;
  other: string;
}

/** Metrics this release can enforce, with the algorithms each supports. Others are kept but can't be activated. */
export const METRICS: Readonly<Record<string, MetricInfo>> = {
  concurrent_requests: { algorithms: ["concurrency"], one: "open request", other: "open requests" },
  concurrent_streams: { algorithms: ["concurrency"], one: "open stream", other: "open streams" },
  cost_nano_usd: { algorithms: ["calendar"], one: "spend", other: "spend" },
  image_units: { algorithms: ["per_request"], one: "image", other: "images" },
  input_tokens: { algorithms: ["calendar", "token_bucket", "per_request"], one: "input token", other: "input tokens" },
  logical_requests: { algorithms: ["calendar", "token_bucket"], one: "request", other: "requests" },
  output_tokens: { algorithms: ["calendar", "token_bucket", "per_request"], one: "output token", other: "output tokens" },
  request_bytes: { algorithms: ["per_request"], one: "request byte", other: "request bytes" },
  tool_calls: { algorithms: ["per_request"], one: "tool call", other: "tool calls" },
  total_tokens: { algorithms: ["calendar", "token_bucket", "per_request"], one: "token", other: "tokens" },
  upstream_attempts: { algorithms: ["calendar", "token_bucket", "per_request"], one: "provider attempt", other: "provider attempts" }
};

export const METRIC_ORDER = ["logical_requests", "total_tokens", "input_tokens", "output_tokens", "cost_nano_usd", "upstream_attempts", "concurrent_requests", "concurrent_streams", "request_bytes", "image_units", "tool_calls"] as const;

/** Server canonical scope order (internal/limitscope). A `normalized_claim:<name>` selector goes last. */
export const SCOPE_DIMENSIONS: ReadonlyArray<readonly [string, string]> = [
  ["organization", "organization"],
  ["application", "application"],
  ["environment", "environment"],
  ["user", "user"],
  ["installation", "installation"],
  ["installation_family", "device family"],
  ["client_component", "app component"],
  ["component_definition", "component definition"],
  ["component_kind", "component kind"],
  ["trust_source", "trust source"],
  ["feature", "feature"],
  ["route", "route"],
  ["upstream", "AI connection"],
  ["model", "model"],
  ["platform", "platform"]
];

const DIMENSION_LABEL = new Map(SCOPE_DIMENSIONS);
const CLAIM_PREFIX = "normalized_claim:";
export const CLAIM_NAME = /^[a-z][a-z0-9_]{0,62}$/;

export const SCOPE_PRESETS: ReadonlyArray<{ id: string; label: string; scope: readonly string[] }> = [
  { id: "user", label: "Each user", scope: ["user"] },
  { id: "user_feature", label: "Each user, per feature", scope: ["user", "feature"] },
  { id: "installation", label: "Each installation", scope: ["installation"] },
  { id: "family", label: "Each device family", scope: ["installation_family"] },
  { id: "trust", label: "Each trust source", scope: ["trust_source"] },
  { id: "component", label: "Each app component", scope: ["client_component"] },
  { id: "feature", label: "Each feature, all users together", scope: ["feature"] },
  { id: "model", label: "Each model, all users together", scope: ["model"] },
  { id: "plan_claim", label: "Each plan claim value", scope: ["normalized_claim:plan"] },
  { id: "organization", label: "Everyone together", scope: ["organization"] }
];

/** Dimensions that count something other than a person: the building blocks of abuse protection. */
const PROTECTION_DIMENSIONS = new Set(["installation", "installation_family", "client_component", "component_definition", "component_kind", "trust_source", "platform"]);

export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

export function canonicalScope(scope: readonly string[]): string[] {
  const fixed = SCOPE_DIMENSIONS.map(([id]) => id).filter((id) => scope.includes(id));
  return [...fixed, ...scope.filter((dimension) => dimension.startsWith(CLAIM_PREFIX))];
}

function sameScope(a: readonly string[], b: readonly string[]): boolean {
  return canonicalScope(a).join("\u0000") === canonicalScope(b).join("\u0000");
}

export function scopePreset(scope: readonly string[]): string | undefined {
  return SCOPE_PRESETS.find((preset) => sameScope(preset.scope, scope))?.id;
}

/** "Each user", or for a custom scope "Each user, per feature and platform" / "Each `team` claim value". */
export function scopeLabel(scope: readonly string[]): string {
  const preset = SCOPE_PRESETS.find((candidate) => sameScope(candidate.scope, scope));
  if (preset) return preset.label;
  if (!scope.length) return "No one (scope missing)";
  const parts = canonicalScope(scope).map((dimension) => dimension.startsWith(CLAIM_PREFIX) ? `${dimension.slice(CLAIM_PREFIX.length)} claim value` : DIMENSION_LABEL.get(dimension) ?? dimension);
  const [first, ...rest] = parts;
  return `Each ${first}${rest.length ? `, per ${rest.length > 1 ? `${rest.slice(0, -1).join(", ")} and ${rest.at(-1)}` : rest[0]}` : ""}`;
}

export function isProtection(limit: JSONRecord): boolean {
  const scope = strings(limit.scope);
  return !scope.includes("user") && scope.some((dimension) => PROTECTION_DIMENSIONS.has(dimension));
}

export function algorithmOf(limit: JSONRecord): Algorithm | undefined {
  const value = limit.algorithm;
  return value === "calendar" || value === "token_bucket" || value === "concurrency" || value === "per_request" ? value : undefined;
}

const number = new Intl.NumberFormat("en-US");

function count(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/** Nano-USD integer to dollars, without floating-point drift: 1500000000 → "$1.50". */
export function nanoToDollars(nano: number): string {
  const negative = nano < 0;
  const digits = String(Math.abs(Math.trunc(nano))).padStart(10, "0");
  const whole = digits.slice(0, -9).replace(/^0+(?=\d)/, "");
  const fraction = digits.slice(-9).replace(/0+$/, "");
  const cents = fraction.length <= 2 ? fraction.padEnd(2, "0") : fraction;
  return `${negative ? "−" : ""}$${number.format(Number(whole))}.${cents}`;
}

/** "12.50" dollars to integer nano-USD, exactly. Undefined for anything that isn't a positive decimal amount. */
export function dollarsToNano(input: string): number | undefined {
  const match = /^\s*\$?\s*(\d{1,7})(?:\.(\d{1,9}))?\s*$/.exec(input.replaceAll(",", ""));
  if (!match?.[1]) return undefined;
  const nano = Number(match[1]) * 1_000_000_000 + Number((match[2] ?? "").padEnd(9, "0"));
  return Number.isSafeInteger(nano) && nano > 0 ? nano : undefined;
}

/** "50,000 tokens", "1 open stream", "$12.50". */
export function formatAmount(metric: string, value: unknown): string {
  const amount = count(value);
  if (amount === undefined) return "—";
  if (metric === "cost_nano_usd") return nanoToDollars(amount);
  const info = METRICS[metric];
  const noun = info ? (amount === 1 ? info.one : info.other) : metric;
  return `${number.format(amount)} ${noun}`;
}

const WINDOW_UNITS: Readonly<Record<string, readonly [string, string]>> = {
  d: ["day", "days"],
  h: ["hour", "hours"],
  m: ["minute", "minutes"],
  mo: ["month", "months"],
  w: ["week", "weeks"]
};

export const WINDOW_MAXIMUM: Readonly<Record<string, number>> = { d: 366, h: 366 * 24, m: 366 * 24 * 60, mo: 12, w: 52 };

export function parseWindow(window: unknown): { amount: number; unit: string } | undefined {
  const match = /^([1-9][0-9]*)(m|h|d|w|mo)$/.exec(String(window ?? ""));
  return match?.[1] && match[2] ? { amount: Number(match[1]), unit: match[2] } : undefined;
}

/** "per day", "per 7 days". */
export function windowLabel(window: unknown): string {
  const parsed = parseWindow(window);
  if (!parsed) return "per (missing period)";
  const [one, other] = WINDOW_UNITS[parsed.unit] ?? [parsed.unit, parsed.unit];
  return parsed.amount === 1 ? `per ${one}` : `per ${parsed.amount} ${other}`;
}

/** Refill as people say it: 0.5 per second reads "30 per minute". */
export function refillLabel(perSecond: unknown, metric: string): string {
  const rate = typeof perSecond === "number" ? perSecond : Number(perSecond);
  if (!Number.isFinite(rate) || rate <= 0) return "(missing refill)";
  const noun = METRICS[metric]?.other ?? metric;
  for (const [unit, seconds] of [["second", 1], ["minute", 60], ["hour", 3600]] as const) {
    const value = rate * seconds;
    if (value >= 1 && Math.abs(value - Math.round(value * 100) / 100) < 1e-9) return `${number.format(Math.round(value * 100) / 100)} ${noun} per ${unit}`;
  }
  return `${rate} ${noun} per second`;
}

export interface LimitSentence {
  amount: string;
  kind: Algorithm | undefined;
  /** Text after the amount, e.g. "per day". */
  tail: string;
  /** "Each user". Empty for per-request limits, which read "No single request…". */
  who: string;
  /** Text between who and amount, e.g. "can use". */
  verb: string;
}

export function limitSentence(limit: JSONRecord): LimitSentence {
  const metric = String(limit.metric ?? "");
  const who = scopeLabel(strings(limit.scope));
  switch (algorithmOf(limit)) {
    case "calendar": return { amount: formatAmount(metric, limit.maximum), kind: "calendar", tail: windowLabel(limit.window), verb: "can use", who };
    case "token_bucket": return { amount: formatAmount(metric, limit.capacity), kind: "token_bucket", tail: `, refilling ${refillLabel(limit.refillPerSecond, metric)}`, verb: "can burst to", who };
    case "concurrency": return { amount: formatAmount(metric, limit.maximum), kind: "concurrency", tail: "at once", verb: "can have", who };
    case "per_request": return { amount: formatAmount(metric, limit.perRequestMaximum), kind: "per_request", tail: "", verb: "No single request can use more than", who: "" };
    default: return { amount: metric || "unknown metric", kind: undefined, tail: "(no supported kind set)", verb: "limits", who };
  }
}

export function limitText(limit: JSONRecord): string {
  const sentence = limitSentence(limit);
  return [sentence.who, sentence.verb, sentence.amount].filter(Boolean).join(" ") + (sentence.tail.startsWith(",") ? sentence.tail : sentence.tail ? ` ${sentence.tail}` : "");
}

export interface PlanIssue {
  /** A one-click fix offered next to the message. */
  fix?: "organization_spend" | "spend";
  /** The limit the issue belongs to, when it belongs to one. */
  index?: number;
  message: string;
}

const TIMEZONE = /^[A-Za-z][A-Za-z0-9._+-]*(\/[A-Za-z0-9][A-Za-z0-9._+-]*)*$/;

/** Problems the server would refuse at activation, phrased for the editor. */
export function limitProblems(limit: JSONRecord): string[] {
  const problems: string[] = [];
  const metric = String(limit.metric ?? "");
  const algorithm = algorithmOf(limit);
  const info = METRICS[metric];
  if (!info) problems.push(`${metric || "This metric"} can't be enforced by this server yet.`);
  if (!algorithm) problems.push("Choose what kind of limit this is.");
  else if (info && !info.algorithms.includes(algorithm)) problems.push(`${KIND_LABEL[algorithm]} doesn't work for ${info.other}; choose ${info.algorithms.map((value) => KIND_LABEL[value]).join(" or ")}.`);
  if (limit.hard === false) problems.push("Track-only limits can't be activated by this server; every limit blocks.");
  const scope = strings(limit.scope);
  const claims = scope.filter((dimension) => dimension.startsWith(CLAIM_PREFIX));
  if (!scope.length) problems.push("Choose who the limit counts.");
  if (claims.length > 1) problems.push("A limit can count at most one claim.");
  if (claims.some((claim) => !CLAIM_NAME.test(claim.slice(CLAIM_PREFIX.length)))) problems.push("Claim names use lowercase letters, digits and _.");
  if (scope.some((dimension) => !dimension.startsWith(CLAIM_PREFIX) && !DIMENSION_LABEL.has(dimension))) problems.push("The scope has an unknown dimension.");
  const positive = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value > 0;
  if (algorithm === "calendar") {
    const window = parseWindow(limit.window);
    if (!positive(limit.maximum)) problems.push("Enter an amount above zero.");
    if (!window || window.amount > (WINDOW_MAXIMUM[window.unit] ?? 0)) problems.push("Enter a period of at most one year, e.g. 1 day or 12 months.");
    if (limit.timezone !== undefined && (typeof limit.timezone !== "string" || !TIMEZONE.test(limit.timezone) || limit.timezone === "Local")) problems.push("Periods start in an IANA time zone such as UTC or America/New_York.");
  }
  if (algorithm === "token_bucket") {
    const rate = typeof limit.refillPerSecond === "number" ? limit.refillPerSecond : Number.NaN;
    if (!positive(limit.capacity) || Number(limit.capacity) > 9_223_372) problems.push("The burst size is a whole number from 1 to 9,223,372.");
    if (!(rate >= 0.000001 && rate <= 1_000_000) || Math.round(rate * 1_000_000) / 1_000_000 !== rate) problems.push("The refill is between 0.000001 and 1,000,000 per second, with at most six decimal places per second.");
  }
  if (algorithm === "concurrency" && !positive(limit.maximum)) problems.push("Enter how many at once, above zero.");
  if (algorithm === "per_request" && !positive(limit.perRequestMaximum)) problems.push("Enter the most a single request can use, above zero.");
  if (limit.costRetryTreatment !== undefined) {
    if (metric !== "cost_nano_usd") problems.push("Retry treatment applies only to spend limits.");
    else if (limit.costRetryTreatment === "initial_attempt_only" && !scope.includes("user")) problems.push("First attempt only needs a scope that includes the user.");
  }
  return problems;
}

function identity(limit: JSONRecord): string {
  return [limit.metric, limit.algorithm, limit.window ?? "", limit.algorithm === "calendar" ? limit.timezone ?? "UTC" : "", canonicalScope(strings(limit.scope)).join(",")].join("|");
}

export function planIssues(limits: readonly JSONRecord[]): { errors: PlanIssue[]; warnings: PlanIssue[] } {
  const errors: PlanIssue[] = [];
  const warnings: PlanIssue[] = [];
  if (!limits.length) errors.push({ message: "A plan needs at least one limit." });
  if (limits.length > 128) errors.push({ message: "A plan can have at most 128 limits." });
  const seen = new Map<string, number>();
  limits.forEach((limit, index) => {
    for (const message of limitProblems(limit)) errors.push({ index, message });
    const key = identity(limit);
    if (seen.has(key)) errors.push({ index, message: `This counts exactly the same thing as limit ${(seen.get(key) ?? 0) + 1}; change one or remove it.` });
    else seen.set(key, index);
  });
  const spend = limits.filter((limit) => limit.metric === "cost_nano_usd");
  const firstAttemptOnly = spend.some((limit) => limit.costRetryTreatment === "initial_attempt_only");
  const organizationWide = spend.some((limit) => (limit.costRetryTreatment ?? "actual_attempts") === "actual_attempts" && strings(limit.scope).includes("organization") && !strings(limit.scope).includes("user"));
  if (firstAttemptOnly && !organizationWide) {
    errors.push({ fix: "organization_spend", message: "A spend limit that counts only the first attempt needs an organization-wide spend limit that counts every attempt, so retries still have a ceiling." });
  }
  if (limits.length && !spend.length) warnings.push({ fix: "spend", message: "This plan has no spend limit, so nothing caps what its users cost." });
  return { errors, warnings };
}

export function organizationSpendLimit(): JSONRecord {
  return { algorithm: "calendar", hard: true, maximum: 100_000_000_000, metric: "cost_nano_usd", scope: ["organization"], timezone: "UTC", window: "1mo" };
}

export function userSpendLimit(): JSONRecord {
  return { algorithm: "calendar", hard: true, maximum: 5_000_000_000, metric: "cost_nano_usd", scope: ["user"], timezone: "UTC", window: "1mo" };
}

export function newLimit(): JSONRecord {
  return { algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], timezone: "UTC", window: "1d" };
}

/** Changes a limit's kind, keeping only the fields that kind takes. */
export function withKind(limit: JSONRecord, kind: Algorithm): JSONRecord {
  const base: JSONRecord = { algorithm: kind, hard: true, metric: limit.metric, scope: limit.scope };
  if (limit.costRetryTreatment !== undefined && kind === "calendar") base.costRetryTreatment = limit.costRetryTreatment;
  const amount = Number(limit.maximum ?? limit.capacity ?? limit.perRequestMaximum ?? 100);
  if (kind === "calendar") return { ...base, maximum: amount, timezone: typeof limit.timezone === "string" ? limit.timezone : "UTC", window: typeof limit.window === "string" ? limit.window : "1d" };
  if (kind === "token_bucket") return { ...base, capacity: Math.min(amount, 9_223_372), refillPerSecond: typeof limit.refillPerSecond === "number" ? limit.refillPerSecond : 1 };
  if (kind === "concurrency") return { ...base, maximum: Math.min(amount, 100) };
  return { ...base, perRequestMaximum: amount };
}

/** Changes a limit's metric, moving to a kind the metric supports when needed. */
export function withMetric(limit: JSONRecord, metric: string): JSONRecord {
  const info = METRICS[metric];
  const current = algorithmOf(limit);
  const next: JSONRecord = { ...limit, metric };
  if (metric !== "cost_nano_usd") delete next.costRetryTreatment;
  if (info && (!current || !info.algorithms.includes(current))) return withKind(next, info.algorithms[0] ?? "calendar");
  return next;
}

function planRecords(document: JSONRecord | undefined, key: string): JSONRecord[] {
  const spec = document?.spec;
  const value = spec && typeof spec === "object" && !Array.isArray(spec) ? (spec as JSONRecord)[key] : undefined;
  return Array.isArray(value) ? value.filter((item): item is JSONRecord => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : [];
}

export function limitPlans(document: JSONRecord | undefined): JSONRecord[] {
  return planRecords(document, "limitPlans");
}

/** Plan IDs a feature's limit-plan expression can return: every quoted identifier in it. */
export function plansInExpression(expression: unknown): string[] {
  return [...new Set([...String(expression ?? "").matchAll(/['"]([a-z][a-z0-9_-]{0,62})['"]/g)].map((match) => match[1] ?? ""))];
}

/** For each plan, the features whose expression mentions it. */
export function featuresByPlan(document: JSONRecord | undefined): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const feature of planRecords(document, "features")) {
    const expression = feature.limitPlan && typeof feature.limitPlan === "object" ? (feature.limitPlan as JSONRecord).expression : undefined;
    for (const plan of plansInExpression(expression)) result.set(plan, [...(result.get(plan) ?? []), String(feature.id)]);
  }
  return result;
}

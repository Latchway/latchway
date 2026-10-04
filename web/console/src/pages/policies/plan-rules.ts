/**
 * A feature's `limitPlan` is a CEL expression that returns a plan ID. The console edits the common shape as ordered
 * rules ("If plan is premium → premium · Everyone else → free") and compiles them to a nested ternary. Anything it
 * can't read back exactly stays a custom expression; the console never rewrites one it doesn't understand.
 */
export type RuleAttribute = "claim" | "platform" | "component_kind" | "trust_level" | "streaming" | "input_tokens";

export interface PlanRule {
  attribute: RuleAttribute;
  /** Claim name, for `claim`. */
  claim?: string;
  plan: string;
  /** Compared value: claim value, platform, kind or trust level; "true"/"false" for streaming; a number for input tokens. */
  value: string;
}

export interface PlanRules {
  fallback: string;
  rules: PlanRule[];
}

export const ATTRIBUTE_LABEL: Readonly<Record<RuleAttribute, string>> = {
  claim: "Claim",
  component_kind: "Component kind",
  input_tokens: "Prompt longer than (tokens)",
  platform: "Platform",
  streaming: "Streaming",
  trust_level: "Trust level"
};

export const PLATFORMS = ["ios", "android", "web", "react_native_ios", "react_native_android", "node"] as const;
export const TRUST_LEVELS = ["none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug"] as const;
export const COMPONENT_KINDS = ["main_app", "widget", "share_extension", "app_intent_extension", "notification_service_extension", "action_extension", "sso_extension", "watch_extension", "android_app", "wear_app", "browser", "node_process"] as const;

const IDENT = "[a-z][a-z0-9_-]{0,62}";
const CLAIM = "[a-z][a-z0-9_]{0,62}";
const VALUE = "[A-Za-z0-9_.:@-]{1,128}";
const CONDITIONS: ReadonlyArray<[RuleAttribute, RegExp]> = [
  ["claim", new RegExp(`^principal\\.claims\\.(${CLAIM}) == '(${VALUE})'$`)],
  ["platform", new RegExp(`^installation\\.platform == '(${IDENT})'$`)],
  ["component_kind", new RegExp(`^client\\.component\\.kind == '(${IDENT})'$`)],
  ["trust_level", new RegExp(`^installation\\.trust_level == '(${IDENT})'$`)],
  ["streaming", /^(!?)request\.streaming$/],
  ["input_tokens", /^request\.estimated_input_tokens > ([0-9]{1,10})$/]
];

export const PLAN_ID = new RegExp(`^${IDENT}$`);
const CLAIM_VALUE = new RegExp(`^${VALUE}$`);

export function condition(rule: PlanRule): string {
  switch (rule.attribute) {
    case "claim": return `principal.claims.${rule.claim ?? "plan"} == '${rule.value}'`;
    case "platform": return `installation.platform == '${rule.value}'`;
    case "component_kind": return `client.component.kind == '${rule.value}'`;
    case "trust_level": return `installation.trust_level == '${rule.value}'`;
    case "streaming": return rule.value === "false" ? "!request.streaming" : "request.streaming";
    case "input_tokens": return `request.estimated_input_tokens > ${Number(rule.value)}`;
  }
}

export function compileRules(rules: PlanRules): string {
  return rules.rules.reduceRight((otherwise, rule) => `${condition(rule)} ? '${rule.plan}' : ${otherwise}`, `'${rules.fallback}'`);
}

function parseCondition(text: string): Omit<PlanRule, "plan"> | undefined {
  for (const [attribute, pattern] of CONDITIONS) {
    const match = pattern.exec(text);
    if (!match) continue;
    if (attribute === "claim") return { attribute, claim: match[1], value: match[2] ?? "" };
    if (attribute === "streaming") return { attribute, value: match[1] ? "false" : "true" };
    return { attribute, value: match[1] ?? "" };
  }
  return undefined;
}

/** Reads an expression the console wrote (or one written the same way). Undefined means "custom expression". */
export function parseRules(expression: unknown): PlanRules | undefined {
  let rest = String(expression ?? "").trim();
  const rules: PlanRule[] = [];
  const step = new RegExp(`^(.+?) \\? '(${IDENT})' : (.+)$`, "s");
  for (let guard = 0; guard < 32; guard += 1) {
    const fallback = new RegExp(`^'(${IDENT})'$`).exec(rest);
    if (fallback?.[1]) return { fallback: fallback[1], rules };
    const match = step.exec(rest);
    if (!match?.[1] || !match[2] || !match[3]) return undefined;
    const parsed = parseCondition(match[1].trim());
    if (!parsed) return undefined;
    rules.push({ ...parsed, plan: match[2] });
    rest = match[3].trim();
  }
  return undefined;
}

/** "If plan is premium → premium · Everyone else → free". */
export function rulesSentence(rules: PlanRules): string {
  const parts = rules.rules.map((rule, index) => `${index ? "Else if" : "If"} ${conditionText(rule)} → ${rule.plan}`);
  return [...parts, `${rules.rules.length ? "Everyone else" : "Everyone"} → ${rules.fallback}`].join(" · ");
}

export function conditionText(rule: PlanRule): string {
  switch (rule.attribute) {
    case "claim": return `${rule.claim ?? "plan"} is ${rule.value}`;
    case "platform": return `platform is ${rule.value.replaceAll("_", " ")}`;
    case "component_kind": return `component is ${rule.value.replaceAll("_", " ")}`;
    case "trust_level": return `trust is ${rule.value.replaceAll("_", " ")}`;
    case "streaming": return rule.value === "false" ? "not streaming" : "streaming";
    case "input_tokens": return `prompt over ${Number(rule.value).toLocaleString("en-US")} tokens`;
  }
}

/** Problems that block saving: bad values, or a plan that isn't in the draft. */
export function rulesProblems(rules: PlanRules, plans: readonly string[]): string[] {
  const problems: string[] = [];
  const unknown = [...new Set([...rules.rules.map((rule) => rule.plan), rules.fallback])].filter((plan) => !plans.includes(plan));
  if (unknown.length) problems.push(`${unknown.join(", ")} ${unknown.length === 1 ? "isn't a plan" : "aren't plans"} in the draft.`);
  rules.rules.forEach((rule, index) => {
    const position = `Rule ${index + 1}`;
    if (rule.attribute === "claim" && !/^[a-z][a-z0-9_]{0,62}$/.test(rule.claim ?? "")) problems.push(`${position}: claim names use lowercase letters, digits and _.`);
    if (rule.attribute === "claim" && !CLAIM_VALUE.test(rule.value)) problems.push(`${position}: enter the claim value (letters, digits, _ . : @ -).`);
    if (rule.attribute === "input_tokens" && !/^[0-9]{1,10}$/.test(rule.value)) problems.push(`${position}: enter a whole number of tokens.`);
    if (["platform", "component_kind", "trust_level"].includes(rule.attribute) && !PLAN_ID.test(rule.value)) problems.push(`${position}: choose a value.`);
  });
  const seen = new Set<string>();
  rules.rules.forEach((rule, index) => {
    const key = condition(rule);
    if (seen.has(key)) problems.push(`Rule ${index + 1} can never be reached: an earlier rule has the same condition.`);
    seen.add(key);
  });
  return problems;
}

/** Points every mention of `from` in a feature's plan selection at `to`. */
export function replacePlanInExpression(expression: string, from: string, to: string): string {
  const rules = parseRules(expression);
  if (rules) return compileRules({ fallback: rules.fallback === from ? to : rules.fallback, rules: rules.rules.map((rule) => (rule.plan === from ? { ...rule, plan: to } : rule)) });
  return expression.replace(new RegExp(`(['"])${from}\\1`, "g"), `'${to}'`);
}

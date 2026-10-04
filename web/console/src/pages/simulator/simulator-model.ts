import { adminRequest, type RouteSimulation, RouteSimulationSchema } from "../../api/admin";

/**
 * The Simulator mirrors `POST /config-revisions/{id}/simulate`: the exact compiled policy and route resolver, with no
 * quota reserved and nothing sent. Everything here builds requests for it or reads its results; nothing is guessed.
 */
export type Platform = "ios" | "android" | "web" | "react_native_ios" | "react_native_android" | "node";
export type TrustLevel = "none" | "identity_only" | "web_risk_verified" | "app_verified" | "device_verified" | "strong_device_verified" | "debug";

export const PLATFORM_LABEL: Readonly<Record<Platform, string>> = {
  android: "Android",
  ios: "iOS",
  node: "Node",
  react_native_android: "React Native Android",
  react_native_ios: "React Native iOS",
  web: "Web"
};

export const TRUST_LABEL: Readonly<Record<TrustLevel, string>> = {
  app_verified: "Genuine app",
  debug: "Debug build",
  device_verified: "Genuine device",
  identity_only: "Signed in only",
  none: "Unverified",
  strong_device_verified: "Strong device proof",
  web_risk_verified: "Web risk check"
};

export const TRUST_ORDER: readonly TrustLevel[] = ["none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug"];

export interface RequestSize {
  expanded_schema_bytes: number;
  framing_unit_count: number;
  image_units: number;
  requested_input_tokens: number;
  requested_output_max: number;
  rewritten_request_bytes: number;
  tool_calls: number;
}

export const SIZE_PRESETS: ReadonlyArray<{ id: string; label: string; size: RequestSize }> = [
  { id: "short", label: "Short chat", size: { expanded_schema_bytes: 0, framing_unit_count: 2, image_units: 0, requested_input_tokens: 800, requested_output_max: 500, rewritten_request_bytes: 4_000, tool_calls: 0 } },
  { id: "long", label: "Long document", size: { expanded_schema_bytes: 0, framing_unit_count: 2, image_units: 0, requested_input_tokens: 40_000, requested_output_max: 2_000, rewritten_request_bytes: 160_000, tool_calls: 0 } },
  { id: "tools", label: "Tool-heavy", size: { expanded_schema_bytes: 8_000, framing_unit_count: 12, image_units: 0, requested_input_tokens: 6_000, requested_output_max: 1_000, rewritten_request_bytes: 24_000, tool_calls: 6 } },
  { id: "image", label: "Image", size: { expanded_schema_bytes: 0, framing_unit_count: 3, image_units: 1, requested_input_tokens: 2_000, requested_output_max: 800, rewritten_request_bytes: 12_000, tool_calls: 0 } }
];

export function sizePreset(size: RequestSize): string {
  return SIZE_PRESETS.find((preset) => (Object.keys(preset.size) as Array<keyof RequestSize>).every((key) => preset.size[key] === size[key]))?.id ?? "custom";
}

export interface SimulationInput {
  appVersion?: string;
  authenticated: boolean;
  /** Normalized claims. Kept in the page only; never in URLs or storage. */
  claims: Record<string, string | boolean>;
  feature: string;
  platform: Platform;
  size: RequestSize;
  streaming: boolean;
  trustLevel: TrustLevel;
}

export function simulationBody(input: SimulationInput) {
  return {
    feature: input.feature,
    platform: input.platform,
    principal: { authenticated: input.authenticated, claims: input.claims },
    request: { ...input.size, ...(input.appVersion ? { app_version: input.appVersion } : {}), streaming: input.streaming },
    trust_level: input.trustLevel
  };
}

export async function simulate(revisionID: string, input: SimulationInput): Promise<RouteSimulation> {
  const result = (await adminRequest(`/admin/v1/config-revisions/${revisionID}/simulate`, RouteSimulationSchema, { body: simulationBody(input), method: "POST" })).data;
  // A result for another revision or feature is never shown as this one's.
  if (result.revision_id !== revisionID || result.feature !== input.feature) throw new Error("The simulation result didn't match the selected revision and feature.");
  return result;
}

/** The stages of a decision, in the server's order. */
export type Stage = "signed_in" | "app_verified" | "access" | "plan" | "quota" | "route";

export const STAGE_LABEL: Readonly<Record<Stage, string>> = {
  access: "Feature access",
  app_verified: "App verified",
  plan: "Limit plan",
  quota: "Quota reserved",
  route: "Route",
  signed_in: "Signed in"
};

export const STAGES: readonly Stage[] = ["signed_in", "app_verified", "access", "plan", "quota", "route"];

/**
 * Where a denied simulation stopped. The server reports a denial as a fixed sentence
 * (internal/adminapi/simulation_api.go); each one belongs to exactly one stage.
 */
export function deniedAt(result: RouteSimulation): Stage | undefined {
  if (result.allowed) return undefined;
  const text = result.explanation.join(" ");
  if (/Authentication fails/.test(text)) return "signed_in";
  if (/does not define the simulated platform|trust level or attestation provider|not fresh enough/.test(text)) return "app_verified";
  if (/no feature with this identifier|access expression denied/.test(text)) return "access";
  if (/limit-plan expression selected no executable plan/.test(text)) return "plan";
  if (/No executable route matched/.test(text)) return "route";
  return undefined;
}

/** Where to fix a denial. */
export const STAGE_FIX: Readonly<Partial<Record<Stage, { label: string; to: "/attestation" | "/features" | "/plan-by-feature" | "/routes" }>>> = {
  access: { label: "Open Access & limits", to: "/features" },
  app_verified: { label: "Open App verification", to: "/attestation" },
  plan: { label: "Open Plan by feature", to: "/plan-by-feature" },
  route: { label: "Open Routing", to: "/routes" }
};

/** One line for a result: "Allowed · premium · fast on openai" or "Denied at Feature access". */
export function outcomeText(result: RouteSimulation | undefined, error?: unknown): string {
  if (error) return "Not available on this revision";
  if (!result) return "—";
  if (!result.allowed) {
    const stage = deniedAt(result);
    return stage ? `Denied at ${STAGE_LABEL[stage]}` : `Denied: ${result.explanation[0] ?? "no reason given"}`;
  }
  return `Allowed · ${result.limit_plan ?? "no plan"} · ${result.model ?? "?"} on ${result.upstream ?? "?"}`;
}

/** Which stages differ between two results; the trace marks them Changed. */
export function changedStages(left: RouteSimulation | undefined, right: RouteSimulation | undefined): Set<Stage> {
  const changed = new Set<Stage>();
  if (!left || !right) return changed;
  if (deniedAt(left) !== deniedAt(right) || left.allowed !== right.allowed) {
    const stage = deniedAt(left) ?? deniedAt(right);
    if (stage) changed.add(stage);
  }
  if (left.matched_access_expression !== right.matched_access_expression) changed.add("access");
  if (left.limit_plan !== right.limit_plan) changed.add("plan");
  if (JSON.stringify(left.limits ?? []) !== JSON.stringify(right.limits ?? []) || JSON.stringify(left.reservation ?? null) !== JSON.stringify(right.reservation ?? null)) changed.add("quota");
  if (JSON.stringify(left.fallback_sequence ?? []) !== JSON.stringify(right.fallback_sequence ?? [])) changed.add("route");
  return changed;
}

/** "Pretend down": the first step in the fallback sequence whose connection isn't down. Computed here, not by the server. */
export function handlingStep(result: RouteSimulation, down: ReadonlySet<string>): number | undefined {
  const index = (result.fallback_sequence ?? []).findIndex((step) => !down.has(step.upstream));
  return index < 0 ? undefined : index;
}

/** One-change variants for What if. Each is a full input; labels say what changed. */
export function whatIfVariants(input: SimulationInput, planValues: readonly string[]): Array<{ input: SimulationInput; label: string }> {
  const variants: Array<{ input: SimulationInput; label: string }> = [];
  const plan = typeof input.claims.plan === "string" ? input.claims.plan : undefined;
  for (const value of planValues.filter((candidate) => candidate !== plan).slice(0, 3)) {
    variants.push({ input: { ...input, claims: { ...input.claims, plan: value } }, label: `Plan claim is ${value}` });
  }
  if (input.platform !== "web") variants.push({ input: { ...input, platform: "web", trustLevel: "web_risk_verified" }, label: "From the web" });
  if (input.platform !== "android") variants.push({ input: { ...input, platform: "android" }, label: "From Android" });
  const lower = TRUST_ORDER[TRUST_ORDER.indexOf(input.trustLevel) - 1];
  if (lower && input.trustLevel !== "debug") variants.push({ input: { ...input, trustLevel: lower }, label: `Trust one level lower (${TRUST_LABEL[lower]})` });
  variants.push({ input: { ...input, streaming: !input.streaming }, label: input.streaming ? "Not streaming" : "Streaming" });
  variants.push({
    input: { ...input, size: { ...input.size, requested_input_tokens: Math.min(input.size.requested_input_tokens * 4, 100_000_000), rewritten_request_bytes: Math.min(input.size.rewritten_request_bytes * 4, 104_857_600) } },
    label: "A 4× longer prompt"
  });
  if (input.authenticated) variants.push({ input: { ...input, authenticated: false }, label: "Signed out" });
  return variants;
}

/** The equivalent CLI call. Claims go to claims.json through a heredoc, so they stay out of shell history. */
export function cliCommand(revisionID: string, input: SimulationInput): string {
  const flags = [
    `--feature ${input.feature}`,
    `--platform ${input.platform}`,
    `--trust-level ${input.trustLevel}`,
    ...(input.authenticated ? [] : ["--authenticated=false"]),
    ...(input.streaming ? ["--streaming"] : []),
    ...(input.appVersion ? [`--app-version '${input.appVersion.replaceAll("'", "")}'`] : []),
    `--requested-input-tokens ${input.size.requested_input_tokens}`,
    `--requested-output-max ${input.size.requested_output_max}`,
    `--rewritten-request-bytes ${input.size.rewritten_request_bytes}`,
    `--framing-unit-count ${input.size.framing_unit_count}`,
    ...(input.size.expanded_schema_bytes ? [`--expanded-schema-bytes ${input.size.expanded_schema_bytes}`] : []),
    ...(input.size.image_units ? [`--image-units ${input.size.image_units}`] : []),
    ...(input.size.tool_calls ? [`--tool-calls ${input.size.tool_calls}`] : []),
    "--claims-file claims.json",
    "--output json"
  ];
  return [
    "cat > claims.json <<'EOF'",
    JSON.stringify(input.claims, null, 2),
    "EOF",
    `latchway routes simulate ${revisionID} \\`,
    ...flags.map((flag, index) => `  ${flag}${index < flags.length - 1 ? " \\" : ""}`)
  ].join("\n");
}

/** Sample people for spot checks: examples, not taken from traffic. */
export const SAMPLE_PEOPLE: ReadonlyArray<{ claims: Record<string, string | boolean>; label: string; platform: Platform; trust: TrustLevel }> = [
  { claims: { plan: "free" }, label: "Free · iOS", platform: "ios", trust: "app_verified" },
  { claims: { plan: "premium" }, label: "Premium · Android", platform: "android", trust: "app_verified" },
  { claims: { plan: "free" }, label: "Free · Web", platform: "web", trust: "web_risk_verified" },
  { claims: { internal: true, plan: "internal" }, label: "Internal · iOS", platform: "ios", trust: "app_verified" }
];

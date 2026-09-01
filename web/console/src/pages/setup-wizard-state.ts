export interface SetupWizardWorkspace {
  applicationID: string;
  applicationSlug: string;
  clientSurface: "native" | "react_native";
  cloudProjectNumber: string;
  environmentID: string;
  environmentSlug: string;
  plannedSecretName: string;
  selfTestMaximumCostNanoUsd: number;
  upstreamAuthentication: "bearer" | "none";
}

interface ResumeSetupInput {
  applicationID: string;
  applicationSlug: string;
  document: unknown;
  environmentID: string;
  environmentSlug: string;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(record).filter((item): item is Record<string, unknown> => Boolean(item)) : [];
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  const object = record(value);
  if (!object) return value;
  return Object.fromEntries(
    Object.keys(object).sort().map((key) => [key, canonicalValue(object[key])])
  );
}

export function canonicalConfigurationJSON(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

/**
 * Reconstructs only non-secret wizard state from a server-owned configuration
 * revision. Unknown/custom shapes fail closed instead of guessing a provider,
 * secret name, platform surface, or Play project number.
 */
export function resumeSetupWorkspace(input: ResumeSetupInput): SetupWizardWorkspace | undefined {
  const root = record(input.document);
  const spec = record(root?.spec);
  if (!spec) return undefined;

  const definitions = records(spec.componentDefinitions);
  const platforms = new Set(definitions.map((definition) => definition.platform));
  const clientSurface = platforms.has("react_native_ios") && platforms.has("react_native_android")
    ? "react_native"
    : platforms.has("ios") && platforms.has("android")
      ? "native"
      : undefined;
  if (!clientSurface) return undefined;

  let cloudProjectNumber: number | undefined;
  for (const policy of records(spec.attestationPolicies)) {
    const platformMap = record(policy.platforms);
    if (!platformMap) continue;
    for (const selection of Object.values(platformMap)) {
      const project = record(record(selection)?.playIntegrity)?.cloudProjectNumber;
      if (typeof project === "number" && Number.isSafeInteger(project) && project > 0) {
        cloudProjectNumber = project;
      }
    }
  }
  if (cloudProjectNumber === undefined) return undefined;

  const upstream = records(spec.upstreams)[0];
  const authentication = record(upstream?.authentication);
  if (!authentication || (authentication.type !== "bearer" && authentication.type !== "none")) return undefined;
  let plannedSecretName = "";
  if (authentication.type === "bearer") {
    const reference = authentication.secretRef;
    if (typeof reference !== "string" || !/^secret\/[a-z][a-z0-9_-]{0,62}$/.test(reference)) return undefined;
    plannedSecretName = reference.slice("secret/".length);
  }

  return {
    applicationID: input.applicationID,
    applicationSlug: input.applicationSlug,
    clientSurface,
    cloudProjectNumber: String(cloudProjectNumber),
    environmentID: input.environmentID,
    environmentSlug: input.environmentSlug,
    plannedSecretName,
    selfTestMaximumCostNanoUsd: 10_000_000,
    upstreamAuthentication: authentication.type
  };
}

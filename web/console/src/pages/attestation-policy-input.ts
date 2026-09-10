export type AppAttestEnvironment = "development" | "production" | "any";
export type AppleValidationCategory = 2 | 3 | 4 | 5;
export type AppleDistribution = "development" | "testflight" | "app_store" | "ad_hoc_enterprise";

export interface ApplePolicyInput {
  environmentKind: "development" | "staging" | "production";
  appAttestEnvironment?: AppAttestEnvironment;
  appleValidationCategories?: AppleValidationCategory[];
  /** Compatibility for callers of the original singleton builder. */
  appleValidationCategory?: AppleValidationCategory;
  appleDistribution?: AppleDistribution;
  dangerousAllowInProduction?: boolean;
}

const distributionCategories: Record<AppleDistribution, AppleValidationCategory> = {
  development: 3, testflight: 2, app_store: 4, ad_hoc_enterprise: 5
};

export function resolveApplePolicy(input: ApplePolicyInput) {
  const legacyCategory = input.appleValidationCategory ?? (input.appleDistribution === undefined
    ? undefined : distributionCategories[input.appleDistribution]);
  if (input.appleDistribution !== undefined && legacyCategory === undefined) throw new Error("app_attest_distribution_invalid");
  const categories = input.appleValidationCategories ?? (legacyCategory === undefined
    ? input.environmentKind === "development" ? [2, 3] : [4]
    : [legacyCategory]);
  if (!categories.length || categories.some((value) => ![2, 3, 4, 5].includes(value)) || new Set(categories).size !== categories.length) {
    throw new Error("Choose at least one distinct supported Apple distribution category.");
  }
  const environment = input.appAttestEnvironment ?? (legacyCategory === undefined
    ? input.environmentKind === "development" ? "any" : "production"
    : legacyCategory === 3 ? "development" : "production");
  if (!["development", "production", "any"].includes(environment)) throw new Error("Choose an accepted App Attest environment.");
  if (input.environmentKind === "production" && environment !== "production" && !input.dangerousAllowInProduction) {
    throw new Error("app_attest_environment_mismatch: Production environments require an explicit dangerous-policy acknowledgment to accept Apple development attestation.");
  }
  return { environment, allowedValidationCategories: categories };
}

export function requirePlayTestingPolicy(environmentKind: ApplePolicyInput["environmentKind"], allowTestingResponses = false): boolean {
  if (allowTestingResponses && environmentKind !== "development") throw new Error("Google Play testing responses are permitted only in a Development environment.");
  return allowTestingResponses;
}

export function applePolicyFromForm(form: FormData): Pick<ApplePolicyInput, "appAttestEnvironment" | "appleValidationCategories" | "dangerousAllowInProduction"> {
  return {
    appAttestEnvironment: String(form.get("app_attest_environment")) as AppAttestEnvironment,
    appleValidationCategories: form.getAll("apple_validation_categories").map(Number) as AppleValidationCategory[],
    dangerousAllowInProduction: form.get("dangerous_allow_in_production") === "on"
  };
}

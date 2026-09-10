import { describe, expect, it } from "vitest";
import { applePolicyFromForm, requirePlayTestingPolicy, resolveApplePolicy } from "./attestation-policy-input";

describe("provider-specific attestation policy inputs", () => {
  it("defaults only new Development Apple policies to any plus local and TestFlight signing", () => {
    expect(resolveApplePolicy({ environmentKind: "development" })).toEqual({ environment: "any", allowedValidationCategories: [2, 3] });
    for (const environmentKind of ["staging", "production"] as const) {
      expect(resolveApplePolicy({ environmentKind })).toEqual({ environment: "production", allowedValidationCategories: [4] });
    }
  });

  it("keeps legacy singleton inputs exact and independent explicit settings separate", () => {
    expect(resolveApplePolicy({ environmentKind: "development", appleDistribution: "development" })).toEqual({ environment: "development", allowedValidationCategories: [3] });
    expect(resolveApplePolicy({ environmentKind: "development", appleValidationCategory: 2 })).toEqual({ environment: "production", allowedValidationCategories: [2] });
    expect(resolveApplePolicy({ environmentKind: "development", appAttestEnvironment: "any", appleValidationCategories: [2, 4] })).toEqual({ environment: "any", allowedValidationCategories: [2, 4] });
  });

  it.each(["development", "any"] as const)("requires explicit production acknowledgment for %s Apple acceptance", (appAttestEnvironment) => {
    const input = { environmentKind: "production" as const, appAttestEnvironment, appleValidationCategories: [2, 3] as (2 | 3)[] };
    expect(() => resolveApplePolicy(input)).toThrow("app_attest_environment_mismatch");
    expect(() => resolveApplePolicy({ ...input, dangerousAllowInProduction: false })).toThrow("app_attest_environment_mismatch");
    expect(resolveApplePolicy({ ...input, dangerousAllowInProduction: true }).environment).toBe(appAttestEnvironment);
  });

  it("rejects missing or duplicate distribution selections and invalid acceptance values", () => {
    expect(() => resolveApplePolicy({ environmentKind: "development", appleValidationCategories: [] })).toThrow("at least one distinct");
    expect(() => resolveApplePolicy({ environmentKind: "development", appleValidationCategories: [2, 2] })).toThrow("at least one distinct");
    expect(() => resolveApplePolicy({ environmentKind: "development", appAttestEnvironment: "sandbox" as never })).toThrow("accepted App Attest environment");
    expect(() => resolveApplePolicy({ environmentKind: "development", appleValidationCategories: [10] as never })).toThrow("at least one distinct");
  });

  it("defaults Play testing off everywhere and accepts explicit opt-in only in Development", () => {
    for (const environmentKind of ["development", "staging", "production"] as const) expect(requirePlayTestingPolicy(environmentKind)).toBe(false);
    expect(requirePlayTestingPolicy("development", true)).toBe(true);
    expect(() => requirePlayTestingPolicy("staging", true)).toThrow("Development environment");
    expect(() => requirePlayTestingPolicy("production", true)).toThrow("Development environment");
  });

  it("reads each distribution checkbox and does not invent an acknowledgment", () => {
    const form = new FormData();
    form.set("app_attest_environment", "any");
    form.append("apple_validation_categories", "2");
    form.append("apple_validation_categories", "3");
    expect(applePolicyFromForm(form)).toEqual({ appAttestEnvironment: "any", appleValidationCategories: [2, 3], dangerousAllowInProduction: false });
    form.set("dangerous_allow_in_production", "on");
    expect(applePolicyFromForm(form).dangerousAllowInProduction).toBe(true);
  });
});

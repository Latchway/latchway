import { describe, expect, it } from "vitest";

import { buildNativeTemplate } from "./native-template";
import { canonicalConfigurationJSON, resumeSetupWorkspace } from "./setup-wizard-state";

function document(authentication: { type: "bearer"; secretName: string } | { type: "none" } = { type: "bearer", secretName: "primary_api_key" }) {
  return JSON.parse(buildNativeTemplate({
    application: "mobile-app",
    environment: "development",
    environmentKind: "development",
    organization: "example",
    firebaseProject: "example-mobile",
    appIDPrefix: "TEAM1234",
    bundleID: "dev.latchway",
    bundleVersion: "1",
    appleDistribution: "development",
    packageName: "dev.latchway.android",
    clientSurface: "react_native",
    cloudProject: 123456789,
    certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    upstreamURL: "https://fixture.example.test/v1",
    physicalModel: "fixture-model",
    maximumFramingTokensPerRequest: 8,
    maximumFramingTokensPerMessage: 4,
    maximumContextTokens: 4096,
    authentication,
    inputNanoUsdPerMillion: 0,
    outputNanoUsdPerMillion: 0,
    requestNanoUsd: 0,
    dailyInputTokenMaximum: 1000,
    dailyOutputTokenMaximum: 1000,
    dailyTotalTokenMaximum: 2000,
    perRequestInputTokenMaximum: 100
  })) as unknown;
}

describe("server-backed setup wizard state", () => {
  it("reconstructs only non-secret state from the latest canonical revision", () => {
    expect(resumeSetupWorkspace({
      applicationID: "app_01J00000000000000000000000",
      applicationSlug: "mobile-app",
      document: document(),
      environmentID: "env_01J00000000000000000000000",
      environmentSlug: "development"
    })).toEqual({
      applicationID: "app_01J00000000000000000000000",
      applicationSlug: "mobile-app",
      clientSurface: "react_native",
      cloudProjectNumber: "123456789",
      environmentID: "env_01J00000000000000000000000",
      environmentSlug: "development",
      plannedSecretName: "primary_api_key",
      selfTestMaximumCostNanoUsd: 10_000_000,
      upstreamAuthentication: "bearer"
    });
  });

  it("does not reconstruct a secret value and supports explicit no-auth", () => {
    const resumed = resumeSetupWorkspace({
      applicationID: "app_01J00000000000000000000000",
      applicationSlug: "mobile-app",
      document: document({ type: "none" }),
      environmentID: "env_01J00000000000000000000000",
      environmentSlug: "development"
    });
    expect(resumed).toMatchObject({ plannedSecretName: "", upstreamAuthentication: "none" });
    expect(JSON.stringify(resumed)).not.toContain("credential");
  });

  it("fails closed for a custom revision whose surface cannot be proven", () => {
    const candidate = document() as { spec: { componentDefinitions: unknown[] } };
    candidate.spec.componentDefinitions = [];
    expect(resumeSetupWorkspace({
      applicationID: "app_01J00000000000000000000000",
      applicationSlug: "mobile-app",
      document: candidate,
      environmentID: "env_01J00000000000000000000000",
      environmentSlug: "development"
    })).toBeUndefined();
  });

  it("compares configuration documents independently of object key order", () => {
    expect(canonicalConfigurationJSON({ z: [3, { b: 2, a: 1 }], a: true })).toBe(
      canonicalConfigurationJSON({ a: true, z: [3, { a: 1, b: 2 }] })
    );
  });
});

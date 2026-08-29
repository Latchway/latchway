import { describe, expect, it } from "vitest";

import { buildNativeSnippets, buildNativeTemplate } from "./native-template";
import nativeTemplateFixture from "./native-template.fixture.json";

describe("native setup template", () => {
  it("binds all native platforms and trusted Responses accounting", () => {
    const document = JSON.parse(buildNativeTemplate({
      application: "mobile-app",
      environment: "production",
      organization: "example",
      firebaseProject: "example-mobile",
      appIDPrefix: "TEAM1234",
      bundleID: "com.example.mobile",
      bundleVersion: "2.3.4",
      packageName: "com.example.mobile",
      cloudProject: 123456789,
      certificateDigest: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      upstreamURL: "https://api.openai.com/v1",
      physicalModel: "operator-reviewed-model",
      maximumFramingTokensPerRequest: 13,
      maximumFramingTokensPerMessage: 7,
      maximumContextTokens: 131072
    })) as {
      spec: {
        attestationPolicies: Array<{ platforms: Record<string, unknown> }>;
        inputAccountingProfiles: Array<Record<string, unknown>>;
        models: Array<Record<string, unknown>>;
        limitPlans: Array<{ limits: Array<Record<string, unknown>> }>;
      };
    };

    expect(document).toEqual(nativeTemplateFixture);
    expect(Object.keys(document.spec.attestationPolicies[0]?.platforms ?? {}).sort()).toEqual([
      "android", "ios", "react_native_android", "react_native_ios"
    ]);
    expect(document.spec.attestationPolicies[0]?.platforms).toMatchObject({
      ios: { minimumTrustLevel: "app_verified", appAttest: { allowedBundleVersions: ["2.3.4"] } },
      android: { minimumTrustLevel: "device_verified" },
      react_native_ios: { minimumTrustLevel: "app_verified", appAttest: { allowedBundleVersions: ["2.3.4"] } },
      react_native_android: { minimumTrustLevel: "device_verified" }
    });
    expect(document.spec.inputAccountingProfiles).toEqual([{
      id: "assistant_default_responses_accounting",
      protocol: "openai_responses",
      method: "utf8_byte_bpe_declared_framing_v1",
      physicalModel: "operator-reviewed-model",
      maximumFramingTokensPerRequest: 13,
      maximumFramingTokensPerMessage: 7,
      maximumContextTokens: 131072
    }]);
    expect(document.spec.models).toEqual([{
      id: "assistant_default",
      upstream: "primary",
      upstreamModel: "operator-reviewed-model",
      capabilities: ["openai_responses"],
      inputAccountingRef: "assistant_default_responses_accounting"
    }]);
    expect(document.spec.limitPlans[0]?.limits).toContainEqual(expect.objectContaining({
      metric: "input_tokens", algorithm: "per_request", hard: true
    }));
  });

  it("emits a runnable React Native configuration and matching first request", () => {
    const snippets = buildNativeSnippets({
      applicationID: "app_01J00000000000000000000000",
      cloudProjectNumber: "123456789",
      environmentSlug: "production"
    });
    expect(snippets.reactNative).toContain('identityProvider: "firebase"');
    expect(snippets.reactNative).toContain('playIntegrityCloudProjectNumber: "123456789"');
    expect(snippets.reactNative).toContain("latchway.fetch" + '("/v1/responses"');
    expect(snippets.reactNative).toContain('latchwayFeature: "assistant"');
    expect(Object.values(snippets).every((snippet) =>
      snippet.includes("app_01J00000000000000000000000"))).toBe(true);
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

import {
  applyConfigurationSliceChange,
  configurationAreas,
  deleteAreaResource,
  listAreaResources,
  upsertAreaResource,
  type JSONRecord
} from "./configuration-slice";

const instant = "2026-08-29T00:00:00Z";
const ids = {
  active: "rev_0123456789abcdef",
  draft: "rev_1123456789abcdef",
  environment: "env_0123456789abcdef"
};

function documentFixture(): JSONRecord {
  return {
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: { application: "mobile", environment: "production", labels: { owner: "mobile" }, organization: "example" },
    spec: {
      attestationPolicies: [{ id: "native", platforms: { react_native_ios: { appAttest: { allowedBundleVersions: ["1.0.0"], allowedValidationCategories: [1], appIdPrefix: "TEAMID", bundleId: "com.example.app", environment: "production" }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" } } }],
      features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "assistant", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ fallbackOn: [], id: "primary", model: "assistant_default", priority: 10, weight: 100, when: "true" }] }],
      identityProviders: [{ id: "firebase", projectId: "example-mobile", type: "firebase" }],
      inputAccountingProfiles: [{ id: "input_default", maximumContextTokens: 128000, maximumFramingTokensPerMessage: 4, maximumFramingTokensPerRequest: 8, method: "utf8_byte_bpe_declared_framing_v1", physicalModel: "gpt-5-mini", protocol: "openai_responses" }],
      limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], timezone: "UTC", window: "1d" }] }],
      models: [{ capabilities: ["openai_responses"], id: "assistant_default", inputAccountingRef: "input_default", upstream: "openai", upstreamModel: "gpt-5-mini" }],
      pricingCatalogs: [{ currency: "USD", effectiveAt: instant, entries: [{ inputNanoUsdPerMillion: 1, model: "assistant_default", outputNanoUsdPerMillion: 2, requestNanoUsd: 0 }], id: "pricing" }],
      privacy: { requestBodyLogging: false, responseBodyLogging: false },
      session: { accessTokenTtl: "5m", refreshTokenTtl: "30d" },
      upstreams: [{ authentication: { secretRef: "secret/primary_api_key", type: "bearer" }, baseUrl: "https://api.openai.com/v1", id: "openai", type: "openai_compatible" }]
    }
  };
}

function revision(id: string, document: JSONRecord, state: "active" | "draft" = "draft") {
  return { created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: ids.environment, id, state, version: state === "active" ? 1 : 2 };
}

beforeEach(() => { adminRequestMock.mockReset(); });

describe("targeted configuration slice editing", () => {
  it("replaces one upstream while preserving every unrelated document slice", () => {
    const original = documentFixture();
    const upstreams = configurationAreas.upstreams.collections[0];
    if (!upstreams) throw new Error("missing upstream collection");
    const candidate = { ...listAreaResources(original, upstreams)[0]?.value, baseUrl: "https://gateway.example.test/v1" };
    const updated = upsertAreaResource(original, upstreams, "openai", candidate).document;
    const before = original.spec as JSONRecord; const after = updated.spec as JSONRecord;

    expect((after.upstreams as JSONRecord[])[0]?.baseUrl).toBe("https://gateway.example.test/v1");
    for (const key of Object.keys(before).filter((key) => key !== "upstreams")) expect(after[key]).toEqual(before[key]);
    expect((original.spec as JSONRecord).upstreams).toEqual([{ authentication: { secretRef: "secret/primary_api_key", type: "bearer" }, baseUrl: "https://api.openai.com/v1", id: "openai", type: "openai_compatible" }]);
  });

  it("replaces and deletes nested routes without changing access or sibling feature fields", () => {
    const original = documentFixture(); const routes = configurationAreas.routes.collections[0];
    if (!routes) throw new Error("missing route collection");
    const candidate = { feature_id: "assistant", route: { fallbackOn: ["server_error"], id: "primary", model: "assistant_default", priority: 10, weight: 75, when: "true" } };
    const updated = upsertAreaResource(original, routes, "assistant/primary", candidate).document;
    const feature = ((updated.spec as JSONRecord).features as JSONRecord[])[0];

    expect((feature?.routes as JSONRecord[])[0]?.weight).toBe(75);
    expect(feature?.access).toEqual({ expression: "principal.authenticated" });
    expect(feature?.limitPlan).toEqual({ expression: "'free'" });
    expect(deleteAreaResource(updated, routes, "assistant/primary")).toMatchObject({ spec: { features: [{ access: { expression: "principal.authenticated" }, routes: [] }] } });
  });

  it("updates abuse composition while preserving routes and every global resource", () => {
    const original = documentFixture(); const abuse = configurationAreas.abuse.collections[0];
    if (!abuse) throw new Error("missing abuse collection");
    const candidate = { access: { expression: "principal.authenticated && principal.claims.plan == 'paid'" }, attestationPolicy: "native", feature_id: "assistant", limitPlan: { expression: "'free'" } };
    const updated = upsertAreaResource(original, abuse, "assistant", candidate).document;
    const before = original.spec as JSONRecord; const after = updated.spec as JSONRecord;
    const beforeFeature = (before.features as JSONRecord[])[0]; const afterFeature = (after.features as JSONRecord[])[0];

    expect(afterFeature?.access).toEqual(candidate.access);
    expect(afterFeature?.routes).toEqual(beforeFeature?.routes);
    for (const key of Object.keys(before).filter((key) => key !== "features")) expect(after[key]).toEqual(before[key]);
  });

  it("uses the exact active base and newest draft ETag through activation", async () => {
    const document = documentFixture(); const draft = revision(ids.draft, document);
    adminRequestMock
      .mockResolvedValueOnce({ data: draft, etag: '"draft-etag-1"' })
      .mockResolvedValueOnce({ data: draft, etag: '"draft-etag-2"' })
      .mockResolvedValueOnce({ data: { checked_at: instant, issues: [], valid: true } })
      .mockResolvedValueOnce({ data: { changes: [{ operation: "replace", path: "/spec/upstreams/0/baseUrl" }], from_revision_id: ids.active, to_revision_id: ids.draft, warnings: [] } })
      .mockResolvedValueOnce({ data: revision(ids.draft, document, "active"), etag: '"active-etag-3"' });

    const result = await applyConfigurationSliceChange({ activate: true, description: "targeted upstream edit", document, environmentID: ids.environment, sourceRevisionID: ids.active });

    expect(adminRequestMock.mock.calls[0]).toEqual([`/admin/v1/environments/${ids.environment}/config-revisions`, expect.anything(), { body: { base_revision_id: ids.active, description: "targeted upstream edit" }, method: "POST" }]);
    expect(adminRequestMock.mock.calls[1]?.[2]).toEqual({ body: document, etag: '"draft-etag-1"', method: "PATCH" });
    expect(adminRequestMock.mock.calls[4]?.[2]).toEqual({ etag: '"draft-etag-2"', method: "POST" });
    expect(result.etag).toBe('"active-etag-3"');
  });

  it("provides canonical schema-shaped templates and preserves them through an add/list round trip", () => {
    const document = documentFixture();
    const templates = {
      abuse: configurationAreas.abuse.collections[0]?.template,
      access: configurationAreas.access.collections[0]?.template,
      attestation: configurationAreas.attestation.collections[0]?.template,
      feature: configurationAreas.features.collections[0]?.template,
      identity: configurationAreas.identity.collections[0]?.template,
      inputProfile: configurationAreas.modelsPricing.collections[1]?.template,
      limitPlan: configurationAreas.limits.collections[0]?.template,
      model: configurationAreas.modelsPricing.collections[0]?.template,
      pricing: configurationAreas.modelsPricing.collections[2]?.template,
      route: configurationAreas.routes.collections[0]?.template,
      upstream: configurationAreas.upstreams.collections[0]?.template
    };

    expect(templates.upstream).toEqual({ authentication: { type: "none" }, baseUrl: "https://api.example.test/v1", id: "new_upstream", type: "openai_compatible" });
    expect(templates.model).toEqual({ capabilities: ["openai_responses"], id: "new_model", upstream: "primary", upstreamModel: "replace-me" });
    expect(templates.route).toEqual({ feature_id: "assistant", route: { fallbackOn: [], id: "new_route", model: "assistant_default", priority: 10, weight: 1, when: "true" } });
    expect(templates.feature).toEqual({ access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "new_feature", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "assistant_default", priority: 10, when: "true" }] });
    expect(templates.limitPlan).toEqual({ id: "new_limit_plan", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], timezone: "UTC", window: "1d" }] });
    expect(templates.pricing).toEqual({ currency: "USD", entries: [{ inputNanoUsdPerMillion: 0, model: "assistant_default", outputNanoUsdPerMillion: 0, requestNanoUsd: 0 }], id: "new_pricing_catalog" });
    expect(templates.inputProfile).toEqual({ id: "new_input_profile", maximumContextTokens: 128000, maximumFramingTokensPerMessage: 4, maximumFramingTokensPerRequest: 8, method: "utf8_byte_bpe_declared_framing_v1", physicalModel: "replace-me", protocol: "openai_responses" });
    expect(templates.identity).toEqual({ id: "new_identity_provider", projectId: "replace-me", type: "firebase" });
    expect(templates.access).toEqual({ access: { expression: "principal.authenticated" }, feature_id: "assistant" });
    expect(templates.abuse).toEqual({ access: { expression: "principal.authenticated" }, attestationPolicy: "native", feature_id: "assistant", limitPlan: { expression: "'free'" } });
    expect(templates.attestation).toEqual({ id: "new_attestation_policy", platforms: { react_native_ios: { appAttest: { allowedBundleVersions: ["1.0.0"], allowedValidationCategories: [1], appIdPrefix: "TEAMID", bundleId: "com.example.app", environment: "production" }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" } } });

    const upstreams = configurationAreas.upstreams.collections[0];
    if (!upstreams || !templates.upstream) throw new Error("missing upstream template");
    const added = upsertAreaResource(document, upstreams, undefined, templates.upstream).document;
    expect(listAreaResources(added, upstreams).find((resource) => resource.key === "new_upstream")?.value).toEqual(templates.upstream);
    expect((added.spec as JSONRecord).features).toEqual((document.spec as JSONRecord).features);
  });

  it("fails closed before draft replacement when the clone ETag is weak", async () => {
    const document = documentFixture();
    adminRequestMock.mockResolvedValueOnce({ data: revision(ids.draft, document), etag: 'W/"stale"' });
    await expect(applyConfigurationSliceChange({ activate: true, description: "targeted edit", document, environmentID: ids.environment, sourceRevisionID: ids.active })).rejects.toThrow("strong ETag");
    expect(adminRequestMock).toHaveBeenCalledTimes(1);
  });

  it("stops before validation, planning, or activation when the server rejects the draft ETag as stale", async () => {
    const document = documentFixture();
    adminRequestMock
      .mockResolvedValueOnce({ data: revision(ids.draft, document), etag: '"draft-etag-1"' })
      .mockRejectedValueOnce(new Error("configuration_revision_conflict"));

    await expect(applyConfigurationSliceChange({ activate: true, description: "targeted edit", document, environmentID: ids.environment, sourceRevisionID: ids.active })).rejects.toThrow("configuration_revision_conflict");
    expect(adminRequestMock).toHaveBeenCalledTimes(2);
    expect(adminRequestMock.mock.calls[1]?.[2]).toEqual({ body: document, etag: '"draft-etag-1"', method: "PATCH" });
  });
});

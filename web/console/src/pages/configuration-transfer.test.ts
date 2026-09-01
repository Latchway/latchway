import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  activateConfigurationImport,
  maximumConfigurationImportBytes,
  parseConfigurationDocument,
  readConfigurationFile,
  redactionSafeConfigurationYAML,
  stageConfigurationImport
} from "./configuration-transfer";

const mocks = vi.hoisted(() => ({ adminRequest: vi.fn(), createValidateActivate: vi.fn() }));

vi.mock("../api/admin", async (load) => {
  const actual = await load<typeof import("../api/admin")>();
  return { ...actual, adminRequest: mocks.adminRequest };
});

vi.mock("./setup-wizard-api", () => ({
  createValidateActivate: mocks.createValidateActivate
}));

describe("configuration transfer", () => {
  beforeEach(() => {
    mocks.adminRequest.mockReset();
    mocks.createValidateActivate.mockReset();
  });

  it("parses duplicate-key-safe YAML and JSON into prototype-free objects", () => {
    const yaml = parseConfigurationDocument("apiVersion: latchway.dev/v1alpha1\nspec:\n  enabled: true\n  weights: [1, 2]\n");
    const json = parseConfigurationDocument('{"apiVersion":"latchway.dev/v1alpha1","spec":{"enabled":true}}');

    expect(yaml).toEqual({ apiVersion: "latchway.dev/v1alpha1", spec: { enabled: true, weights: [1, 2] } });
    expect(Object.getPrototypeOf(yaml)).toBeNull();
    expect(Object.getPrototypeOf(yaml.spec)).toBeNull();
    expect(Object.getPrototypeOf(json)).toBeNull();
  });

  it.each([
    ["multiple documents", "a: 1\n---\nb: 2"],
    ["aliases", "a: &shared 1\nb: *shared"],
    ["custom tags", "a: !unsafe 1"],
    ["merge keys", "<<: {a: 1}"],
    ["duplicate keys", "a: 1\na: 2"],
    ["non-finite values", "a: .nan"],
    ["unsafe integers", "a: 9007199254740993"],
    ["implicit timestamps", "created: 2026-09-01T12:00:00Z"],
    ["prototype pollution keys", "__proto__: unsafe"],
    ["constructor keys", "constructor: unsafe"],
    ["a top-level sequence", "- one\n- two"]
  ])("rejects %s", (_case, source) => {
    expect(() => parseConfigurationDocument(source)).toThrow();
  });

  it("enforces the one-MiB UTF-8 boundary", () => {
    const overLimit = `value: ${"é".repeat(Math.floor(maximumConfigurationImportBytes / 2))}`;
    expect(() => parseConfigurationDocument(overLimit)).toThrow("cannot exceed 1 MiB");
  });

  it("rejects oversized or malformed UTF-8 files before parsing", async () => {
    const oversized = new File([new Uint8Array(maximumConfigurationImportBytes + 1)], "too-large.yaml");
    const malformed = new File([new Uint8Array([0xff, 0xfe])], "malformed.yaml");
    await expect(readConfigurationFile(oversized)).rejects.toThrow("cannot exceed 1 MiB");
    await expect(readConfigurationFile(malformed)).rejects.toThrow("valid UTF-8");
  });

  it("exports deterministic YAML with references but no anchors", () => {
    const output = redactionSafeConfigurationYAML({
      spec: { upstreams: [{ authentication: { secretRef: "secret/provider", type: "bearer" }, id: "provider" }] },
      apiVersion: "latchway.dev/v1alpha1"
    });

    expect(output).toContain("apiVersion: latchway.dev/v1alpha1");
    expect(output).toContain("secretRef: secret/provider");
    expect(output).not.toMatch(/[&*][A-Za-z0-9_-]+/);
    expect(output.indexOf("apiVersion")).toBeLessThan(output.indexOf("spec"));
  });

  it("fails closed on raw credential-shaped fields or prototype-bearing input", () => {
    expect(() => redactionSafeConfigurationYAML({ spec: { apiKey: "not-safe" } })).toThrow("cannot be exported safely");
    expect(() => redactionSafeConfigurationYAML({ spec: { providerCredential: "not-safe" } })).toThrow("cannot be exported safely");
    expect(() => redactionSafeConfigurationYAML(new Date())).toThrow("Prototype-bearing objects");
  });

  it("stages through validation and activates only the exact reviewed immutable revision", async () => {
    const document = parseConfigurationDocument("apiVersion: latchway.dev/v1alpha1");
    const result = {
      report: { checked_at: "2026-09-01T00:00:00Z", issues: [], valid: true },
      revision: {
        created_at: "2026-09-01T00:00:00Z",
        created_by: "adm_fixture",
        document,
        environment_id: "env_fixture",
        id: "rev_fixture",
        state: "valid" as const,
        version: 1
      }
    };
    mocks.createValidateActivate.mockResolvedValue(result);
    mocks.adminRequest
      .mockResolvedValueOnce({ data: result.revision, etag: '"reviewed-etag"' })
      .mockResolvedValueOnce({ data: { ...result.revision, state: "active" }, etag: '"active-etag"' });

    await expect(stageConfigurationImport({ document, environmentID: "env_fixture" })).resolves.toBe(result);
    await expect(activateConfigurationImport({
      document,
      environmentID: "env_fixture",
      staged: result
    })).resolves.toEqual({ ...result, revision: { ...result.revision, state: "active" } });

    expect(mocks.createValidateActivate).toHaveBeenCalledOnce();
    expect(mocks.createValidateActivate).toHaveBeenCalledWith({
      activate: false,
      document,
      environmentID: "env_fixture"
    });
    expect(mocks.adminRequest).toHaveBeenNthCalledWith(
      1,
      "/admin/v1/config-revisions/rev_fixture",
      expect.anything()
    );
    expect(mocks.adminRequest).toHaveBeenNthCalledWith(
      2,
      "/admin/v1/config-revisions/rev_fixture/activate",
      expect.anything(),
      { etag: '"reviewed-etag"', method: "POST" }
    );
  });

  it("fails closed instead of activating a changed or superseded reviewed revision", async () => {
    const document = parseConfigurationDocument("apiVersion: latchway.dev/v1alpha1");
    const staged = {
      report: { checked_at: "2026-09-01T00:00:00Z", issues: [], valid: true },
      revision: {
        created_at: "2026-09-01T00:00:00Z", created_by: "adm_fixture", document,
        environment_id: "env_fixture", id: "rev_fixture", state: "valid" as const, version: 1
      }
    };
    mocks.adminRequest.mockResolvedValue({
      data: { ...staged.revision, state: "superseded" }, etag: '"stale-etag"'
    });

    await expect(activateConfigurationImport({ document, environmentID: "env_fixture", staged }))
      .rejects.toThrow("no longer activatable");
    expect(mocks.adminRequest).toHaveBeenCalledTimes(1);
  });
});

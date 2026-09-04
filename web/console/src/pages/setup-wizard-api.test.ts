import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

import {
  createValidateActivate,
  findApplication,
  findOrCreateApplication,
  findOrCreateEnvironment
} from "./setup-wizard-api";

const instant = "2026-09-04T00:00:00Z";
const ids = {
  application: "app_01J00000000000000000000000",
  environment: "env_01J00000000000000000000000",
  organization: "org_01J00000000000000000000000",
  revision: "rev_01J00000000000000000000000",
  siblingApplication: "app_02J00000000000000000000000",
  siblingEnvironment: "env_02J00000000000000000000000",
  siblingOrganization: "org_02J00000000000000000000000",
  siblingRevision: "rev_02J00000000000000000000000"
};

const document = {
  apiVersion: "latchway.dev/v1alpha1",
  kind: "EnvironmentConfig",
  metadata: { application: "mobile", environment: "development", organization: "latchway" },
  spec: {}
};

const validReport = { checked_at: instant, issues: [], valid: true };

function application(overrides: Record<string, unknown> = {}) {
  return {
    created_at: instant,
    display_name: "Mobile",
    id: ids.application,
    organization_id: ids.organization,
    slug: "mobile",
    status: "active" as const,
    ...overrides
  };
}

function environment(overrides: Record<string, unknown> = {}) {
  return {
    application_id: ids.application,
    created_at: instant,
    display_name: "Development",
    id: ids.environment,
    kind: "development" as const,
    slug: "development",
    status: "active" as const,
    ...overrides
  };
}

function revision(overrides: Record<string, unknown> = {}) {
  return {
    created_at: instant,
    created_by: "adm_01J00000000000000000000000",
    document,
    environment_id: ids.environment,
    id: ids.revision,
    state: "valid" as const,
    validation: validReport,
    version: 1,
    ...overrides
  };
}

beforeEach(() => adminRequestMock.mockReset());

describe("setup wizard API context binding", () => {
  it("rejects an application page containing a resource from another organization", async () => {
    adminRequestMock.mockResolvedValue({
      data: { items: [application({ organization_id: ids.siblingOrganization })], page: { has_more: false } }
    });

    await expect(findApplication(ids.organization, "mobile")).rejects.toThrow("application_context_mismatch");
  });

  it("rejects a create-application response that does not exactly match the requested parent and identity", async () => {
    adminRequestMock
      .mockResolvedValueOnce({ data: { items: [], page: { has_more: false } } })
      .mockResolvedValueOnce({ data: application({ slug: "other" }) });

    await expect(findOrCreateApplication({
      displayName: "Mobile",
      organizationID: ids.organization,
      slug: "mobile"
    })).rejects.toThrow("application_context_mismatch");
  });

  it("rejects an environment list containing a resource from another application", async () => {
    adminRequestMock.mockResolvedValue({
      data: { items: [environment({ application_id: ids.siblingApplication })] }
    });

    await expect(findOrCreateEnvironment({
      applicationID: ids.application,
      displayName: "Development",
      kind: "development",
      slug: "development"
    })).rejects.toThrow("environment_context_mismatch");
  });

  it("rejects a create-environment response that does not exactly match the requested parent and identity", async () => {
    adminRequestMock
      .mockResolvedValueOnce({ data: { items: [] } })
      .mockResolvedValueOnce({ data: environment({ kind: "production" }) });

    await expect(findOrCreateEnvironment({
      applicationID: ids.application,
      displayName: "Development",
      kind: "development",
      slug: "development"
    })).rejects.toThrow("environment_context_mismatch");
  });

  it("rejects a latest revision from a sibling environment before reuse or creation", async () => {
    adminRequestMock.mockResolvedValue({
      data: { items: [revision({ environment_id: ids.siblingEnvironment })], page: { has_more: false } }
    });

    await expect(createValidateActivate({ activate: true, document, environmentID: ids.environment }))
      .rejects.toThrow("configuration_revision_context_mismatch");
    expect(adminRequestMock).toHaveBeenCalledOnce();
  });

  it.each([
    ["environment", { environment_id: ids.siblingEnvironment }],
    ["document", { document: { ...document, kind: "OtherConfig" } }],
    ["revision ID shape", { id: "app_01J00000000000000000000000" }]
  ])("rejects a newly created revision with a mismatched %s", async (_case, mutation) => {
    adminRequestMock
      .mockResolvedValueOnce({ data: { items: [], page: { has_more: false } } })
      .mockResolvedValueOnce({ data: revision(mutation) });

    await expect(createValidateActivate({ activate: true, document, environmentID: ids.environment }))
      .rejects.toThrow("configuration_revision_context_mismatch");
    expect(adminRequestMock).toHaveBeenCalledTimes(2);
  });

  it.each([
    ["environment", { environment_id: ids.siblingEnvironment }],
    ["document", { document: { ...document, kind: "OtherConfig" } }],
    ["revision ID", { id: ids.siblingRevision }]
  ])("rejects a reusable revision GET with a mismatched %s", async (_case, mutation) => {
    adminRequestMock
      .mockResolvedValueOnce({ data: { items: [revision()], page: { has_more: false } } })
      .mockResolvedValueOnce({ data: revision(mutation), etag: '"revision-1"' });

    await expect(createValidateActivate({ activate: true, document, environmentID: ids.environment }))
      .rejects.toThrow("configuration_revision_context_mismatch");
    expect(adminRequestMock).toHaveBeenCalledTimes(2);
  });

  it("rejects a validation plan bound to another target revision", async () => {
    adminRequestMock
      .mockResolvedValueOnce({ data: { items: [], page: { has_more: false } } })
      .mockResolvedValueOnce({ data: revision() })
      .mockResolvedValueOnce({ data: validReport })
      .mockResolvedValueOnce({ data: {
        changes: [], from_revision_id: ids.siblingRevision, to_revision_id: ids.siblingRevision, warnings: []
      } });

    await expect(createValidateActivate({ activate: true, document, environmentID: ids.environment }))
      .rejects.toThrow("configuration_plan_context_mismatch");
    expect(adminRequestMock).toHaveBeenCalledTimes(4);
  });

  it("rejects a changed revision immediately before activation", async () => {
    adminRequestMock
      .mockResolvedValueOnce({ data: { items: [], page: { has_more: false } } })
      .mockResolvedValueOnce({ data: revision() })
      .mockResolvedValueOnce({ data: validReport })
      .mockResolvedValueOnce({ data: {
        changes: [], from_revision_id: ids.siblingRevision, to_revision_id: ids.revision, warnings: []
      } })
      .mockResolvedValueOnce({ data: revision({ document: { ...document, kind: "OtherConfig" } }), etag: '"revision-1"' });

    await expect(createValidateActivate({ activate: true, document, environmentID: ids.environment }))
      .rejects.toThrow("configuration_revision_context_mismatch");
    expect(adminRequestMock).toHaveBeenCalledTimes(5);
  });

  it.each([
    ["environment", { environment_id: ids.siblingEnvironment }],
    ["document", { document: { ...document, kind: "OtherConfig" } }],
    ["revision ID", { id: ids.siblingRevision }],
    ["state", { state: "valid" }]
  ])("rejects an activation response with a mismatched %s", async (_case, mutation) => {
    adminRequestMock
      .mockResolvedValueOnce({ data: { items: [], page: { has_more: false } } })
      .mockResolvedValueOnce({ data: revision() })
      .mockResolvedValueOnce({ data: validReport })
      .mockResolvedValueOnce({ data: {
        changes: [], from_revision_id: ids.siblingRevision, to_revision_id: ids.revision, warnings: []
      } })
      .mockResolvedValueOnce({ data: revision(), etag: '"revision-1"' })
      .mockResolvedValueOnce({ data: revision({ state: "active", ...mutation }) });

    await expect(createValidateActivate({ activate: true, document, environmentID: ids.environment }))
      .rejects.toThrow(_case === "state" ? "configuration_activation_context_mismatch" : "configuration_revision_context_mismatch");
    expect(adminRequestMock).toHaveBeenCalledTimes(6);
  });
});

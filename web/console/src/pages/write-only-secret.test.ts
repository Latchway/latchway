import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

import { resolveWriteOnlySecret } from "./write-only-secret";
import { AdminRequestError } from "../api/auth";

const metadata = {
  algorithm: "AES-256-GCM",
  created_at: "2026-09-01T00:00:00Z",
  environment_id: "env_0123456789abcdef",
  id: "sec_0123456789abcdef",
  master_key_id: "primary",
  name: "provider_api_key",
  version: 1
};

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("write-only secret metadata reconciliation", () => {
  it("requires explicit confirmation when a create name already exists", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [metadata], page: { has_more: false } } });

    const result = await resolveWriteOnlySecret({
      action: "create",
      environmentID: metadata.environment_id,
      name: metadata.name,
      value: "must-not-be-compared"
    });

    expect(result).toEqual({ metadata, outcome: "confirmation_required", reason: "already_exists" });
    expect(adminRequestMock.mock.calls.some(([, , options]) => options?.method === "POST")).toBe(false);
    expect(JSON.stringify(result)).not.toContain("must-not-be-compared");
  });

  it("reconciles an indeterminate create only to metadata and still requires confirmation", async () => {
    let reads = 0;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        reads += 1;
        return Promise.resolve({ data: { items: reads === 1 ? [] : [metadata], page: { has_more: false } } });
      }
      if (path === "/admin/v1/secrets" && options?.method === "POST") return Promise.reject(new AdminRequestError({
        code: "operation_indeterminate",
        detail: "response lost",
        operationId: "arq_00000000000000000000000000",
        requestId: "request_test_1234",
        retryable: true,
        status: 503,
        title: "Operation outcome unknown"
      }));
      throw new Error(`unexpected request ${path}`);
    });

    const result = await resolveWriteOnlySecret({
      action: "create",
      environmentID: metadata.environment_id,
      name: metadata.name,
      value: "indeterminate-value"
    });

    expect(result).toEqual({ metadata, operationId: "arq_00000000000000000000000000", outcome: "confirmation_required", reason: "create_response_indeterminate" });
    expect(reads).toBe(2);
    expect(JSON.stringify(result)).not.toContain("indeterminate-value");
  });

  it("uses an exact existing named secret without issuing a create", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [metadata], page: { has_more: false } } });

    const result = await resolveWriteOnlySecret({
      action: "use_existing",
      environmentID: metadata.environment_id,
      name: metadata.name
    });

    expect(result).toEqual({ metadata, outcome: "existing" });
    expect(adminRequestMock.mock.calls.some(([, , options]) => options?.method === "POST")).toBe(false);
  });
});

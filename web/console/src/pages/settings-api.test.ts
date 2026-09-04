import { describe, expect, it, vi } from "vitest";

import {
  AdminSessionMetadataPageSchema,
  adminRequest,
  NoContentSchema,
  SystemStatusSchema
} from "../api/admin";
import { requiredSettingsServerCapabilities } from "./settings-compatibility";

describe("Settings canonical Admin API contracts", () => {
  it("accepts capability negotiation extensions while rejecting duplicates", () => {
    const status = {
      contract_version: "1.0.0",
      database_schema_version: "27",
      mutation_ready: true,
      protocol_versions: [1, 2],
      ready: true,
      role: "all",
      server_capabilities: [...requiredSettingsServerCapabilities, "admin_event_stream"],
      server_version: "1.0.0"
    };
    expect(SystemStatusSchema.parse(status).server_capabilities).toContain("admin_event_stream");
    expect(() => SystemStatusSchema.parse({
      ...status,
      server_capabilities: [...status.server_capabilities, "admin_event_stream"]
    })).toThrow();
  });

  it("validates only credential-free administrator session metadata", () => {
    const page = {
      items: [{
        administrator: { email: "owner@example.test", id: "adm_0123456789abcdef" },
        created_at: "2026-08-29T00:00:00Z",
        current: true,
        expires_at: "2026-09-02T00:00:00Z",
        id: "asn_0123456789abcdef",
        last_seen_at: "2026-09-01T00:00:00Z",
        status: "active"
      }],
      page: { has_more: false }
    };
    expect(AdminSessionMetadataPageSchema.parse(page)).toEqual(page);
    expect(() => AdminSessionMetadataPageSchema.parse({
      ...page,
      items: [{ ...page.items[0], credential: "must-never-be-returned" }]
    })).toThrow();
  });

  it("accepts only an empty 204 body from the canonical revoke endpoint", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 204 })) as unknown as typeof fetch;
    await expect(adminRequest(
      "/admin/v1/admin-sessions/asn_0123456789abcdef/revoke",
      NoContentSchema,
      { bearerToken: "test-only-bearer-token-material-0123456789", method: "POST" },
      fetcher
    )).resolves.toEqual({ data: undefined });
    expect(fetcher).toHaveBeenCalledWith(
      "/admin/v1/admin-sessions/asn_0123456789abcdef/revoke",
      expect.objectContaining({ credentials: "omit", method: "POST" })
    );
  });
});

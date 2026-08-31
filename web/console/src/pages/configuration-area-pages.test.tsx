import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration"], organization_id: "org_0123456789abcdef" } } })
}));

import { ConfigurationAreaEditor } from "./configuration-area-pages";
import { configurationAreas, type JSONRecord } from "./configuration-slice";

const environment = "env_0123456789abcdef";
const activeID = "rev_0123456789abcdef";
const draftID = "rev_1123456789abcdef";
const instant = "2026-08-29T00:00:00Z";

function documentFixture(): JSONRecord {
  return {
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: { application: "mobile", environment: "production", labels: { retained: "yes" }, organization: "example" },
    spec: {
      attestationPolicies: [{ id: "native", platforms: { react_native_ios: { appAttest: { allowedBundleVersions: ["1"], allowedValidationCategories: [4], appIdPrefix: "TEAMID", bundleId: "com.example.app", environment: "production" }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" } } }],
      features: [{ access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "assistant", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "assistant", priority: 10, weight: 1, when: "true" }] }],
      identityProviders: [{ id: "firebase", projectId: "example-mobile", type: "firebase" }],
      limitPlans: [{ id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], timezone: "UTC", window: "1d" }] }],
      models: [{ capabilities: ["openai_responses"], id: "assistant", upstream: "openai", upstreamModel: "gpt-5-mini" }],
      upstreams: [{ authentication: { type: "none" }, baseUrl: "https://api.openai.com/v1", id: "openai", type: "openai_compatible" }]
    }
  };
}

function revision(id: string, document: JSONRecord, state: "active" | "draft", version: number) {
  return { activated_at: state === "active" ? instant : undefined, created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: environment, id, state, version };
}

beforeEach(() => { adminRequestMock.mockReset(); });

describe("dedicated configuration area editor", () => {
  it("cancels a staged deletion without changing the resource or calling a mutation", async () => {
    const user = userEvent.setup(); const document = documentFixture();
    adminRequestMock.mockResolvedValue({ data: revision(activeID, document, "active", 1), etag: '"active-etag"' });
    render(<ConfigurationAreaEditor definition={configurationAreas.upstreams} />);
    await user.type(screen.getByLabelText("Environment ID"), environment);
    await user.click(screen.getByRole("button", { name: "Load active configuration" }));
    await screen.findByRole("button", { name: "Delete openai" });

    await user.click(screen.getByRole("button", { name: "Delete openai" }));
    expect(screen.getByRole("button", { name: "Stage resource deletion" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Cancel deletion" }));

    expect(screen.queryByRole("heading", { name: "Stage deletion of openai" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit openai" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Validate and activate" })).toBeDisabled();
    expect(adminRequestMock).toHaveBeenCalledTimes(1);
  });

  it("activates one edited resource through clone, strong-ETag patch, validation, and plan", async () => {
    const user = userEvent.setup(); const original = documentFixture(); let patched: JSONRecord | undefined;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { body?: unknown; etag?: string; method?: string }) => {
      if (path.endsWith("/config") && !options?.method) return Promise.resolve({ data: revision(activeID, original, "active", 1), etag: '"active-etag"' });
      if (path.endsWith("/config-revisions") && options?.method === "POST") return Promise.resolve({ data: revision(draftID, original, "draft", 2), etag: '"draft-etag-1"' });
      if (path === `/admin/v1/config-revisions/${draftID}` && options?.method === "PATCH") { patched = options.body as JSONRecord; return Promise.resolve({ data: revision(draftID, patched, "draft", 2), etag: '"draft-etag-2"' }); }
      if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
      if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [{ operation: "replace", path: "/spec/upstreams/0/baseUrl" }], from_revision_id: activeID, to_revision_id: draftID, warnings: [] } });
      if (path.endsWith("/activate")) return Promise.resolve({ data: revision(draftID, patched ?? original, "active", 2), etag: '"active-etag-2"' });
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<ConfigurationAreaEditor definition={configurationAreas.upstreams} />);
    await user.type(screen.getByLabelText("Environment ID"), environment);
    await user.click(screen.getByRole("button", { name: "Load active configuration" }));
    await user.click(await screen.findByRole("button", { name: "Edit openai" }));
    const edited = { ...((original.spec as JSONRecord).upstreams as JSONRecord[])[0], baseUrl: "https://gateway.example.test/v1" };
    fireEvent.change(screen.getByLabelText("Resource JSON"), { target: { value: JSON.stringify(edited, null, 2) } });
    await user.click(screen.getByRole("button", { name: "Stage resource" }));
    expect(screen.getByText("Staged changes")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Validate and activate" }));

    await screen.findByText("active");
    expect(((patched?.spec as JSONRecord).upstreams as JSONRecord[])[0]?.baseUrl).toBe("https://gateway.example.test/v1");
    expect(patched?.metadata).toEqual(original.metadata);
    expect((patched?.spec as JSONRecord).identityProviders).toEqual((original.spec as JSONRecord).identityProviders);
    const patchCall = adminRequestMock.mock.calls.find((call) => call[0] === `/admin/v1/config-revisions/${draftID}`);
    const activationCall = adminRequestMock.mock.calls.find((call) => call[0] === `/admin/v1/config-revisions/${draftID}/activate`);
    expect(patchCall?.[2]).toMatchObject({ etag: '"draft-etag-1"', method: "PATCH" });
    expect(activationCall?.[2]).toEqual({ etag: '"draft-etag-2"', method: "POST" });
    await waitFor(() => expect(screen.getByText("No staged changes")).toBeInTheDocument());
  });
});

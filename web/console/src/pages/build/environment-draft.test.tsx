import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  compatibility: { current: { mutationAllowed: true, status: undefined as { server_capabilities: string[] } | undefined } }
}));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility.current }));

import { WorkspaceContext, type WorkspaceContextValue } from "../../app/workspace-context-value";
import type { JSONRecord } from "../configuration-slice";
import { useEnvironmentDraft } from "./environment-draft";

const instant = "2026-08-29T00:00:00Z";
const environmentID = "env_0123456789abcdef";
const activeID = "rev_0123456789abcdef";
const draftID = "rev_1123456789abcdef";
const carriedID = "rev_2123456789abcdef";
const document: JSONRecord = { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: {}, spec: { session: { accessTokenTtl: "10m" } } };

type Options = { body?: unknown; etag?: string; method?: string } | undefined;

function revision(id: string, state: string, version: number, extra: JSONRecord = {}) {
  return { created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: environmentID, id, state, version, ...extra };
}

/** The newest revision is a validated draft: the state every console save leaves behind. */
function server() {
  adminRequestMock.mockImplementation((path: string, _schema: unknown, request: Options) => {
    const method = request?.method ?? "GET";
    if (path === `/admin/v1/environments/${environmentID}/config`) return Promise.resolve({ data: revision(activeID, "active", 1, { activated_at: instant }), etag: '"active"' });
    if (path === `/admin/v1/environments/${environmentID}/config-revisions?page_size=1`) return Promise.resolve({ data: { items: [revision(draftID, "valid", 2)], page: { has_more: false } } });
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "GET") return Promise.resolve({ data: revision(draftID, "valid", 2), etag: '"draft"' });
    if (path === `/admin/v1/environments/${environmentID}/config-revisions` && method === "POST") return Promise.resolve({ data: revision(carriedID, "draft", 3), etag: '"carried"' });
    if (path.startsWith("/admin/v1/config-revisions/") && method === "PATCH") return Promise.resolve({ data: revision(path.split("/").at(-1) ?? "", "draft", 2), etag: '"patched"' });
    if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
    if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [], from_revision_id: activeID, to_revision_id: draftID, warnings: [] } });
    if (path.endsWith("/activate")) return Promise.resolve({ data: revision(draftID, "active", 2, { activated_at: instant }), etag: '"draft"' });
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
}

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Mobile", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile", status: "active" as const };
  const environment = { application_id: application.id, created_at: instant, display_name: "Production", id: environmentID, kind: "production" as const, slug: "production", status: "active" as const };
  const value: WorkspaceContextValue = { application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search: {}, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: vi.fn() };
  return <QueryClientProvider client={queryClient}><WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider></QueryClientProvider>;
}

function calls(): string[] {
  return adminRequestMock.mock.calls.filter(([, , options]) => (options as Options)?.method).map(([path, , options]) => `${(options as Options)?.method} ${String(path)}`);
}

beforeEach(() => {
  adminRequestMock.mockReset();
  compatibility.current = { mutationAllowed: true, status: undefined };
});

describe("useEnvironmentDraft", () => {
  it("edits a validated draft in place on servers with the draft lifecycle", async () => {
    server();
    compatibility.current = { mutationAllowed: true, status: { server_capabilities: ["admin_configuration_drafts"] } };
    const { result } = renderHook(() => useEnvironmentDraft(), { wrapper });
    await waitFor(() => expect(result.current.draft?.id).toBe(draftID));
    await act(async () => { await result.current.save((current) => ({ ...current, kind: "EnvironmentConfig" })); });
    expect(calls()).toContain(`PATCH /admin/v1/config-revisions/${draftID}`);
    expect(calls()).not.toContain(`POST /admin/v1/environments/${environmentID}/config-revisions`);
    expect(result.current.problem).toBeUndefined();
  });

  it("carries a validated draft into a fresh one on servers that freeze it", async () => {
    server();
    const { result } = renderHook(() => useEnvironmentDraft(), { wrapper });
    await waitFor(() => expect(result.current.draft?.id).toBe(draftID));
    await act(async () => { await result.current.save((current) => current); });
    const create = adminRequestMock.mock.calls.find(([path, , options]) => path === `/admin/v1/environments/${environmentID}/config-revisions` && (options as Options)?.method === "POST");
    expect((create?.[2] as Options)?.body).toEqual({ description: "Admin console draft", document });
    expect(calls()).toContain(`PATCH /admin/v1/config-revisions/${carriedID}`);
    expect(calls()).not.toContain(`PATCH /admin/v1/config-revisions/${draftID}`);
  });

  it("sends a publish note only to servers that keep one", async () => {
    server();
    compatibility.current = { mutationAllowed: true, status: { server_capabilities: ["admin_configuration_drafts"] } };
    const lifecycle = renderHook(() => useEnvironmentDraft(), { wrapper });
    await waitFor(() => expect(lifecycle.result.current.draft?.id).toBe(draftID));
    await act(async () => { await lifecycle.result.current.publish("  Raise the free plan.  "); });
    const withNote = adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/activate"));
    expect((withNote?.[2] as Options)?.body).toEqual({ note: "Raise the free plan." });
    lifecycle.unmount();

    adminRequestMock.mockClear();
    compatibility.current = { mutationAllowed: true, status: undefined };
    const older = renderHook(() => useEnvironmentDraft(), { wrapper });
    await waitFor(() => expect(older.result.current.draft?.id).toBe(draftID));
    await act(async () => { await older.result.current.publish("ignored"); });
    const withoutNote = adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/activate"));
    expect((withoutNote?.[2] as Options)?.body).toBeUndefined();
  });
});

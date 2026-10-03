import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdminRequestError } from "../../api/auth";
import { WorkspaceContext, type WorkspaceContextValue } from "../../app/workspace-context-value";
import { configurationAreas, type JSONRecord } from "../configuration-slice";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/admin")>()),
  adminRequest: adminRequestMock
}));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => ({ mutationAllowed: true })
}));

import { CollectionPage } from "./collection-page";
import { draftProblem, useEnvironmentDraft } from "./environment-draft";

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
      features: [{ access: { expression: "principal.authenticated" }, id: "assistant", protocol: "openai_responses", routes: [{ id: "primary", model: "assistant", priority: 10, weight: 1, when: "true" }] }],
      identityProviders: [{ id: "firebase", projectId: "example-mobile", type: "firebase" }],
      models: [{ capabilities: ["openai_responses"], id: "assistant", upstream: "openai", upstreamModel: "gpt-5-mini" }],
      upstreams: [
        { authentication: { type: "none" }, baseUrl: "https://api.openai.com/v1", id: "openai", type: "openai_compatible" },
        { authentication: { type: "none" }, baseUrl: "https://backup.example.test/v1", id: "backup", type: "openai_compatible" }
      ]
    }
  };
}

function revision(id: string, document: JSONRecord, state: string, version: number) {
  return { activated_at: state === "active" ? instant : undefined, created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: environment, id, state, version };
}

function workspaceValue(): WorkspaceContextValue {
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Mobile", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile", status: "active" as const };
  const selected = { application_id: application.id, created_at: instant, display_name: "Production", id: environment, kind: "production" as const, slug: "production", status: "active" as const };
  return { application, applications: [application], environment: selected, environments: [selected], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search: {}, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: vi.fn() };
}

function Harness() {
  const draft = useEnvironmentDraft();
  return <CollectionPage definition={configurationAreas.upstreams} description="Connections" draft={draft} title="Connections" />;
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><WorkspaceContext.Provider value={workspaceValue()}><Harness /></WorkspaceContext.Provider></QueryClientProvider>);
}

type Options = { body?: unknown; etag?: string; method?: string } | undefined;

/** A small Admin API: one active revision and, once created, one working draft. */
function server(initialDraft?: { document: JSONRecord; version: number }) {
  const active = documentFixture();
  const state = { draft: initialDraft ? { ...initialDraft, etag: '"draft-etag-1"' } : undefined as { document: JSONRecord; etag: string; version: number } | undefined };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    const method = options?.method ?? "GET";
    if (path === `/admin/v1/environments/${environment}/config` && method === "GET") return Promise.resolve({ data: revision(activeID, active, "active", 3), etag: '"active-etag"' });
    if (path.startsWith(`/admin/v1/environments/${environment}/config-revisions?`)) {
      const items = state.draft ? [revision(draftID, state.draft.document, "valid", state.draft.version)] : [revision(activeID, active, "active", 3)];
      return Promise.resolve({ data: { items, page: { has_more: false } } });
    }
    if (path === `/admin/v1/environments/${environment}/config-revisions` && method === "POST") {
      state.draft = { document: active, etag: '"draft-etag-1"', version: 4 };
      return Promise.resolve({ data: revision(draftID, active, "draft", 4), etag: state.draft.etag });
    }
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "GET" && state.draft) return Promise.resolve({ data: revision(draftID, state.draft.document, "valid", state.draft.version), etag: state.draft.etag });
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "PATCH" && state.draft) {
      if (options?.etag !== state.draft.etag) return Promise.reject(new AdminRequestError({ code: "etag_mismatch", detail: "stale", retryable: false, status: 412, title: "Precondition failed" }));
      state.draft = { ...state.draft, document: options.body as JSONRecord, etag: '"draft-etag-2"' };
      return Promise.resolve({ data: revision(draftID, state.draft.document, "draft", state.draft.version), etag: state.draft.etag });
    }
    if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
    if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [{ operation: "replace", path: "/spec/upstreams/0/baseUrl" }], from_revision_id: activeID, to_revision_id: draftID, warnings: [] } });
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
  return state;
}

function mutations() {
  return adminRequestMock.mock.calls.filter(([, , options]) => (options as Options)?.method);
}

beforeEach(() => { adminRequestMock.mockReset(); });

describe("collection page on the shared draft", () => {
  it("lists live resources and cancels a removal without any mutation", async () => {
    const user = userEvent.setup();
    server();
    renderPage();

    await user.click(await screen.findByText("openai"));
    const drawer = await screen.findByRole("complementary", { name: "openai" });
    await user.click(within(drawer).getByRole("button", { name: "Remove openai" }));
    const dialog = screen.getByRole("alertdialog", { name: "Remove openai?" });
    expect(within(dialog).getByRole("button", { name: "Remove in Draft" })).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/to confirm/), "backup");
    expect(within(dialog).getByRole("button", { name: "Remove in Draft" })).toBeDisabled();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(mutations()).toHaveLength(0);
  });

  it("saves one edited resource into a new draft with the draft's strong ETag, then validates and plans", async () => {
    const user = userEvent.setup();
    const state = server();
    renderPage();

    await user.click(await screen.findByText("openai"));
    const drawer = await screen.findByRole("complementary", { name: "openai" });
    await user.click(within(drawer).getByRole("button", { name: "Edit as JSON" }));
    const original = documentFixture();
    const edited = { ...((original.spec as JSONRecord).upstreams as JSONRecord[])[0], baseUrl: "https://gateway.example.test/v1" };
    fireEvent.change(within(drawer).getByLabelText("Resource JSON"), { target: { value: JSON.stringify(edited, null, 2) } });
    expect(window.dispatchEvent(new Event("beforeunload", { cancelable: true }))).toBe(false);
    await user.click(within(drawer).getByRole("button", { name: "Save to Draft" }));

    expect(await screen.findByText("Saved to draft")).toBeInTheDocument();
    const calls = mutations().map(([path, , options]) => [path, (options as Options)?.method, (options as Options)?.etag]);
    expect(calls).toEqual([
      [`/admin/v1/environments/${environment}/config-revisions`, "POST", undefined],
      [`/admin/v1/config-revisions/${draftID}`, "PATCH", '"draft-etag-1"'],
      [`/admin/v1/config-revisions/${draftID}/validate`, "POST", undefined],
      [`/admin/v1/config-revisions/${draftID}/plan`, "POST", undefined]
    ]);
    expect(adminRequestMock.mock.calls.find(([, , options]) => (options as Options)?.method === "POST")?.[2]).toMatchObject({ body: { base_revision_id: activeID } });
    const saved = state.draft?.document as JSONRecord;
    expect(((saved.spec as JSONRecord).upstreams as JSONRecord[])[0]?.baseUrl).toBe("https://gateway.example.test/v1");
    expect(saved.metadata).toEqual(original.metadata);
    expect((saved.spec as JSONRecord).identityProviders).toEqual((original.spec as JSONRecord).identityProviders);
    await waitFor(() => expect(screen.getByText("Edited")).toBeInTheDocument());
  });

  it("marks draft changes against the live configuration and ignores drafts older than it", async () => {
    const changed = documentFixture();
    const spec = changed.spec as JSONRecord;
    spec.upstreams = [...(spec.upstreams as JSONRecord[]).filter((upstream) => upstream.id !== "backup"), { authentication: { type: "none" }, baseUrl: "https://new.example.test/v1", id: "fresh", type: "openai_compatible" }];
    server({ document: changed, version: 4 });
    const first = renderPage();
    expect(await screen.findByText("New")).toBeInTheDocument();
    expect(screen.getByText("Removing")).toBeInTheDocument();
    first.unmount();

    adminRequestMock.mockReset();
    server({ document: changed, version: 2 });
    renderPage();
    expect(await screen.findByText("backup")).toBeInTheDocument();
    expect(screen.queryByText("fresh")).not.toBeInTheDocument();
    expect(screen.queryByText("Removing")).not.toBeInTheDocument();
  });

  it("reports an edit made elsewhere instead of overwriting it", async () => {
    const user = userEvent.setup();
    const state = server({ document: documentFixture(), version: 4 });
    renderPage();
    await user.click(await screen.findByText("openai"));
    const drawer = await screen.findByRole("complementary", { name: "openai" });
    await user.click(within(drawer).getByRole("button", { name: "Edit as JSON" }));
    // Another tab replaces the draft after this page loaded it; the PATCH below then carries a stale ETag.
    const realImplementation = adminRequestMock.getMockImplementation();
    adminRequestMock.mockImplementation((path: string, schema: unknown, options: Options) => {
      if (path === `/admin/v1/config-revisions/${draftID}` && options?.method === "PATCH") return Promise.reject(new AdminRequestError({ code: "etag_mismatch", detail: "stale", retryable: false, status: 412, title: "Precondition failed" }));
      return realImplementation?.(path, schema, options);
    });
    await user.click(within(drawer).getByRole("button", { name: "Save to Draft" }));

    expect((await screen.findAllByText("The draft changed")).length).toBeGreaterThan(0);
    expect(mutations().some(([path]) => String(path).endsWith("/validate"))).toBe(false);
    expect(state.draft?.etag).toBe('"draft-etag-1"');
  });
});

describe("draft problems", () => {
  it("explains a stale ETag and a draft whose base is no longer live in plain language", () => {
    expect(draftProblem(new AdminRequestError({ code: "etag_mismatch", detail: "x", retryable: false, status: 412, title: "x" })).title).toBe("The draft changed");
    expect(draftProblem(new AdminRequestError({ code: "conflict", detail: "x", retryable: false, status: 409, title: "x" })).title).toBe("The draft is out of date");
  });
});

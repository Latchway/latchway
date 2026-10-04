import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => ({ mutationAllowed: true }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
import type { JSONRecord } from "../configuration-slice";
import { DraftChangesPage, JsonEditorPage, RevisionHistoryPage } from "./changes-pages";

const instant = "2026-08-29T00:00:00Z";
const environmentID = "env_0123456789abcdef";
const oldID = "rev_0023456789abcdef";
const activeID = "rev_0123456789abcdef";
const draftID = "rev_1123456789abcdef";

function documentWith(baseUrl: string, extra: JSONRecord = {}): JSONRecord {
  return { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: { application: "mobile" }, spec: { features: [{ access: { expression: "principal.authenticated" }, id: "chat", limitPlan: { expression: "'free'" }, routes: [{ id: "primary", model: "fast", priority: 10, when: "true" }] }], upstreams: [{ baseUrl, id: "openai", type: "openai_compatible" }], ...extra } };
}

const oldDocument = documentWith("https://old.example.test/v1");
const liveDocument = documentWith("https://api.example.test/v1");
const draftDocument = documentWith("https://gateway.example.test/v1", { session: { accessTokenTtl: "15m" } });

function revision(id: string, document: JSONRecord, state: string, version: number, extra: JSONRecord = {}) {
  return { activated_at: state === "active" || state === "superseded" ? instant : undefined, created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: environmentID, id, state, version, ...extra };
}

type Options = { body?: unknown; etag?: string; method?: string } | undefined;

function server(withDraft = true) {
  const state: { active: string; draft?: JSONRecord; draftETag: string } = { active: activeID, draft: withDraft ? draftDocument : undefined, draftETag: '"draft-etag-1"' };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, request: Options) => {
    const method = request?.method ?? "GET";
    const activeDocument = state.active === activeID ? liveDocument : oldDocument;
    if (path === `/admin/v1/environments/${environmentID}/config` && method === "GET") return Promise.resolve({ data: revision(state.active, activeDocument, "active", state.active === activeID ? 2 : 1), etag: `"active-${state.active}"` });
    if (path === `/admin/v1/environments/${environmentID}/config-revisions?page_size=1`) return Promise.resolve({ data: { items: [state.draft ? revision(draftID, state.draft, "invalid", 3, { validation: { checked_at: instant, issues: [{ code: "limit_plan_unknown", message: "Plan free doesn't exist.", path: "/spec/features/0/limitPlan", severity: "error" }], valid: false } }) : revision(activeID, liveDocument, "active", 2)], page: { has_more: false } } });
    if (path === `/admin/v1/environments/${environmentID}/config-revisions?page_size=20`) return Promise.resolve({ data: { items: [...(state.draft ? [revision(draftID, state.draft, "invalid", 3)] : []), revision(activeID, liveDocument, state.active === activeID ? "active" : "superseded", 2), revision(oldID, oldDocument, state.active === oldID ? "active" : "superseded", 1)], page: { has_more: false } } });
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "GET" && state.draft) return Promise.resolve({ data: revision(draftID, state.draft, "invalid", 3, { validation: { checked_at: instant, issues: [{ code: "limit_plan_unknown", message: "Plan free doesn't exist.", path: "/spec/features/0/limitPlan", severity: "error" }], valid: false } }), etag: state.draftETag });
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "PATCH") { state.draft = request?.body as JSONRecord; state.draftETag = '"draft-etag-2"'; return Promise.resolve({ data: revision(draftID, state.draft, "draft", 3), etag: state.draftETag }); }
    if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
    if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [], from_revision_id: activeID, to_revision_id: draftID, warnings: [] } });
    if (path === `/admin/v1/environments/${environmentID}/rollback` && method === "POST") { state.active = (request?.body as JSONRecord).revision_id as string; return Promise.resolve({ data: revision(state.active, oldDocument, "active", 1) }); }
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
  return state;
}

function Harness({ children, initial }: { children: ReactNode; initial: WorkspaceSearch }) {
  const [search, setSearch] = useState<WorkspaceSearch>(initial);
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Mobile", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile", status: "active" as const };
  const environment = { active_revision_id: activeID, application_id: application.id, created_at: instant, display_name: "Production", id: environmentID, kind: "production" as const, slug: "production", status: "active" as const };
  const value: WorkspaceContextValue = { application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: (patch) => setSearch((current) => ({ ...current, ...patch })) };
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

function renderPage(page: ReactNode, initial: WorkspaceSearch = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><Harness initial={initial}>{page}</Harness></QueryClientProvider>);
}

function mutations() {
  return adminRequestMock.mock.calls.filter(([, , options]) => (options as Options)?.method).map(([path, , options]) => `${(options as Options)?.method} ${String(path)}`);
}

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("Changes → Draft", () => {
  it("groups the draft's changes by resource, links problems to their fix, and discards one change", async () => {
    const user = userEvent.setup();
    const state = server();
    renderPage(<DraftChangesPage />);

    const connections = await screen.findByRole("region", { name: "AI Connections" });
    expect(connections).toHaveTextContent("baseUrl: https://api.example.test/v1 → https://gateway.example.test/v1");
    expect(screen.getByRole("region", { name: "Client Trust" })).toHaveTextContent("session");
    expect(screen.getByText("Plan free doesn't exist.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Fix" })).toHaveAttribute("href", "/features");

    await user.click(within(connections).getByRole("button", { name: /openai/ }));
    expect(within(connections).getByText("baseUrl")).toBeInTheDocument();
    await user.click(within(connections).getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(mutations()).toContain(`PATCH /admin/v1/config-revisions/${draftID}`));
    expect(state.draft).toEqual({ ...draftDocument, spec: { ...(draftDocument.spec as JSONRecord), upstreams: (liveDocument.spec as JSONRecord).upstreams } });
    const patch = adminRequestMock.mock.calls.find(([, , options]) => (options as Options)?.method === "PATCH");
    expect((patch?.[2] as Options)?.etag).toBe('"draft-etag-1"');
  });

  it("discards everything back to exactly the live document after confirming", async () => {
    const user = userEvent.setup();
    const state = server();
    renderPage(<DraftChangesPage />);
    await user.click(await screen.findByRole("button", { name: "Discard All" }));
    const dialog = screen.getByRole("alertdialog", { name: "Discard all 2 changes?" });
    await user.click(within(dialog).getByRole("button", { name: "Discard All" }));
    await waitFor(() => expect(state.draft).toEqual(liveDocument));
    expect(await screen.findByText("No unpublished changes")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is drafted", async () => {
    server(false);
    renderPage(<DraftChangesPage />);
    expect(await screen.findByText("No unpublished changes")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Discard All" })).not.toBeInTheDocument();
  });
});

describe("Changes → History", () => {
  it("summarises each revision against the one before and rolls back with a fresh ETag after review", async () => {
    const user = userEvent.setup();
    server();
    renderPage(<RevisionHistoryPage />);

    expect(await screen.findByText(oldID)).toBeInTheDocument();
    expect(screen.getByText("Live")).toBeInTheDocument();
    await user.click(screen.getByText(oldID));
    const drawer = await screen.findByRole("complementary", { name: oldID });
    await user.click(within(drawer).getByRole("button", { name: "Roll Back to This" }));
    const dialog = screen.getByRole("alertdialog", { name: "Roll back to version 1?" });
    expect(dialog).toHaveTextContent("changes undone");
    const confirm = within(dialog).getByRole("button", { name: "Roll Back" });
    await user.type(within(dialog).getByLabelText("Reason"), "Bad gateway URL");
    await user.type(within(dialog).getByLabelText(/to confirm/), oldID);
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(confirm);

    await waitFor(() => expect(mutations()).toContain(`POST /admin/v1/environments/${environmentID}/rollback`));
    const call = adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/rollback"));
    expect(call?.[2]).toEqual({ body: { reason: "Bad gateway URL", revision_id: oldID }, etag: `"active-${activeID}"`, method: "POST" });
    expect(await within(drawer).findByText(`${oldID} is live again.`)).toBeInTheDocument();
  });
});

describe("Changes → Edit as JSON", () => {
  it("refuses invalid JSON and saves a whole document into the draft against the shown basis", async () => {
    const user = userEvent.setup();
    const state = server();
    renderPage(<JsonEditorPage />);
    const editor = await screen.findByLabelText("Configuration document JSON");
    fireEvent.change(editor, { target: { value: "{ not json" } });
    await user.click(screen.getByRole("button", { name: "Save to Draft" }));
    expect(screen.getByText(/This isn't valid JSON/)).toBeInTheDocument();
    expect(mutations()).toEqual([]);

    const edited = documentWith("https://edited.example.test/v1");
    fireEvent.change(editor, { target: { value: JSON.stringify(edited, null, 2) } });
    await user.click(screen.getByRole("button", { name: "Save to Draft" }));
    await waitFor(() => expect(state.draft).toEqual(edited));
  });
});

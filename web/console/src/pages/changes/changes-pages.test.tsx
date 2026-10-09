import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
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

function Harness({ children, initial, staging = false }: { children: ReactNode; initial: WorkspaceSearch; staging?: boolean }) {
  const [search, setSearch] = useState<WorkspaceSearch>(initial);
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Mobile", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile", status: "active" as const };
  const environment = { active_revision_id: activeID, application_id: application.id, created_at: instant, display_name: "Production", id: environmentID, kind: "production" as const, slug: "production", status: "active" as const };
  const other = { active_revision_id: oldID, application_id: application.id, created_at: instant, display_name: "Staging", id: "env_9123456789abcdef", kind: "staging" as const, slug: "staging", status: "active" as const };
  const value: WorkspaceContextValue = { application, applications: [application], environment, environments: staging ? [environment, other] : [environment], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch: (patch) => setSearch((current) => ({ ...current, ...patch })) };
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

function renderPage(page: ReactNode, initial: WorkspaceSearch = {}, staging = false) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><Harness initial={initial} staging={staging}>{page}</Harness></QueryClientProvider>);
}

function mutations() {
  return adminRequestMock.mock.calls.filter(([, , options]) => (options as Options)?.method).map(([path, , options]) => `${(options as Options)?.method} ${String(path)}`);
}

beforeEach(() => {
  adminRequestMock.mockReset();
  compatibility.current = { mutationAllowed: true, status: undefined };
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

describe("Changes with the draft lifecycle", () => {
  const lifecycle = { server_capabilities: ["admin_configuration_drafts"] };

  /** A server where the draft started from the old revision and something newer went live since. */
  function lifecycleServer({ draft = true, stale = false }: { draft?: boolean; stale?: boolean } = {}) {
    const state = { discarded: false, draft: draft ? draftDocument : undefined as JSONRecord | undefined, promoted: false };
    const draftRevision = () => revision(draftID, state.draft ?? liveDocument, "valid", 3, {
      base_revision_id: stale ? oldID : activeID, description: "Admin console draft", updated_at: "2026-08-29T01:00:00Z", updated_by: "adm_1123456789abcdef",
      validation: { checked_at: instant, issues: [], valid: true }
    });
    adminRequestMock.mockImplementation((path: string, _schema: unknown, request: Options) => {
      const method = request?.method ?? "GET";
      if (path === `/admin/v1/environments/${environmentID}/config` && method === "GET") return Promise.resolve({ data: revision(activeID, liveDocument, "active", 2), etag: '"active-etag"' });
      if (path === `/admin/v1/environments/${environmentID}/config-revisions?page_size=1`) return Promise.resolve({ data: { items: [state.draft && !state.discarded ? draftRevision() : revision(activeID, liveDocument, "active", 2)], page: { has_more: false } } });
      if (path === `/admin/v1/config-revisions/${draftID}` && method === "GET") return Promise.resolve({ data: draftRevision(), etag: '"draft-etag"' });
      if (path === `/admin/v1/config-revisions/${oldID}` && method === "GET") return Promise.resolve({ data: revision(oldID, oldDocument, "superseded", 1), etag: '"old-etag"' });
      if (path === `/admin/v1/config-revisions/${draftID}/discard` && method === "POST") { state.discarded = true; return Promise.resolve({ data: { ...draftRevision(), discarded_at: instant, discarded_by: "adm_0123456789abcdef", state: "discarded", validation: undefined }, etag: '"draft-etag"' }); }
      if (path === `/admin/v1/config-revisions/${draftID}/edits`) return Promise.resolve({ data: { items: [{ change_count: 1, changes: [{ operation: "add", path: "/spec/session" }], edited_at: instant, edited_by: "adm_1123456789abcdef", kind: "edited", version: 2 }, { change_count: 0, changes: [], edited_at: instant, edited_by: "adm_0123456789abcdef", kind: "created", version: 1 }], revision_id: draftID, truncated: false } });
      if (path === `/admin/v1/config-revisions/${draftID}/rebase-preview`) return Promise.resolve({ data: { base_revision_id: oldID, conflicts: ["/spec/upstreams/openai/baseUrl"], draft_changes: [{ operation: "replace", path: "/spec/upstreams/openai/baseUrl" }], live_changes: [{ operation: "replace", path: "/spec/upstreams/openai/baseUrl" }], live_revision_id: activeID, revision_id: draftID, up_to_date: false } });
      if (path === `/admin/v1/config-revisions/${draftID}/rebase` && method === "POST") return Promise.resolve({ data: { ...draftRevision(), base_revision_id: activeID, state: "draft", validation: undefined }, etag: '"draft-etag-2"' });
      if (path === `/admin/v1/environments/${environmentID}/config-revisions/promote` && method === "POST") {
        state.promoted = true;
        return Promise.resolve({ data: { promotion: { copied: ["/spec/features"], kept: ["/metadata", "/spec/upstreams/openai"], review: ["/spec/identityProviders/firebase"], source_environment_id: "env_9123456789abcdef", source_revision_id: oldID }, revision: revision(draftID, draftDocument, "draft", 3) }, etag: '"promoted-etag"' });
      }
      return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
    });
    compatibility.current = { mutationAllowed: true, status: lifecycle };
    return state;
  }

  it("discards the draft on the server, keeping it in history", async () => {
    const user = userEvent.setup();
    const state = lifecycleServer();
    renderPage(<DraftChangesPage />);
    await user.click(await screen.findByRole("button", { name: "Discard Draft" }));
    const dialog = screen.getByRole("alertdialog", { name: `Discard draft ${draftID}?` });
    expect(dialog).toHaveTextContent("stays in History as discarded");
    await user.click(within(dialog).getByRole("button", { name: "Discard Draft" }));
    await waitFor(() => expect(state.discarded).toBe(true));
    const discard = adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/discard"));
    expect((discard?.[2] as Options)?.etag).toBe('"draft-etag"');
    expect(mutations()).not.toContain(`PATCH /admin/v1/config-revisions/${draftID}`);
  });

  it("shows who edited the draft and which paths, without values", async () => {
    const user = userEvent.setup();
    lifecycleServer();
    renderPage(<DraftChangesPage />);
    expect(await screen.findByText(/last edited by/)).toBeInTheDocument();
    await user.click(screen.getByText("Edit history"));
    const history = await screen.findByRole("list", { name: "Edit history" });
    expect(history).toHaveTextContent("Edited");
    expect(history).toHaveTextContent("/spec/session");
    expect(history).toHaveTextContent("adm_1123456789abcdef");
  });

  it("brings a stale draft up to date after a side is chosen for every conflict", async () => {
    const user = userEvent.setup();
    lifecycleServer({ stale: true });
    renderPage(<DraftChangesPage />);
    expect(await screen.findByText("Something else was published")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Bring Up to Date" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Bring the draft up to date?" });
    expect(await within(dialog).findByText(/1 conflict: both changed the same thing/)).toBeInTheDocument();
    expect(dialog).toHaveTextContent("https://gateway.example.test/v1");
    expect(dialog).toHaveTextContent("https://api.example.test/v1");
    const confirm = within(dialog).getByRole("button", { name: "Bring Up to Date" });
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole("radio", { name: /^Take live's/ }));
    await user.click(confirm);
    await waitFor(() => expect(mutations()).toContain(`POST /admin/v1/config-revisions/${draftID}/rebase`));
    const rebase = adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/rebase"));
    expect((rebase?.[2] as Options)?.body).toEqual({ live_revision_id: activeID, resolutions: { "/spec/upstreams/openai/baseUrl": "live" } });
    expect((rebase?.[2] as Options)?.etag).toBe('"draft-etag"');
  });

  it("copies another environment's live configuration into a new draft and lists what to review", async () => {
    const user = userEvent.setup();
    const state = lifecycleServer({ draft: false });
    renderPage(<DraftChangesPage />, {}, true);
    await user.click(await screen.findByRole("button", { name: "Copy From Environment" }));
    const dialog = screen.getByRole("alertdialog", { name: "Copy from another environment?" });
    expect(within(dialog).getByLabelText("Copy from")).toHaveValue("env_9123456789abcdef");
    await user.click(within(dialog).getByRole("button", { name: "Start Draft" }));
    await waitFor(() => expect(state.promoted).toBe(true));
    const promote = adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/promote"));
    expect((promote?.[2] as Options)?.body).toEqual({ description: "From Staging", source_environment_id: "env_9123456789abcdef" });
    expect(await screen.findByText(/Review before publishing/)).toBeInTheDocument();
    expect(screen.getByText("Sign-in providers: firebase")).toBeInTheDocument();
  });
});

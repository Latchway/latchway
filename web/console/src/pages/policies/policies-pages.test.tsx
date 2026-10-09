import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: ["activate_configuration", "inspect_users"], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => ({ mutationAllowed: true }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { AdminRequestError } from "../../api/auth";
import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
import type { JSONRecord } from "../configuration-slice";
import { LimitPlansPage, OverridesPage } from "./policies-pages";

const instant = "2026-08-29T00:00:00Z";
const environmentID = "env_0123456789abcdef";
const activeID = "rev_0123456789abcdef";
const draftID = "rev_1123456789abcdef";
const userID = "usr_0123456789abcdef";

function liveDocument(): JSONRecord {
  return {
    apiVersion: "latchway.dev/v1alpha1",
    kind: "EnvironmentConfig",
    metadata: { application: "mobile" },
    spec: {
      features: [
        { access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "chat", limitPlan: { expression: "principal.claims.plan == 'premium' ? 'premium' : 'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "fast", priority: 10, when: "true" }] }
      ],
      limitPlans: [
        { id: "free", limits: [{ algorithm: "calendar", hard: true, maximum: 50_000, metric: "total_tokens", scope: ["user"], timezone: "UTC", window: "1d" }] },
        { id: "premium", limits: [{ algorithm: "calendar", hard: true, maximum: 500_000, metric: "total_tokens", scope: ["user"], timezone: "UTC", window: "1d" }] }
      ]
    }
  };
}

function revision(id: string, document: JSONRecord, state: string, version: number) {
  return { activated_at: state === "active" ? instant : undefined, created_at: instant, created_by: "adm_0123456789abcdef", document, environment_id: environmentID, id, state, version };
}

type Options = { body?: unknown; etag?: string; method?: string } | undefined;

function server(options: { draftDocument?: JSONRecord; override?: JSONRecord } = {}) {
  const live = liveDocument();
  const state: { draft?: { document: JSONRecord; etag: string }; override?: JSONRecord } = { draft: options.draftDocument ? { document: options.draftDocument, etag: '"draft-etag-1"' } : undefined, override: options.override };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, request: Options) => {
    const method = request?.method ?? "GET";
    if (path === `/admin/v1/environments/${environmentID}/config` && method === "GET") return Promise.resolve({ data: revision(activeID, live, "active", 1), etag: '"active-etag"' });
    if (path.startsWith(`/admin/v1/environments/${environmentID}/config-revisions?`)) return Promise.resolve({ data: { items: [state.draft ? revision(draftID, state.draft.document, "valid", 2) : revision(activeID, live, "active", 1)], page: { has_more: false } } });
    if (path === `/admin/v1/environments/${environmentID}/config-revisions` && method === "POST") { state.draft = { document: live, etag: '"draft-etag-1"' }; return Promise.resolve({ data: revision(draftID, live, "draft", 2), etag: state.draft.etag }); }
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "GET" && state.draft) return Promise.resolve({ data: revision(draftID, state.draft.document, "valid", 2), etag: state.draft.etag });
    if (path === `/admin/v1/config-revisions/${draftID}` && method === "PATCH") { state.draft = { document: request?.body as JSONRecord, etag: '"draft-etag-2"' }; return Promise.resolve({ data: revision(draftID, state.draft.document, "draft", 2), etag: state.draft.etag }); }
    if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
    if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [], from_revision_id: activeID, to_revision_id: draftID, warnings: [] } });
    if (path === `/admin/v1/users/${userID}?environment_id=${environmentID}`) return Promise.resolve({ data: { created_at: instant, environment_id: environmentID, id: userID, identity_providers: ["firebase"], ...(state.override ? { limit_plan_override: state.override } : {}), normalized_claims: { plan: "free" }, status: "active" } });
    if (path === `/admin/v1/users/${userID}/limit-override?environment_id=${environmentID}` && method === "PUT") {
      const body = request?.body as JSONRecord;
      const same = state.override && state.override.limit_plan === body.limit_plan && state.override.expires_at === body.expires_at;
      state.override = same ? state.override : { created_at: instant, id: "ovr_1123456789abcdef", limit_plan: body.limit_plan, reason: body.reason, ...(body.expires_at ? { expires_at: body.expires_at } : {}) };
      return Promise.resolve({ data: { created_at: instant, environment_id: environmentID, id: userID, identity_providers: ["firebase"], limit_plan_override: state.override, normalized_claims: {}, status: "active" } });
    }
    if (path === `/admin/v1/users/${userID}/limit-override?environment_id=${environmentID}` && method === "DELETE") { state.override = undefined; return Promise.resolve({ data: undefined }); }
    if (path.includes("/effective-configuration")) return Promise.reject(new AdminRequestError({ code: "unavailable", detail: "No session", retryable: false, status: 404, title: "Unavailable" }));
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
  return state;
}

const searchLog: WorkspaceSearch[] = [];

function Harness({ children, initial }: { children: ReactNode; initial: WorkspaceSearch }) {
  const [search, setSearch] = useState<WorkspaceSearch>(initial);
  const organization = { created_at: instant, display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: instant, display_name: "Mobile", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile", status: "active" as const };
  const environment = { active_revision_id: activeID, application_id: application.id, created_at: instant, display_name: "Production", id: environmentID, kind: "production" as const, slug: "production", status: "active" as const };
  const value: WorkspaceContextValue = {
    application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search,
    selectApplication: vi.fn(), selectEnvironment: vi.fn(),
    updateSearch: (patch) => { searchLog.push(patch as WorkspaceSearch); setSearch((current) => ({ ...current, ...patch })); }
  };
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
  searchLog.length = 0;
});

describe("Limit plans", () => {
  it("lists plans as sentences and saves an edited limit into the draft", async () => {
    const user = userEvent.setup();
    const state = server();
    renderPage(<LimitPlansPage />);

    expect((await screen.findAllByText("chat", { selector: ".lw-mono" })).length).toBe(2);
    expect(screen.getAllByText("50,000 tokens").length).toBeGreaterThan(0);
    await user.click(screen.getByText("free", { selector: ".lw-mono" }));
    const drawer = await screen.findByRole("complementary", { name: "free" });
    expect(searchLog.at(-1)).toEqual({ plan: "free" });
    await user.click(within(drawer).getByRole("button", { name: /Each user can use 50,000 tokens per day/ }));
    const amount = within(drawer).getByLabelText("Limit 1 amount");
    await user.clear(amount);
    await user.type(amount, "80000");
    await user.click(within(drawer).getByRole("button", { name: "Save to Draft" }));

    await waitFor(() => expect(mutations()).toContain(`PATCH /admin/v1/config-revisions/${draftID}`));
    const plans = ((state.draft?.document.spec as JSONRecord).limitPlans as JSONRecord[]);
    expect(plans.find((plan) => plan.id === "free")?.limits).toEqual([{ algorithm: "calendar", hard: true, maximum: 80_000, metric: "total_tokens", scope: ["user"], timezone: "UTC", window: "1d" }]);
    expect(plans.find((plan) => plan.id === "premium")).toEqual(((liveDocument().spec as JSONRecord).limitPlans as JSONRecord[])[1]);
  });

  it("blocks a first-attempt-only spend limit without its organization-wide pair, and Add It fixes it", async () => {
    const user = userEvent.setup();
    server();
    renderPage(<LimitPlansPage />, { plan: "free" });
    const drawer = await screen.findByRole("complementary", { name: "free" });
    await user.click(within(drawer).getByRole("button", { name: /Each user can use/ }));
    await user.selectOptions(within(drawer).getByLabelText("Limit 1 metric"), "cost_nano_usd");
    const dollars = within(drawer).getByLabelText("Limit 1 amount in dollars");
    await user.type(dollars, "5");
    await user.selectOptions(within(drawer).getByLabelText("Limit 1 retries"), "initial_attempt_only");
    expect(within(drawer).getByText(/needs an organization-wide spend limit that counts every attempt/)).toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: "Save to Draft" }));
    expect(within(drawer).getByText(/problem to fix first/)).toBeInTheDocument();
    expect(mutations()).toEqual([]);

    await user.click(within(drawer).getByRole("button", { name: "Add It" }));
    expect(drawer).toHaveTextContent("Everyone together can use $100.00 per month");
    expect(within(drawer).queryByText(/needs an organization-wide spend limit/)).not.toBeInTheDocument();
  });

  it("removes a plan in use only after its features are reassigned in the same draft", async () => {
    const user = userEvent.setup();
    const state = server();
    renderPage(<LimitPlansPage />, { plan: "premium" });
    const drawer = await screen.findByRole("complementary", { name: "premium" });
    await user.click(within(drawer).getByRole("button", { name: "Remove premium" }));
    const dialog = screen.getByRole("alertdialog", { name: "Remove premium?" });
    expect(within(dialog).getByLabelText("New plan for chat")).toHaveValue("free");
    expect(within(dialog).getByText(/can't list users with an override/)).toBeInTheDocument();
    const confirm = within(dialog).getByRole("button", { name: "Reassign and Remove in Draft" });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/to confirm/), "premium");
    await user.click(confirm);

    await waitFor(() => expect(mutations()).toContain(`PATCH /admin/v1/config-revisions/${draftID}`));
    const spec = state.draft?.document.spec as JSONRecord;
    expect((spec.limitPlans as JSONRecord[]).map((plan) => plan.id)).toEqual(["free"]);
    expect((spec.features as JSONRecord[])[0]?.limitPlan).toEqual({ expression: "principal.claims.plan == 'premium' ? 'free' : 'free'" });
  });

  it("refuses an unknown plan in the URL instead of opening another", async () => {
    server();
    renderPage(<LimitPlansPage />, { plan: "missing" });
    expect(await screen.findByText("Plan not found")).toBeInTheDocument();
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
  });
});

describe("Overrides", () => {
  it("applies an override now, with a reason and an end, offering only live plans", async () => {
    const user = userEvent.setup();
    const trial = liveDocument();
    ((trial.spec as JSONRecord).limitPlans as JSONRecord[]).push({ id: "trial", limits: [{ algorithm: "calendar", hard: true, maximum: 1, metric: "logical_requests", scope: ["user"], timezone: "UTC", window: "1d" }] });
    server({ draftDocument: trial });
    renderPage(<OverridesPage />);

    await user.type(await screen.findByLabelText("User ID"), "someone@example.com");
    await user.click(screen.getByRole("button", { name: "Open" }));
    expect(screen.getByText(/Emails and sign-in subjects are never stored/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText("User ID"));
    await user.type(screen.getByLabelText("User ID"), userID);
    await user.click(screen.getByRole("button", { name: "Open" }));
    expect(searchLog.at(-1)).toEqual({ user: userID });

    const plan = await screen.findByLabelText("Plan");
    expect(within(plan).getByRole("option", { name: /trial \(only in the draft; publish first\)/ })).toBeDisabled();
    await user.selectOptions(plan, "premium");
    expect(screen.getByText("Applies immediately")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Reason"), "Support ticket 4411");
    await user.click(screen.getByRole("button", { name: "Apply Now" }));

    expect(await screen.findByText(/Override applied\. premium is live for this user now\./)).toBeInTheDocument();
    const put = adminRequestMock.mock.calls.find(([, , options]) => (options as Options)?.method === "PUT");
    const body = (put?.[2] as Options)?.body as JSONRecord;
    expect(body).toMatchObject({ limit_plan: "premium", reason: "Support ticket 4411" });
    const days = (Date.parse(String(body.expires_at)) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.9);
    expect(days).toBeLessThan(7.1);
    expect(mutations().every((call) => !call.includes("config-revisions"))).toBe(true);
  });

  it("says when an override was already in place, and clears only after confirming", async () => {
    const user = userEvent.setup();
    server({ override: { created_at: instant, id: "ovr_0123456789abcdef", limit_plan: "premium", reason: "Existing" } });
    renderPage(<OverridesPage />, { user: userID });

    await user.selectOptions(await screen.findByLabelText("Plan"), "premium");
    await user.selectOptions(screen.getByLabelText("Ends"), "never");
    await user.type(screen.getByLabelText("Reason"), "Again");
    await user.click(screen.getByRole("button", { name: "Apply Now" }));
    expect(await screen.findByText("No change: the same override was already in place.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear Override" }));
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent("doesn't bring back any earlier override");
    await user.click(within(dialog).getByRole("button", { name: "Clear Override" }));
    expect(await screen.findByText(/Override cleared/)).toBeInTheDocument();
    expect(mutations()).toContain(`DELETE /admin/v1/users/${userID}/limit-override?environment_id=${environmentID}`);
  });
});

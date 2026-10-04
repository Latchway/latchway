import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  adminRequestMock,
  getRequestEffectiveConfigurationMock,
  getUserEffectiveConfigurationMock,
  getUserOperationImpactMock,
  requireApplicationUserAppReverificationMock,
  requireApplicationUserReauthenticationMock,
  setApplicationUserBlockedMock
} = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  getRequestEffectiveConfigurationMock: vi.fn(),
  getUserEffectiveConfigurationMock: vi.fn(),
  getUserOperationImpactMock: vi.fn(),
  requireApplicationUserAppReverificationMock: vi.fn(),
  requireApplicationUserReauthenticationMock: vi.fn(),
  setApplicationUserBlockedMock: vi.fn()
}));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock,
  getRequestEffectiveConfiguration: getRequestEffectiveConfigurationMock,
  getUserEffectiveConfiguration: getUserEffectiveConfigurationMock,
  getUserOperationImpact: getUserOperationImpactMock,
  requireApplicationUserAppReverification: requireApplicationUserAppReverificationMock,
  requireApplicationUserReauthentication: requireApplicationUserReauthenticationMock,
  setApplicationUserBlocked: setApplicationUserBlockedMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({
    data: {
      mode: "configured",
      session: { capabilities: ["inspect_users", "revoke_installations", "run_self_tests"], organization_id: "org_0123456789abcdef" }
    }
  })
}));
vi.mock("../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => ({ mutationAllowed: true })
}));

import { AuditPageView, SelfTestsPage } from "./control-plane-pages";
import { SelfTestSchema } from "../api/admin";
import { dispatchAdminRefresh } from "../api/admin-events";
import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../app/workspace-context-value";

function renderInWorkspace(children: ReactNode, search: WorkspaceSearch) {
  const organization = { created_at: "2026-08-29T00:00:00Z", display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: "2026-08-29T00:00:00Z", display_name: "Mobile App", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile-app", status: "active" as const };
  const environment = { application_id: application.id, created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: "env_0123456789abcdef", kind: "production" as const, slug: "production", status: "active" as const };
  const updateSearch = vi.fn();
  const value: WorkspaceContextValue = {
    application,
    applications: [application],
    environment,
    environments: [environment],
    invalidApplication: false,
    invalidEnvironment: false,
    isLoading: false,
    organization,
    search,
    selectApplication: vi.fn(),
    selectEnvironment: vi.fn(),
    updateSearch
  };
  return { updateSearch, ...render(<WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>) };
}

afterEach(cleanup);

beforeEach(() => {
  adminRequestMock.mockReset();
  getRequestEffectiveConfigurationMock.mockReset();
  getUserEffectiveConfigurationMock.mockReset();
  getUserOperationImpactMock.mockReset();
  requireApplicationUserAppReverificationMock.mockReset();
  requireApplicationUserReauthenticationMock.mockReset();
  setApplicationUserBlockedMock.mockReset();
});

describe("rich usage and route-simulator views", () => {
  it("restores every audit filter from workspace URL state and sends it to the Admin API", async () => {
    const search: WorkspaceSearch = {
      action: "admin.user_block",
      actor_id: "tok_0123456789abcdef",
      actor_kind: "admin_api_token",
      application: "mobile-app",
      cursor: "next-audit-page",
      end: "2026-08-30T00:00:00Z",
      environment: "production",
      environment_id: "env_0123456789abcdef",
      organization: "example",
      reason: "security_response",
      resource_id: "usr_0123456789abcdef",
      resource_type: "application_user",
      result: "succeeded",
      source: "console",
      start: "2026-08-29T00:00:00Z"
    };
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: false } } });

    renderInWorkspace(<AuditPageView />, search);

    await waitFor(() => expect(adminRequestMock).toHaveBeenCalled());
    const listPath = String(adminRequestMock.mock.calls.find(([path]) => String(path).startsWith("/admin/v1/audit-events?"))?.[0]);
    const query = new URLSearchParams(listPath.split("?")[1]);
    expect(Object.fromEntries(query)).toEqual({
      action: "admin.user_block",
      actor_id: "tok_0123456789abcdef",
      actor_kind: "admin_api_token",
      cursor: "next-audit-page",
      end: "2026-08-30T00:00:00Z",
      environment_id: "env_0123456789abcdef",
      organization_id: "org_0123456789abcdef",
      page_size: "50",
      reason: "security_response",
      resource_id: "usr_0123456789abcdef",
      resource_type: "application_user",
      result: "succeeded",
      source: "console",
      start: "2026-08-29T00:00:00Z"
    });
    expect(screen.getByLabelText("Reason code")).toHaveValue("security_response");
    expect(screen.getByLabelText("Descriptive source")).toHaveValue("console");
    const initialLoads = adminRequestMock.mock.calls.filter(([path]) => String(path).startsWith("/admin/v1/audit-events?")).length;
    dispatchAdminRefresh(["audit"]);
    await waitFor(() => expect(adminRequestMock.mock.calls.filter(([path]) => String(path).startsWith("/admin/v1/audit-events?")).length).toBe(initialLoads + 1));
  });

  it("keeps audit pagination server-side by writing the returned cursor to URL state", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: true, next_cursor: "next-audit-page" } } });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<AuditPageView />, {
      application: "mobile-app",
      environment: "production",
      organization: "example",
      result: "failed"
    });

    await user.click(await screen.findByRole("button", { name: "Next page" }));

    expect(updateSearch).toHaveBeenLastCalledWith({ cursor: "next-audit-page" });
  });

  it("filters audit history and inspects its value-free field-level diff", async () => {
    const event = {
      action: "admin.user_block",
      actor: "admin_api_token:tok_00000000000000000000000000",
      actor_id: "tok_00000000000000000000000000",
      actor_kind: "admin_api_token",
      changes: [{ classification: "sensitive", field: "credential", operation: "revoke", redacted: true }],
      environment_id: "env_0123456789abcdef",
      id: "aud_00000000000000000000000000",
      reason: "security_response",
      request_id: "arq_00000000000000000000000000",
      resource_id: "usr_00000000000000000000000000",
      resource_type: "user",
      result: "succeeded",
      source: "api",
      summary: { changes: [{ classification: "sensitive", field: "credential", operation: "revoke", redacted: true }] },
      target: "user:usr_00000000000000000000000000",
      timestamp: "2026-08-29T00:00:00Z"
    };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(event.id)
      ? { data: event }
      : { data: { items: [event], page: { has_more: false } } });
    const user = userEvent.setup();
    render(<AuditPageView />);
    await user.type(screen.getByLabelText("Environment"), event.environment_id);
    await user.selectOptions(screen.getByLabelText("Actor kind"), "admin_api_token");
    await user.type(screen.getByLabelText("Resource ID"), event.resource_id);
    await user.selectOptions(screen.getByLabelText("Descriptive source"), "api");
    await user.type(screen.getByLabelText("Reason code"), "security_response");
    await user.selectOptions(screen.getByLabelText("Result"), "succeeded");
    await user.click(screen.getByRole("button", { name: "Apply filters" }));

    expect(await screen.findByRole("button", { name: event.target })).toBeInTheDocument();
    const listPath = String(adminRequestMock.mock.calls[0]?.[0]);
    expect(listPath).toContain("actor_kind=admin_api_token");
    expect(listPath).toContain("resource_id=usr_00000000000000000000000000");
    expect(listPath).toContain("source=api");
    expect(listPath).toContain("reason=security_response");
    await user.click(screen.getByRole("button", { name: event.target }));
    expect(await screen.findByRole("heading", { name: "Field-level diff" })).toBeInTheDocument();
    expect(screen.getByText("Redacted by contract")).toBeInTheDocument();
    expect(adminRequestMock).toHaveBeenLastCalledWith(`/admin/v1/audit-events/${event.id}`, expect.anything());
  });

  it("restores an exact audit detail from validated deep-link state on reload", async () => {
    const event = {
      action: "admin.environment_disable",
      actor: "admin_user:adm_00000000000000000000000000",
      actor_id: "adm_00000000000000000000000000",
      actor_kind: "admin_user",
      changes: [],
      environment_id: "env_0123456789abcdef",
      id: "aud_00000000000000000000000000",
      reason: "security_response",
      request_id: "arq_00000000000000000000000000",
      resource_id: "env_0123456789abcdef",
      resource_type: "environment",
      result: "succeeded",
      source: "console",
      summary: { changes: [] },
      target: "environment:env_0123456789abcdef",
      timestamp: "2026-08-29T00:00:00Z"
    };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(event.id)
      ? { data: event }
      : { data: { items: [event], page: { has_more: false } } });

    renderInWorkspace(<AuditPageView />, { event: event.id });

    expect(await screen.findByRole("heading", { name: "Audit detail" })).toBeInTheDocument();
    expect(screen.getByText(event.id)).toBeInTheDocument();
    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/audit-events/${event.id}`, expect.anything());
  });

  it("writes a selected immutable audit event to shareable route state", async () => {
    const event = {
      action: "admin.environment_disable",
      actor: "admin_user:adm_00000000000000000000000000",
      changes: [],
      id: "aud_00000000000000000000000000",
      result: "succeeded",
      source: "console",
      target: "environment:env_0123456789abcdef",
      timestamp: "2026-08-29T00:00:00Z"
    };
    adminRequestMock.mockResolvedValue({ data: { items: [event], page: { has_more: false } } });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<AuditPageView />, {});

    await user.click(await screen.findByRole("button", { name: event.target }));

    expect(updateSearch).toHaveBeenCalledWith({ event: event.id });
  });

  it("restores selected self-test run and schedule IDs while keeping bearer material local", async () => {
    const environmentID = "env_0123456789abcdef";
    const run = { checks: [{ name: "usage", safe_detail: "Bounded usage passed.", state: "passed" }], completed_at: "2026-08-29T00:00:01Z", config_revision_id: "rev_0123456789abcdef", created_at: "2026-08-29T00:00:00Z", environment_id: environmentID, id: "tst_0123456789abcdef", kind: "upstream", state: "passed" };
    const schedule = {
      application_id: "app_0123456789abcdef", authorization_credential_id: "tok_0123456789abcdef", config_revision_id: "rev_0123456789abcdef",
      created_at: "2026-08-29T00:00:00Z", daily_cost_limit_nano_usd: 240_000_000, environment_id: environmentID,
      id: "sts_0123456789abcdef", interval_seconds: 3600, kind: "upstream", max_cost_nano_usd: 10_000_000, model: "canary",
      next_run_at: "2026-08-29T01:00:00Z", status: "active", updated_at: "2026-08-29T00:00:00Z", upstream: "primary"
    };
    adminRequestMock.mockImplementation(async (path: string) => {
      if (path === `/admin/v1/self-tests/${run.id}?environment_id=${environmentID}`) return { data: run };
      if (path.startsWith("/admin/v1/self-test-schedules?")) return { data: { items: [schedule], page: { has_more: false } } };
      if (path === `/admin/v1/self-test-schedules/${schedule.id}`) return { data: schedule };
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<SelfTestsPage />, { environment_id: environmentID, schedule_id: schedule.id, self_test_id: run.id });

    expect(await screen.findByRole("heading", { name: "upstream self-test" })).toBeInTheDocument();
    expect(await screen.findByText(`${schedule.id} · active`)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Durable Admin API token/)).toHaveValue("");
    const initialLoads = adminRequestMock.mock.calls.length;
    dispatchAdminRefresh(["self_tests"]);
    await waitFor(() => expect(adminRequestMock).toHaveBeenCalledTimes(initialLoads + 3));
    await user.click(screen.getByRole("button", { name: "Close run" }));
    expect(updateSearch).toHaveBeenLastCalledWith({ self_test_id: undefined });
    await user.click(screen.getByRole("button", { name: "Close schedule" }));
    expect(updateSearch).toHaveBeenLastCalledWith({ schedule_id: undefined });
    expect(JSON.stringify(updateSearch.mock.calls)).not.toContain("tok_0123456789abcdef");
  });

  it("fails closed when a restored self-test belongs to another environment", async () => {
    const environmentID = "env_0123456789abcdef";
    const runID = "tst_0123456789abcdef";
    adminRequestMock.mockResolvedValue({ data: {
      checks: [{ name: "usage", state: "passed" }], completed_at: "2026-08-29T00:00:01Z",
      config_revision_id: "rev_0123456789abcdef", created_at: "2026-08-29T00:00:00Z",
      environment_id: "env_fedcba9876543210", id: runID, kind: "upstream", state: "passed"
    } });

    renderInWorkspace(<SelfTestsPage />, { environment_id: environmentID, self_test_id: runID });

    expect(await screen.findByRole("alert")).toHaveTextContent("Self-test context mismatch");
    expect(screen.queryByRole("heading", { name: "upstream self-test" })).not.toBeInTheDocument();
    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/self-tests/${runID}?environment_id=${environmentID}`,
      SelfTestSchema
    );
  });

  it("creates, lists, reads, and disables a schedule using only durable token metadata", async () => {
    const schedule = {
      application_id: "app_0123456789abcdef", authorization_credential_id: "tok_0123456789abcdef",
      config_revision_id: "rev_0123456789abcdef", created_at: "2026-08-29T00:00:00Z",
      daily_cost_limit_nano_usd: 240_000_000, environment_id: "env_0123456789abcdef",
      id: "sts_0123456789abcdef", interval_seconds: 3600, kind: "upstream", max_cost_nano_usd: 10_000_000,
      model: "canary", next_run_at: "2026-08-29T01:00:00Z", status: "active",
      updated_at: "2026-08-29T00:00:00Z", upstream: "primary"
    } as const;
    adminRequestMock.mockImplementation(async (path: string, _schema: unknown, options?: { method?: string; body?: unknown }) => {
      if (options?.method === "DELETE") return { data: { ...schedule, disabled_at: "2026-08-29T00:10:00Z", disabled_reason_code: "operator_disabled", next_run_at: undefined, status: "disabled", updated_at: "2026-08-29T00:10:00Z" } };
      if (options?.method === "POST") return { data: schedule };
      if (path === `/admin/v1/self-test-schedules/${schedule.id}`) return { data: schedule };
      return { data: { items: [schedule], page: { has_more: false } } };
    });
    const user = userEvent.setup();
    render(<SelfTestsPage />);
    await user.type(screen.getByLabelText("Scheduled environment ID"), schedule.environment_id);
    await user.click(screen.getByRole("button", { name: "Load schedules" }));

    expect(await screen.findByRole("button", { name: schedule.id })).toBeInTheDocument();
    expect(screen.getByText(schedule.config_revision_id)).toBeInTheDocument();
    expect(screen.getByText(schedule.authorization_credential_id)).toBeInTheDocument();
    const bearerToken = "transient-scheduled-self-test-token-material-1234567890";
    await user.type(screen.getByLabelText(/^Durable Admin API token/), bearerToken);
    await user.type(screen.getByLabelText("Scheduled upstream ID"), schedule.upstream);
    await user.type(screen.getByLabelText("Scheduled model ID"), schedule.model);
    await user.click(screen.getByRole("button", { name: "Create schedule" }));

    expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/self-test-schedules", expect.anything(), expect.objectContaining({
      bearerToken, body: expect.not.objectContaining({ authorization_credential_id: expect.anything() }), method: "POST"
    }));
    expect(screen.getByLabelText(/^Durable Admin API token/)).toHaveValue("");
    const createBody = adminRequestMock.mock.calls.find(([path, , options]) => path === "/admin/v1/self-test-schedules" && options?.method === "POST")?.[2]?.body;
    expect(JSON.stringify(createBody)).not.toContain(bearerToken);
    await user.click(screen.getByRole("button", { name: "Disable schedule" }));
    expect(await screen.findByText(`${schedule.id} · disabled`)).toBeInTheDocument();
  });
});

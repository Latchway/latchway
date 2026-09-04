import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

import { AttestationFailuresPage, AuditPageView, CostPage, ErrorsPage, InstallationsPage, LatencyPage, RequestsPage, RouteSimulatorPage, SelfTestsPage, UsagePage, UsersPage } from "./control-plane-pages";
import { SelfTestSchema } from "../api/admin";
import { dispatchAdminRefresh } from "../api/admin-events";
import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../app/workspace-context-value";

const zeroValues = { cost_nano_usd: 0, input_tokens: 0, logical_requests: 0, output_tokens: 0, total_tokens: 0 };
const requestProvenance = {
  config_revision_id: "rev_0123456789abcdef",
  decision_stages: [],
  selected_limit_plan: "subscriber"
};

function effectiveConfigurationFixture(mode: "current_user_projection" | "recorded_request" = "current_user_projection") {
  const route = {
    configured_priority: 0, configured_weight: 100, fallback_on: ["timeout"], match_expression: "true",
    model: "gpt_mobile", observed: mode === "recorded_request", order: 1, physical_model: "gpt-5-mini",
    retry_maximum_attempts: 2, retry_on: ["timeout"], route: "primary", source: mode === "recorded_request" ? "upstream_attempt" : "feature.routes[0]",
    sticky_by: "user", upstream: "openai"
  };
  return {
    decision_stages: [], environment_id: "env_0123456789abcdef", environment_kind: "production",
    evaluation_mode: mode, feature: "assistant",
    inputs: [{ availability: mode === "recorded_request" ? "unavailable" : "available", detail: mode === "recorded_request" ? "Historical claim values were not persisted and are not inferred." : "Only normalized claim keys are shown.", fact: "normalized_claims", ...(mode === "recorded_request" ? {} : { keys: ["plan"] }), source: mode === "recorded_request" ? "historical_request" : "current_application_user" }],
    limit_plan: "subscriber", limit_plan_source: mode === "recorded_request" ? "durable_request_record" : "policy_expression",
    limits: [{ algorithm: "per_request", hard: true, index: 0, metric: "input_tokens", per_request_maximum: 4096, scope: ["user", "feature"], source: "limit_plans.subscriber.limits[0]" }],
    policy_outcome: "allowed", protocol: "openai_chat", revision_id: "rev_0123456789abcdef",
    routes: [route], selected_route: route,
    subject: mode === "recorded_request"
      ? { id: "req_0123456789abcdef", kind: "request", user_id: "usr_0123456789abcdef" }
      : { id: "usr_0123456789abcdef", kind: "user", user_id: "usr_0123456789abcdef" },
    warnings: mode === "recorded_request" ? ["Historical claim values remain unavailable."] : []
  };
}

function analyticsFixture() {
  return {
    analytics: {
      active_users: 2,
      attestation_failure_rate: { denominator: 4, numerator: 1, parts_per_million: 250_000 },
      by_feature: { items: [{ active_users: 2, key: "assistant", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      by_model: { items: [{ active_users: 2, key: "gpt_mobile", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      by_selected_plan: { items: [{ active_users: 2, key: "subscriber", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
      cost_per_active_user_nano_usd: { denominator: 2, numerator: 900 },
      failure_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
      fallback_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
      quota_denial_rate: { denominator: 3, numerator: 0, parts_per_million: 0 },
      request_count: 3,
      request_latency: { p50_ms: 100, p95_ms: 300, p99_ms: 500, samples: 3 },
      requests_per_active_user: { denominator: 2, numerator: 3 },
      time_to_first_token: { p50_ms: 20, p95_ms: 40, p99_ms: 60, samples: 3 },
      usage_by_provenance: [
        { cost_source: "openrouter_usage_cost", provenance: "upstream_reported", values: { ...zeroValues, input_tokens: 10, output_tokens: 20, total_tokens: 30 } },
        { provenance: "calculated", values: { ...zeroValues, cost_nano_usd: 900 } },
        { provenance: "estimated", values: zeroValues },
        { provenance: "unknown", values: zeroValues }
      ]
    },
    end: "2026-08-29T01:00:00Z", provenance: ["calculated", "upstream_reported"],
    start: "2026-08-29T00:00:00Z", values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 }
  };
}

function localDateTime(value: string): string {
  const parsed = new Date(value);
  const local = new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function routeSimulationFixture() {
  return {
    allowed: true, application_id: "app_0123456789abcdef", environment_id: "env_0123456789abcdef",
    environment_kind: "production", explanation: ["production policy allowed"],
    facts: { application_id: "app_0123456789abcdef", authenticated: true, environment_id: "env_0123456789abcdef", environment_kind: "production", feature: "assistant", framing_unit_count: 1, image_units: 0, normalized_claims: {}, platform: "react_native_ios", requested_input_tokens: 99, requested_output_max: 100, revision_id: "rev_0123456789abcdef", rewritten_request_bytes: 1024, streaming: false, tool_calls: 0, trust_level: "app_verified" },
    fact_usage: [{ affects_cel: true, explanation: "Bounded untrusted CEL estimate; never accounting authority.", fact: "request.estimated_input_tokens", role: "policy" }],
    feature: "assistant", limit_plan: "subscriber",
    limits: [{ algorithm: "calendar", hard: true, maximum: 1000, metric: "total_tokens", scope: ["user", "feature"], timezone: "UTC", window: "1d" }],
    model: "gpt_mobile", physical_model: "gpt-5-mini", pricing_confidence: "configured", protocol: "openai_responses",
    reservation: { allocations: [{ algorithm: "calendar", applicable: true, durable: true, metric: "total_tokens", units: 1132 }], applied_output_maximum: 100, cost_bound_known: true, cost_nano_usd_bound: 50, input_accounting: { framing_unit_count: 1, input_token_bound: 1032, maximum_context_tokens: 128000, maximum_framing_tokens_per_request: 4, maximum_framing_tokens_per_unit: 4, method: "utf8_byte_bpe_declared_framing_v1", profile_id: "gpt_mobile_input", required: true, rewritten_request_bytes: 1024 }, pricing_catalog: "mobile_price", total_token_bound: 1132 },
    revision_id: "rev_0123456789abcdef", route: "primary", upstream: "openai", warnings: []
  };
}

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
  it("restores every request-list filter from workspace URL state and sends it to the Admin API", async () => {
    const search: WorkspaceSearch = {
      application: "mobile-app",
      component_kind: "main_app",
      cost_max_nano_usd: "2000",
      cost_min_nano_usd: "1000",
      cursor: "next-request-page",
      end: "2026-08-30T00:00:00Z",
      environment: "production",
      error_code: "upstream_timeout",
      feature: "assistant",
      latency_max_ms: "5000",
      latency_min_ms: "50",
      model: "openai/gpt-5-mini",
      organization: "example",
      platform: "react_native_ios",
      request_id: "req_1123456789abcdef",
      route: "primary",
      sort: "started_at_asc",
      start: "2026-08-29T00:00:00Z",
      status: "failed",
      tokens_max: "4096",
      tokens_min: "10",
      trust_source: "direct_attested",
      upstream: "openrouter",
      user_id: "usr_0123456789abcdef"
    };
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: false } } });

    renderInWorkspace(<RequestsPage />, search);

    await waitFor(() => expect(adminRequestMock).toHaveBeenCalled());
    const listPath = String(adminRequestMock.mock.calls.find(([path]) => String(path).startsWith("/admin/v1/requests?"))?.[0]);
    const query = new URLSearchParams(listPath.split("?")[1]);
    expect(Object.fromEntries(query)).toEqual({
      component_kind: "main_app",
      cost_max_nano_usd: "2000",
      cost_min_nano_usd: "1000",
      cursor: "next-request-page",
      end: "2026-08-30T00:00:00Z",
      environment_id: "env_0123456789abcdef",
      error_code: "upstream_timeout",
      feature: "assistant",
      latency_max_ms: "5000",
      latency_min_ms: "50",
      model: "openai/gpt-5-mini",
      page_size: "50",
      platform: "react_native_ios",
      request_id: "req_1123456789abcdef",
      route: "primary",
      sort: "started_at_asc",
      start: "2026-08-29T00:00:00Z",
      status: "failed",
      tokens_max: "4096",
      tokens_min: "10",
      trust_source: "direct_attested",
      upstream: "openrouter",
      user_id: "usr_0123456789abcdef"
    });
    expect(screen.getByLabelText("Status")).toHaveValue("failed");
    expect(screen.getByLabelText("Model")).toHaveValue("openai/gpt-5-mini");
    const initialLoads = adminRequestMock.mock.calls.filter(([path]) => String(path).startsWith("/admin/v1/requests?")).length;
    dispatchAdminRefresh(["requests"]);
    await waitFor(() => expect(adminRequestMock.mock.calls.filter(([path]) => String(path).startsWith("/admin/v1/requests?")).length).toBe(initialLoads + 1));
  });

  it("writes edited request filters back as validated shareable search state", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: false } } });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<RequestsPage />, {
      application: "mobile-app",
      environment: "production",
      organization: "example"
    });
    await waitFor(() => expect(adminRequestMock).toHaveBeenCalled());
    await user.selectOptions(screen.getByLabelText("Status"), "denied");
    await user.type(screen.getByLabelText("Feature"), "assistant");
    await user.click(screen.getByRole("button", { name: "Apply filters" }));

    expect(updateSearch).toHaveBeenLastCalledWith(expect.objectContaining({
      cursor: undefined,
      feature: "assistant",
      request: undefined,
      status: "denied"
    }));
  });

  it("keeps request pagination server-side by writing only the returned cursor to URL state", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: true, next_cursor: "next-request-page" } } });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<RequestsPage />, {
      application: "mobile-app",
      environment: "production",
      feature: "assistant",
      organization: "example",
      status: "failed"
    });

    await user.click(await screen.findByRole("button", { name: "Next page" }));

    expect(updateSearch).toHaveBeenLastCalledWith({ cursor: "next-request-page", request: undefined });
  });

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

  it("restores and closes an exact pseudonymous user detail from workspace URL state", async () => {
    const environmentID = "env_0123456789abcdef";
    const userID = "usr_0123456789abcdef";
    const selected = { created_at: "2026-08-29T00:00:00Z", environment_id: environmentID, id: userID, identity_providers: ["firebase"], normalized_claims: { plan: "subscriber" }, status: "active" };
    adminRequestMock.mockImplementation(async (path: string) => {
      if (path.startsWith("/admin/v1/users?")) return { data: { items: [selected], page: { has_more: false } } };
      if (path === `/admin/v1/users/${userID}?environment_id=${environmentID}`) return { data: selected };
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<UsersPage />, { environment_id: environmentID, user_id: userID });

    expect(await screen.findByRole("heading", { name: "User detail" })).toBeInTheDocument();
    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/users/${userID}?environment_id=${environmentID}`, expect.anything());
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(updateSearch).toHaveBeenLastCalledWith({ user_id: undefined });
  });

  it("restores and closes an exact legacy installation without sharing revocation state", async () => {
    const installation = {
      attestation_provider: "app_attest", created_at: "2026-08-29T00:00:00Z", dpop_jkt: "A".repeat(43),
      environment_id: "env_0123456789abcdef", id: "ins_0123456789abcdef", last_seen_at: "2026-08-29T00:01:00Z",
      platform: "react_native_ios", status: "active", trust_expires_at: "2026-08-30T00:00:00Z", trust_level: "app_verified",
      user_id: "usr_0123456789abcdef"
    };
    adminRequestMock.mockImplementation(async (path: string) => {
      if (path.startsWith("/admin/v1/installations?")) return { data: { items: [installation], page: { has_more: false } } };
      if (path === `/admin/v1/installations/${installation.id}`) return { data: installation };
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<InstallationsPage />, { environment_id: installation.environment_id, installation_id: installation.id });

    expect(await screen.findByRole("heading", { name: "Installation detail" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review revoke" }));
    expect(screen.getByRole("heading", { name: "Revoke this installation?" })).toBeInTheDocument();
    expect(updateSearch).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(updateSearch).toHaveBeenLastCalledWith({ installation_id: undefined });
  });

  it("restores a complete analytics window and writes filter edits as replacement URL state", async () => {
    const search: WorkspaceSearch = {
      end: "2026-08-29T01:00:00Z",
      environment_id: "env_0123456789abcdef",
      interval: "hour",
      start: "2026-08-29T00:00:00Z"
    };
    adminRequestMock.mockImplementation(async (path: string) => path.includes("/summary")
      ? { data: analyticsFixture() }
      : { data: { interval: path.includes("interval=day") ? "day" : "hour", points: [] } });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<UsagePage />, search);

    expect(await screen.findByRole("heading", { name: "Feature usage" })).toBeInTheDocument();
    expect(screen.getByLabelText("Environment ID")).toHaveValue(search.environment_id);
    expect(screen.getByLabelText("Start")).toHaveValue(localDateTime(search.start!));
    expect(screen.getByLabelText("End")).toHaveValue(localDateTime(search.end!));
    const initialLoads = adminRequestMock.mock.calls.length;
    dispatchAdminRefresh(["usage"]);
    await waitFor(() => expect(adminRequestMock).toHaveBeenCalledTimes(initialLoads + 2));
    await user.selectOptions(screen.getByLabelText("Interval"), "day");
    await user.click(screen.getByRole("button", { name: "Load usage" }));
    expect(updateSearch).toHaveBeenLastCalledWith({
      end: new Date(search.end!).toISOString(),
      environment_id: search.environment_id,
      interval: "day",
      start: new Date(search.start!).toISOString()
    });
  });

  it("restores only non-PII route-simulator shape and never writes claims to URL state", async () => {
    const search: WorkspaceSearch = {
      app_version: "1.2.3",
      authenticated: true,
      environment_id: "env_0123456789abcdef",
      feature: "assistant",
      framing_unit_count: "1",
      platform: "react_native_ios",
      requested_input_tokens: "99",
      requested_output_max: "100",
      revision_id: "rev_0123456789abcdef",
      rewritten_request_bytes: "1024",
      streaming: false,
      trust_level: "app_verified"
    };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith("/config") ? { data: {
      created_at: "2026-08-29T00:00:00Z", created_by: "adm_0123456789abcdef",
      document: { spec: { features: [{ id: "assistant" }] } }, environment_id: search.environment_id,
      id: search.revision_id, state: "active", version: 1
    } } : { data: routeSimulationFixture() });
    const user = userEvent.setup();
    const { updateSearch } = renderInWorkspace(<RouteSimulatorPage />, search);

    await waitFor(() => expect(screen.getByText(/Selected active revision/)).toBeInTheDocument());
    expect(screen.getByLabelText("Requested input tokens (explanatory)")).toHaveValue(99);
    expect(screen.getByLabelText("Requested output maximum")).toHaveValue(100);
    fireEvent.change(screen.getByLabelText("Normalized claims JSON"), { target: { value: '{"plan":"private-value"}' } });
    await user.click(screen.getByRole("button", { name: "Simulate route" }));

    expect(await screen.findByRole("heading", { name: "Allowed" })).toBeInTheDocument();
    const patch = updateSearch.mock.calls.at(-1)?.[0] as Record<string, unknown>;
    expect(patch).toMatchObject({ environment_id: search.environment_id, feature: "assistant", requested_input_tokens: "99", revision_id: search.revision_id });
    expect(patch).not.toHaveProperty("claims");
    expect(JSON.stringify(patch)).not.toMatch(/private-value|credential|reason|secret|bearer|authorization/i);
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

  it("links a selected pseudonymous user to an exact Installation Family filter", async () => {
    const environmentID = "env_0123456789abcdef";
    const userID = "usr_0123456789abcdef";
    adminRequestMock.mockResolvedValue({ data: { items: [{ created_at: "2026-08-29T00:00:00Z", environment_id: environmentID, id: userID, identity_providers: ["firebase"], last_seen_at: "2026-08-29T00:01:00Z", normalized_claims: { plan: "subscriber" }, status: "active" }], page: { has_more: false } } });
    const user = userEvent.setup();
    render(<UsersPage />);
    await user.type(screen.getByLabelText("Environment ID"), environmentID);
    await user.click(screen.getByRole("button", { name: "List users" }));
    await user.click(await screen.findByRole("button", { name: userID }));

    expect(screen.getByRole("link", { name: "View this user's installation families" })).toHaveAttribute("href", `/installation-families?environment_id=${environmentID}&user_id=${userID}`);
  });

  it("explains a user's exact current policy and limits without exposing claim values", async () => {
    const environmentID = "env_0123456789abcdef";
    const userID = "usr_0123456789abcdef";
    adminRequestMock.mockResolvedValue({ data: { items: [{ created_at: "2026-08-29T00:00:00Z", environment_id: environmentID, id: userID, identity_providers: ["firebase"], normalized_claims: {}, status: "active" }], page: { has_more: false } } });
    getUserEffectiveConfigurationMock.mockResolvedValue({ data: effectiveConfigurationFixture() });
    const user = userEvent.setup();
    render(<UsersPage />);
    await user.type(screen.getByLabelText("Environment ID"), environmentID);
    await user.click(screen.getByRole("button", { name: "List users" }));
    await user.click(await screen.findByRole("button", { name: userID }));
    await user.type(screen.getByLabelText("Feature"), "assistant");
    await user.type(screen.getByLabelText("Estimated input tokens"), "2048");
    await user.click(screen.getByRole("button", { name: "Explain current state" }));

    expect(getUserEffectiveConfigurationMock).toHaveBeenCalledWith(userID, expect.objectContaining({ environmentID, estimatedInputTokens: 2048, feature: "assistant" }));
    expect(await screen.findByRole("heading", { name: "Current-state projection" })).toBeInTheDocument();
    expect(screen.getByText("4,096 / request")).toBeInTheDocument();
    expect(screen.getAllByText(/gpt-5-mini/).length).toBeGreaterThan(0);
    expect(screen.getByText("keys: plan")).toBeInTheDocument();
    expect(screen.getByText(/neither reserves quota nor sends an upstream request/i)).toBeInTheDocument();
  });

  it("requires a fresh impact review, typed user ID, reason, and acknowledgement before blocking", async () => {
    const environmentID = "env_0123456789abcdef";
    const userID = "usr_0123456789abcdef";
    const activeUser = { created_at: "2026-08-29T00:00:00Z", environment_id: environmentID, id: userID, identity_providers: ["firebase"], normalized_claims: {}, status: "active" };
    const blockedUser = { ...activeUser, status: "blocked" };
    const impact = {
      access_effect: "deny_and_revoke", action: "block", applicable: true,
      counts: { active_client_components: 2, active_component_refresh_tokens: 2, active_component_sessions: 2, active_installation_families: 1, active_refresh_tokens: 1, active_session_grants: 1 },
      current_status: "active", immediate: true, impact_token: "A".repeat(43), reversible: true,
      summary: "Blocks access and revokes active credentials application-wide."
    };
    adminRequestMock.mockResolvedValue({ data: { items: [activeUser], page: { has_more: false } } });
    getUserOperationImpactMock.mockResolvedValue({ data: impact });
    setApplicationUserBlockedMock.mockResolvedValue({ data: blockedUser });
    const user = userEvent.setup();
    render(<UsersPage />);
    await user.type(screen.getByLabelText("Environment ID"), environmentID);
    await user.click(screen.getByRole("button", { name: "List users" }));
    await user.click(await screen.findByRole("button", { name: userID }));

    expect(setApplicationUserBlockedMock).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Review block" }));
    expect(getUserOperationImpactMock).toHaveBeenCalledWith(userID, environmentID, "block");
    expect(await screen.findByRole("heading", { name: "Block user impact" })).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: "Confirm Block user" });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText("Operator reason"), "Confirmed compromised account");
    await user.type(screen.getByLabelText("Type the exact user ID to confirm"), userID);
    await user.click(screen.getByLabelText(/acknowledge the immediate application-wide effect/i));
    expect(confirm).toBeEnabled();
    await user.click(confirm);

    expect(setApplicationUserBlockedMock).toHaveBeenCalledWith(userID, environmentID, true, {
      acknowledge_immediate_effect: true,
      impact_token: impact.impact_token,
      reason: "Confirmed compromised account"
    });
    expect(await screen.findByRole("status")).toHaveTextContent("Block user completed");
    expect(screen.getAllByText("blocked")).toHaveLength(2);
  });

  it("reviews irreversible installation credential impact before revocation", async () => {
    const installation = {
      attestation_provider: "app_attest",
      created_at: "2026-08-29T00:00:00Z",
      dpop_jkt: "A".repeat(43),
      environment_id: "env_0123456789abcdef",
      id: "ins_0123456789abcdef",
      last_seen_at: "2026-08-29T00:01:00Z",
      platform: "react_native_ios",
      status: "active",
      trust_expires_at: "2026-08-30T00:00:00Z",
      trust_level: "app_verified",
      user_id: "usr_0123456789abcdef"
    };
    adminRequestMock.mockImplementation(async (path: string, _schema: unknown, options?: { body?: unknown; method?: string }) => {
      if (path.startsWith("/admin/v1/installations?")) return { data: { items: [installation], page: { has_more: false } } };
      if (path === `/admin/v1/installations/${installation.id}/revoke` && options?.method === "POST") {
        return { data: { ...installation, revoked_at: "2026-08-29T00:02:00Z", status: "revoked" } };
      }
      throw new Error(`Unexpected request ${path}`);
    });
    const user = userEvent.setup();
    render(<InstallationsPage />);
    await user.type(screen.getByLabelText("Environment ID"), installation.environment_id);
    await user.click(screen.getByRole("button", { name: "List installations" }));
    await user.click(await screen.findByRole("button", { name: "Review revoke" }));

    expect(screen.getByRole("heading", { name: "Revoke this installation?" })).toBeInTheDocument();
    expect(screen.getByText(/Installation revocation is terminal/)).toBeInTheDocument();
    expect(screen.getByText(/Revoked sessions, refresh tokens, and attestation keys stay revoked/)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: "Revoke installation credentials" });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText("Operator reason"), "confirmed compromised device");
    await user.click(screen.getByLabelText(/immediately and permanently revokes this installation/i));
    await user.click(confirm);

    expect(adminRequestMock).toHaveBeenCalledWith(`/admin/v1/installations/${installation.id}/revoke`, expect.anything(), { body: { reason: "confirmed compromised device" }, method: "POST" });
    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Revoke this installation?" })).not.toBeInTheDocument();
  });

  it("renders bounded per-user, latency, rate, dimension, and provenance analytics", async () => {
    adminRequestMock.mockImplementation(async (path: string) => path.includes("/summary") ? { data: {
      analytics: {
        active_users: 2,
        attestation_failure_rate: { denominator: 4, numerator: 1, parts_per_million: 250_000 },
        by_feature: { items: [{ active_users: 2, key: "assistant", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
        by_model: { items: [{ active_users: 2, key: "gpt_mobile", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
        by_selected_plan: { items: [{ active_users: 2, key: "subscriber", request_count: 3, values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 } }], limit: 50, truncated: false },
        cost_per_active_user_nano_usd: { denominator: 2, numerator: 900 },
        failure_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
        fallback_rate: { denominator: 3, numerator: 1, parts_per_million: 333_333 },
        quota_denial_rate: { denominator: 3, numerator: 0, parts_per_million: 0 },
        request_count: 3,
        request_latency: { p50_ms: 100, p95_ms: 300, p99_ms: 500, samples: 3 },
        requests_per_active_user: { denominator: 2, numerator: 3 },
        time_to_first_token: { p50_ms: 20, p95_ms: 40, p99_ms: 60, samples: 3 },
        usage_by_provenance: [
          { cost_source: "openrouter_usage_cost", provenance: "upstream_reported", values: { ...zeroValues, input_tokens: 10, output_tokens: 20, total_tokens: 30 } },
          { provenance: "calculated", values: { ...zeroValues, cost_nano_usd: 900 } },
          { provenance: "estimated", values: zeroValues },
          { provenance: "unknown", values: zeroValues }
        ]
      },
      end: "2026-08-29T01:00:00Z", provenance: ["calculated", "upstream_reported"],
      start: "2026-08-29T00:00:00Z", values: { ...zeroValues, cost_nano_usd: 900, total_tokens: 30 }
    } } : { data: { interval: "hour", points: [] } });
    const user = userEvent.setup();
    render(<UsagePage />);
    await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
    await user.click(screen.getByRole("button", { name: "Load usage" }));

    expect(await screen.findByText("Requests / active user")).toBeInTheDocument();
    expect(screen.getByText("1.5")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Feature usage" })).toBeInTheDocument();
    expect(screen.getByText("gpt_mobile")).toBeInTheDocument();
    expect(screen.getByText("subscriber")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Usage provenance" })).toBeInTheDocument();
    expect(screen.getByText("upstream_reported")).toBeInTheDocument();
    expect(screen.queryByText("openrouter_usage_cost")).not.toBeInTheDocument();
  });

  it("renders token and cost provenance independently for each attempt", async () => {
	const request = { ...requestProvenance, attempts: [{
	  attempt_number: 1, completed_at: "2026-08-29T00:00:00.400Z", cost_provenance: "unknown",
	  failure_code: "timeout", http_status: 504, id: "atm_0123456789abcdef", model: "openai/gpt",
	  route: "primary", started_at: "2026-08-29T00:00:00Z", status: "failed",
	  upstream: "openrouter", usage_provenance: "unknown"
	}, {
	  attempt_number: 2, completed_at: "2026-08-29T00:00:02.500Z", cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost",
	  first_byte_at: "2026-08-29T00:00:01Z", first_token_at: "2026-08-29T00:00:01.500Z", http_status: 200, id: "atm_0123456789abcdeg", model: "openai/gpt",
	  route: "fallback", started_at: "2026-08-29T00:00:00.500Z", status: "succeeded", upstream: "openrouter",
	  usage: { cost_nano_usd: 321, input_tokens: 10, logical_requests: 0, output_tokens: 20, total_tokens: 30 }, usage_provenance: "unknown"
	}], client_component_id: "cmp_0123456789abcdef", completed_at: "2026-08-29T00:00:03Z", component_definition_id: "ios-main", component_kind: "main_app", environment_id: "env_0123456789abcdef", feature: "assistant", framework: "swift-openai", framework_version: "4.6.0",
	  id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef",
	  installation_family_id: "fam_0123456789abcdef",
	  protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z", status: "succeeded",
	  trust_source: "direct_attested",
	  usage: { cost_nano_usd: 321, input_tokens: 10, logical_requests: 1, output_tokens: 20, total_tokens: 30 },
	  user_id: "usr_0123456789abcdef" };
	adminRequestMock.mockImplementation(async (path: string) => path.endsWith(request.id) ? { data: request } : { data: { items: [request], page: { has_more: false } } });
	const user = userEvent.setup();
	render(<RequestsPage />);
	await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
	await user.click(screen.getByRole("button", { name: "List requests" }));
	await user.click(await screen.findByRole("button", { name: "req_0123456789abcdef" }));
	expect(await screen.findByRole("heading", { name: "Request detail" })).toBeInTheDocument();
	expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/requests/req_0123456789abcdef", expect.anything());
	expect(screen.getByRole("heading", { name: "Aggregate usage" })).toBeInTheDocument();
	expect(screen.getByRole("heading", { name: "Ordered upstream attempts" })).toBeInTheDocument();
	expect(screen.getByText("1 s")).toBeInTheDocument();
	expect(screen.getAllByText("321")).toHaveLength(2);
	expect(screen.getByText("fallback")).toBeInTheDocument();
	expect(screen.getByText("504")).toBeInTheDocument();
	const timeoutLinks = screen.getAllByRole("link", { name: "timeout" });
	expect(timeoutLinks.length).toBeGreaterThan(0);
	for (const link of timeoutLinks) {
	  expect(link).toHaveAttribute("href", "https://docs.latchway.dev/errors/timeout");
	}
	expect(screen.getByText("upstream_reported")).toBeInTheDocument();
	expect(screen.getByText("openrouter_usage_cost")).toBeInTheDocument();
	expect(screen.getAllByText("swift-openai 4.6.0")).toHaveLength(1);
	expect(screen.getByText("cmp_0123456789abcdef")).toBeInTheDocument();
	expect(screen.getByText("direct_attested")).toBeInTheDocument();
	expect(screen.getByText(/closed, sanitized vocabulary/)).toBeInTheDocument();
	expect(screen.queryByText("upstream_timeout")).not.toBeInTheDocument();
  });

  it("loads a recorded request explanation without reconstructing missing historical claims", async () => {
    const request = {
      ...requestProvenance, attempts: [], completed_at: "2026-08-29T00:00:01Z",
      environment_id: "env_0123456789abcdef", feature: "assistant", id: "req_0123456789abcdef",
      installation_id: "ins_0123456789abcdef", protocol: "openai_chat",
      started_at: "2026-08-29T00:00:00Z", status: "succeeded", user_id: "usr_0123456789abcdef"
    };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(request.id) ? { data: request } : { data: { items: [request], page: { has_more: false } } });
    getRequestEffectiveConfigurationMock.mockResolvedValue({ data: effectiveConfigurationFixture("recorded_request") });
    const user = userEvent.setup();
    render(<RequestsPage />);
    await user.type(screen.getByLabelText("Environment ID"), request.environment_id);
    await user.click(screen.getByRole("button", { name: "List requests" }));
    await user.click(await screen.findByRole("button", { name: request.id }));
    expect(await screen.findByText(/does not reconstruct them from current state/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Explain recorded configuration" }));

    expect(getRequestEffectiveConfigurationMock).toHaveBeenCalledWith(request.id);
    expect(await screen.findByRole("heading", { name: "Recorded decision inputs" })).toBeInTheDocument();
    expect(screen.getByText(/Historical claim values were not persisted and are not inferred/i)).toBeInTheDocument();
    expect(screen.getByText("Historical claim values remain unavailable.")).toBeInTheDocument();
  });

  it("rejects request detail that does not match the selected environment", async () => {
    const listed = { ...requestProvenance, attempts: [], completed_at: "2026-08-29T00:00:01Z", environment_id: "env_0123456789abcdef", feature: "assistant", id: "req_0123456789abcdef", installation_id: "ins_0123456789abcdef", protocol: "openai_chat", started_at: "2026-08-29T00:00:00Z", status: "succeeded", user_id: "usr_0123456789abcdef" };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(listed.id) ? { data: { ...listed, environment_id: "env_ffffffffffffffff" } } : { data: { items: [listed], page: { has_more: false } } });
    const user = userEvent.setup();
    render(<RequestsPage />);
    await user.type(screen.getByLabelText("Environment ID"), listed.environment_id);
    await user.click(screen.getByRole("button", { name: "List requests" }));
    await user.click(await screen.findByRole("button", { name: listed.id }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Request detail mismatch");
    expect(screen.queryByRole("heading", { name: "Request detail" })).not.toBeInTheDocument();
  });

  it.each([
    ["Cost", CostPage, "Load cost", "Cost provenance", "Latency distributions"],
    ["Latency", LatencyPage, "Load latency", "Latency distributions", "Cost provenance"],
    ["Errors", ErrorsPage, "Load errors", "Error and recovery rates", "Cost provenance"],
    ["Attestation failures", AttestationFailuresPage, "Load attestation failures", "Attestation rejection aggregate", "Cost provenance"]
  ] as const)("renders %s as a focused analytics page", async (title, Page, loadLabel, expectedHeading, excludedHeading) => {
    adminRequestMock.mockImplementation(async (path: string) => path.includes("/summary") ? { data: analyticsFixture() } : { data: { interval: "hour", points: [] } });
    const user = userEvent.setup();
    render(<Page />);
    await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
    await user.click(screen.getByRole("button", { name: loadLabel }));

    expect(await screen.findByRole("heading", { name: expectedHeading })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: title })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: excludedHeading })).not.toBeInTheDocument();
  });

  it("renders authoritative scope, exact reservation, applicable limits, and fact roles", async () => {
    adminRequestMock.mockResolvedValue({ data: routeSimulationFixture() });
    const user = userEvent.setup();
    render(<RouteSimulatorPage />);
    await user.type(screen.getByLabelText("Revision ID"), "rev_0123456789abcdef");
    await user.type(screen.getByLabelText("Feature"), "assistant");
    await user.click(screen.getByRole("button", { name: "Simulate route" }));

    expect(await screen.findByRole("heading", { name: "Exact conservative reservation" })).toBeInTheDocument();
    expect(screen.getByText("app_0123456789abcdef")).toBeInTheDocument();
    expect(screen.getByText("rev_0123456789abcdef")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Applicable limits" })).toBeInTheDocument();
    expect(screen.getByText("requested_input_tokens")).toBeInTheDocument();
    expect(screen.getByText("request.estimated_input_tokens")).toBeInTheDocument();
    expect(screen.getByText("policy")).toBeInTheDocument();
  });

  it("loads exact active route context and rejects a cross-environment simulation result", async () => {
    const simulation = { ...routeSimulationFixture(), environment_id: "env_ffffffffffffffff" };
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith("/config") ? { data: {
      created_at: "2026-08-29T00:00:00Z", created_by: "adm_0123456789abcdef",
      document: { spec: { features: [{ id: "assistant" }, { id: "search" }] } },
      environment_id: "env_0123456789abcdef", id: "rev_0123456789abcdef", state: "active", version: 1
    } } : { data: simulation });
    const user = userEvent.setup();
    render(<RouteSimulatorPage />);
    await user.type(screen.getByLabelText("Environment context ID"), "env_0123456789abcdef");
    await user.click(screen.getByRole("button", { name: "Load active route context" }));

    expect(await screen.findByText(/Selected active revision/)).toHaveTextContent("2 features");
    expect(screen.getByLabelText("Revision ID")).toHaveValue("rev_0123456789abcdef");
    expect(screen.getByLabelText("Feature")).toHaveValue("assistant");
    await user.click(screen.getByRole("button", { name: "Simulate route" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Route context mismatch");
    expect(screen.queryByRole("heading", { name: "Allowed" })).not.toBeInTheDocument();
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

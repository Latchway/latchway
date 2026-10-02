import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, getRequestEffectiveConfigurationMock } = vi.hoisted(() => ({
  adminRequestMock: vi.fn(),
  getRequestEffectiveConfigurationMock: vi.fn()
}));

vi.mock("../../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/admin")>()),
  adminRequest: adminRequestMock,
  getRequestEffectiveConfiguration: getRequestEffectiveConfigurationMock
}));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { capabilities: [], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: React.ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { AdminRequestError } from "../../api/auth";
import { dispatchAdminRefresh } from "../../api/admin-events";
import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../../app/workspace-context-value";
import { RequestsPage } from "./requests-page";

const ENV = "env_0123456789abcdef";
const REQUEST = "req_0123456789abcdef";

const succeededAttempt = {
  attempt_number: 2, completed_at: "2026-08-29T00:00:02.500Z", cost_provenance: "upstream_reported", cost_source: "openrouter_usage_cost",
  first_byte_at: "2026-08-29T00:00:01Z", first_token_at: "2026-08-29T00:00:01.500Z", http_status: 200, id: "atm_0123456789abcdeg", model: "openai/gpt",
  route: "fallback", started_at: "2026-08-29T00:00:00.500Z", status: "succeeded", upstream: "openrouter",
  usage: { cost_nano_usd: 321, input_tokens: 10, logical_requests: 0, output_tokens: 20, total_tokens: 30 }, usage_provenance: "upstream_reported"
};
const failedAttempt = {
  attempt_number: 1, completed_at: "2026-08-29T00:00:00.400Z", cost_provenance: "unknown", failure_code: "timeout", http_status: 504,
  id: "atm_0123456789abcdef", model: "openai/gpt", provider_error: { category: "rate_limit_exceeded", request_id: "req-provider-123" },
  route: "primary", started_at: "2026-08-29T00:00:00Z", status: "failed", upstream: "openai", usage_provenance: "unknown"
};
const stages = [
  { completed_at: "2026-08-29T00:00:00.003Z", config_revision_id: "rev_0123456789abcdef", duration_ms: 3, number: 1, outcome: "succeeded", stage: "identity_verified", started_at: "2026-08-29T00:00:00Z" },
  { completed_at: "2026-08-29T00:00:00.005Z", config_revision_id: "rev_0123456789abcdef", duration_ms: 2, limit_algorithm: "calendar", limit_maximum: 50000, limit_metric: "total_tokens", limit_plan_key: "free", limit_rule_key: "A".repeat(43), number: 2, outcome: "succeeded", stage: "quota_rule_evaluated", started_at: "2026-08-29T00:00:00.003Z" }
];

function requestFixture(overrides: Record<string, unknown> = {}) {
  return {
    attempts: [failedAttempt, succeededAttempt], caller_sdk: "ios", client_component_id: "cmp_0123456789abcdef", completed_at: "2026-08-29T00:00:03Z",
    component_definition_id: "ios-main", component_kind: "main_app", config_revision_id: "rev_0123456789abcdef", decision_stages: stages,
    environment_id: ENV, feature: "assistant", framework: "swift-openai", framework_version: "4.6.0", id: REQUEST,
    installation_family_id: "fam_0123456789abcdef", installation_id: "ins_0123456789abcdef", protocol: "openai_chat",
    selected_limit_plan: "free", selected_model: "gpt_mobile", selected_physical_model: "gpt-5-mini", selected_route: "primary", selected_upstream: "openai",
    started_at: "2026-08-29T00:00:00Z", status: "succeeded", trust_source: "direct_attested",
    usage: { cost_nano_usd: 321, input_tokens: 10, logical_requests: 1, output_tokens: 20, total_tokens: 30 },
    user_id: "usr_0123456789abcdef", ...overrides
  };
}

function listCalls(): URLSearchParams[] {
  return adminRequestMock.mock.calls.map(([path]) => String(path)).filter((path) => path.startsWith("/admin/v1/requests?")).map((path) => new URLSearchParams(path.split("?")[1]));
}

/** Renders the page with URL search state held in React state, so navigation re-renders like the router would. */
function renderRequests(initial: WorkspaceSearch = {}) {
  const updates: Array<Partial<WorkspaceSearch>> = [];
  const organization = { created_at: "2026-08-29T00:00:00Z", display_name: "Example", id: "org_0123456789abcdef", slug: "example" };
  const application = { created_at: "2026-08-29T00:00:00Z", display_name: "Mobile App", id: "app_0123456789abcdef", organization_id: organization.id, slug: "mobile-app", status: "active" as const };
  const environment = { application_id: application.id, created_at: "2026-08-29T00:00:00Z", display_name: "Production", id: ENV, kind: "production" as const, slug: "production", status: "active" as const };
  function Harness() {
    const [search, setSearch] = useState<WorkspaceSearch>({ application: "mobile-app", environment: "production", organization: "example", ...initial });
    const value: WorkspaceContextValue = {
      application, applications: [application], environment, environments: [environment], invalidApplication: false, invalidEnvironment: false,
      isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(),
      updateSearch: (patch) => { updates.push(patch); setSearch((current) => ({ ...current, ...patch })); }
    };
    return <WorkspaceContext.Provider value={value}><RequestsPage /></WorkspaceContext.Provider>;
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><Harness /></QueryClientProvider>);
  return { updates };
}

beforeEach(() => {
  adminRequestMock.mockReset();
  getRequestEffectiveConfigurationMock.mockReset();
});
afterEach(cleanup);

describe("Requests", () => {
  it("restores every filter, range, sort and page size from the URL and sends them to the Admin API", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: false } } });
    renderRequests({
      component_kind: "main_app", cost_max_nano_usd: "2000", cost_min_nano_usd: "1000", cursor: "next-request-page", end: "2026-08-30T00:00:00Z",
      error_code: "upstream_timeout", feature: "assistant", latency_max_ms: "5000", latency_min_ms: "50", model: "openai/gpt-5-mini",
      page_size: "100", platform: "react_native_ios", request_id: "req_1123456789abcdef", route: "primary", sort: "started_at_asc",
      start: "2026-08-29T00:00:00Z", status: "failed", tokens_max: "4096", tokens_min: "10", trust_source: "direct_attested",
      upstream: "openrouter", user_id: "usr_0123456789abcdef"
    });
    await waitFor(() => expect(listCalls()).toHaveLength(1));
    expect(Object.fromEntries(listCalls()[0] ?? [])).toEqual({
      component_kind: "main_app", cost_max_nano_usd: "2000", cost_min_nano_usd: "1000", cursor: "next-request-page", end: "2026-08-30T00:00:00Z",
      environment_id: ENV, error_code: "upstream_timeout", feature: "assistant", latency_max_ms: "5000", latency_min_ms: "50", model: "openai/gpt-5-mini",
      page_size: "100", platform: "react_native_ios", request_id: "req_1123456789abcdef", route: "primary", sort: "started_at_asc",
      start: "2026-08-29T00:00:00Z", status: "failed", tokens_max: "4096", tokens_min: "10", trust_source: "direct_attested",
      upstream: "openrouter", user_id: "usr_0123456789abcdef"
    });
    expect(screen.getByRole("button", { name: /Outcome:\s*Failed/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /More filters:\s*8/ })).toBeInTheDocument();
    expect(await screen.findByText("No requests match")).toBeInTheDocument();
  });

  it("applies quick views and filters as replacement URL state", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: false } } });
    const user = userEvent.setup();
    const { updates } = renderRequests();
    await waitFor(() => expect(listCalls()).toHaveLength(1));
    await user.click(screen.getByRole("button", { name: /^Slow/ }));
    expect(updates.at(-1)).toMatchObject({ cursor: undefined, latency_min_ms: "2000", request: undefined, status: undefined });
    await waitFor(() => expect(listCalls().at(-1)?.get("latency_min_ms")).toBe("2000"));
    expect(screen.getByRole("button", { name: /^Slow/ })).toHaveAttribute("aria-pressed", "true");

    await user.click(screen.getByRole("button", { name: /^Outcome:/ }));
    await user.click(screen.getByRole("menuitem", { name: "Denied" }));
    await waitFor(() => expect(listCalls().at(-1)?.get("status")).toBe("denied"));
    expect(listCalls().at(-1)?.get("latency_min_ms")).toBe("2000");

    await user.click(screen.getByRole("button", { name: /^Feature:/ }));
    await user.type(screen.getByLabelText("Feature"), "assistant");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(listCalls().at(-1)?.get("feature")).toBe("assistant"));
  });

  it("validates More filters and converts seconds and dollars for the API", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [], page: { has_more: false } } });
    const user = userEvent.setup();
    renderRequests();
    await waitFor(() => expect(listCalls()).toHaveLength(1));
    await user.click(screen.getByRole("button", { name: /^More filters/ }));
    await user.type(screen.getByLabelText("Duration at least"), "3");
    await user.type(screen.getByLabelText("Duration at most"), "2");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(screen.getByRole("alert")).toHaveTextContent("minimum no larger than the maximum");
    await user.clear(screen.getByLabelText("Duration at most"));
    await user.type(screen.getByLabelText("Cost at least"), "0.02");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(listCalls().at(-1)?.get("latency_min_ms")).toBe("3000"));
    expect(listCalls().at(-1)?.get("cost_min_nano_usd")).toBe("20000000");
  });

  it("loads more with the server cursor, appending rather than replacing rows", async () => {
    adminRequestMock.mockImplementation(async (path: string) => path.includes("cursor=page-2")
      ? { data: { items: [requestFixture({ id: "req_1123456789abcdef" })], page: { has_more: false } } }
      : { data: { items: [requestFixture()], page: { has_more: true, next_cursor: "page-2" } } });
    const user = userEvent.setup();
    renderRequests();
    expect(await screen.findByText("1 shown · more available")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Load 50 More" }));
    expect(await screen.findByText("2 shown · that's all")).toBeInTheDocument();
    expect(listCalls().at(-1)?.get("cursor")).toBe("page-2");
  });

  it("holds new arrivals behind a notice instead of shifting the list", async () => {
    adminRequestMock.mockResolvedValue({ data: { items: [requestFixture()], page: { has_more: false } } });
    const user = userEvent.setup();
    renderRequests();
    await screen.findByText("1 shown · that's all");
    act(() => dispatchAdminRefresh(["requests"]));
    const notice = await screen.findByRole("button", { name: /New requests may have arrived/ });
    expect(listCalls()).toHaveLength(1);
    await user.click(notice);
    await waitFor(() => expect(listCalls()).toHaveLength(2));
  });

  it("opens a request from Go to ID and explains outcome, stages, attempts and provenance", async () => {
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(REQUEST) ? { data: requestFixture() } : { data: { items: [], page: { has_more: false } } });
    const user = userEvent.setup();
    const { updates } = renderRequests();
    await waitFor(() => expect(listCalls()).toHaveLength(1));
    await user.type(screen.getByLabelText("Go to a request or user ID"), "timeout{Enter}");
    expect(screen.getByText(/Search isn't available/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Go to a request or user ID"));
    await user.type(screen.getByLabelText("Go to a request or user ID"), `${REQUEST}{Enter}`);
    expect(updates.at(-1)).toEqual({ request: REQUEST });

    await screen.findByText("Answered by openrouter after 1 failed attempt.");
    const drawer = screen.getByRole("complementary", { name: REQUEST });
    expect(within(drawer).getByText("Limit checked")).toBeInTheDocument();
    expect(within(drawer).getByText("50,000 total tokens · free plan")).toBeInTheDocument();
    expect(within(drawer).getByRole("img", { name: /2 decision stages/ })).toBeInTheDocument();
    expect(within(drawer).getByText("The provider was rate-limiting this key.")).toBeInTheDocument();
    expect(within(drawer).getByRole("button", { name: /Copy provider request ID req-provider-123/ })).toBeInTheDocument();
    expect(within(drawer).getByText("504")).toBeInTheDocument();
    expect(within(drawer).getAllByText("321 (ledger; provenance unavailable)").length).toBeGreaterThan(0);
    expect(within(drawer).getByText(/openrouter_usage_cost/)).toBeInTheDocument();
    expect(within(drawer).getByText("swift-openai 4.6.0", { exact: false })).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: "timeout" })).toHaveAttribute("href", "https://docs.latchway.dev/errors/timeout");
    expect(within(drawer).getByText(/closed, sanitized vocabulary/)).toBeInTheDocument();

    await user.click(within(drawer).getByRole("button", { name: "This user's requests" }));
    expect(updates.at(-1)).toMatchObject({ request: undefined, user_id: "usr_0123456789abcdef" });
  });

  it("says older requests were recorded before stages were kept, and loads the recorded explanation", async () => {
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(REQUEST)
      ? { data: requestFixture({ attempts: [], decision_stages: [] }) }
      : { data: { items: [], page: { has_more: false } } });
    getRequestEffectiveConfigurationMock.mockResolvedValue({ data: {
      decision_stages: [], environment_id: ENV, environment_kind: "production", evaluation_mode: "recorded_request", feature: "assistant",
      inputs: [{ availability: "unavailable", detail: "Historical claim values were not persisted and are not inferred.", fact: "normalized_claims", source: "historical_request" }],
      limit_plan: "free", limit_plan_source: "durable_request_record", limits: [], policy_outcome: "allowed", protocol: "openai_chat",
      revision_id: "rev_0123456789abcdef", routes: [], subject: { id: REQUEST, kind: "request", user_id: "usr_0123456789abcdef" }, warnings: ["Historical claim values remain unavailable."]
    } });
    const user = userEvent.setup();
    renderRequests({ request: REQUEST });
    await screen.findByText(/Recorded before decision stages were kept/);
    const drawer = screen.getByRole("complementary", { name: REQUEST });
    await user.click(within(drawer).getByRole("button", { name: "Explain This Request" }));
    expect(getRequestEffectiveConfigurationMock).toHaveBeenCalledWith(REQUEST);
    expect(await within(drawer).findByRole("heading", { name: "Recorded decision inputs" })).toBeInTheDocument();
    expect(within(drawer).getByText("Historical claim values remain unavailable.")).toBeInTheDocument();
  });

  it("rejects request detail from another environment and names a missing request", async () => {
    adminRequestMock.mockImplementation(async (path: string) => path.endsWith(REQUEST)
      ? { data: requestFixture({ environment_id: "env_ffffffffffffffff" }) }
      : { data: { items: [], page: { has_more: false } } });
    renderRequests({ request: REQUEST });
    expect(await screen.findByRole("alert")).toHaveTextContent("Request detail mismatch");
    expect(screen.queryByText("Summary")).not.toBeInTheDocument();
    cleanup();

    adminRequestMock.mockImplementation(async (path: string) => {
      if (path.endsWith(REQUEST)) throw new AdminRequestError({ code: "resource_not_found", detail: "Not found.", retryable: false, status: 404, title: "Resource not found" });
      return { data: { items: [], page: { has_more: false } } };
    });
    renderRequests({ request: REQUEST });
    expect(await screen.findByRole("alert")).toHaveTextContent(`No request ${REQUEST} in Mobile App · Production`);
  });

  it("moves between loaded requests with the arrow keys and closes on Escape", async () => {
    adminRequestMock.mockImplementation(async (path: string) => {
      const id = path.split("/").at(-1) ?? "";
      if (id.startsWith("req_")) return { data: requestFixture({ id }) };
      return { data: { items: [requestFixture(), requestFixture({ id: "req_1123456789abcdef" })], page: { has_more: false } } };
    });
    const user = userEvent.setup();
    const { updates } = renderRequests({ request: REQUEST });
    await screen.findByRole("complementary", { name: REQUEST });
    await screen.findByText("2 shown · that's all");
    await user.keyboard("{ArrowDown}");
    expect(updates.at(-1)).toEqual({ request: "req_1123456789abcdef" });
    await screen.findByRole("complementary", { name: "req_1123456789abcdef" });
    await user.keyboard("{Escape}");
    expect(updates.at(-1)).toEqual({ request: undefined });
  });
});

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock, compatibility } = vi.hoisted(() => ({ adminRequestMock: vi.fn(), compatibility: { mutationAllowed: true } }));

vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));
vi.mock("../../api/session", () => ({
  useConsoleSession: () => ({ data: { mode: "configured", session: { administrator: { email: "owner@example.test", enabled: true, id: "adm_0123456789abcdef" }, capabilities: ["activate_configuration", "manage_secrets", "inspect_users"], expires_at: null, memberships: [{ organization_id: "org_0123456789abcdef", role: "admin" }], organization_id: "org_0123456789abcdef" } } })
}));
vi.mock("../../app/console-compatibility-context", () => ({ useConsoleCompatibility: () => compatibility }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children, className, to }: { children: React.ReactNode; className?: string; to: string }) => <a className={className} href={to}>{children}</a>
}));

import { ids, instant, mutationsOf, renderWithWorkspace } from "../../test/workspace-harness";
import { SecretsPage } from "../build/secrets-page";
import { DraftChangesPage } from "../changes/changes-pages";
import type { JSONRecord } from "../configuration-slice";
import { ApplicationsSettingsPage } from "./settings-pages";

type Options = { body?: Record<string, unknown>; etag?: string; method?: string } | undefined;

const application = { created_at: instant, display_name: "Mobile", id: ids.application, organization_id: ids.organization, slug: "mobile", status: "active" };
const production = { active_revision_id: ids.activeRevision, application_id: ids.application, created_at: instant, display_name: "Production", id: ids.environment, kind: "production", slug: "production", status: "active" };
const live: JSONRecord = { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: { application: "mobile" }, spec: { upstreams: [{ authentication: { secretRef: "secret/openai_key", type: "bearer" }, baseUrl: "https://api.example.test/v1", id: "openai", type: "openai_compatible" }] } };
const secret = (name: string, id: string, version = 1, rotatedDaysAgo = 1) => ({ algorithm: "aes-256-gcm", created_at: new Date(Date.now() - rotatedDaysAgo * 86_400_000).toISOString(), environment_id: ids.environment, id, master_key_id: "mk1", name, version });

function server() {
  const state: { draft?: { document: JSONRecord; etag: string }; environments: Array<typeof production>; secrets: Array<ReturnType<typeof secret>> } = { environments: [production], secrets: [secret("openai_key", "sec_0123456789abcdef", 3, 120), secret("unused_key", "sec_1123456789abcdef")] };
  adminRequestMock.mockImplementation((path: string, _schema: unknown, options: Options) => {
    const method = options?.method ?? "GET";
    if (path.startsWith("/admin/v1/applications?")) return Promise.resolve({ data: { items: [application], page: { has_more: false } } });
    if (path === `/admin/v1/applications/${ids.application}/environments` && method === "GET") return Promise.resolve({ data: { items: state.environments } });
    if (path === `/admin/v1/applications/${ids.application}/environments` && method === "POST") { const created = { ...production, active_revision_id: undefined, display_name: options?.body?.display_name, id: "env_2123456789abcdef", kind: options?.body?.kind, slug: options?.body?.slug } as unknown as typeof production; state.environments = [...state.environments, created]; return Promise.resolve({ data: created }); }
    if (path === `/admin/v1/environments/${ids.environment}/disable`) { state.environments = state.environments.map((environment) => (environment.id === ids.environment ? { ...environment, status: "disabled" } : environment)); return Promise.resolve({ data: state.environments[0] }); }
    if (path === `/admin/v1/environments/${ids.environment}/config` && method === "GET") return Promise.resolve({ data: { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: live, environment_id: ids.environment, id: ids.activeRevision, state: "active", version: 1 }, etag: '"active"' });
    if (path.startsWith(`/admin/v1/environments/${ids.environment}/config-revisions?`)) return Promise.resolve({ data: { items: [state.draft ? { created_at: instant, created_by: "adm_0123456789abcdef", document: state.draft.document, environment_id: ids.environment, id: ids.draftRevision, state: "valid", version: 2 } : { activated_at: instant, created_at: instant, created_by: "adm_0123456789abcdef", document: live, environment_id: ids.environment, id: ids.activeRevision, state: "active", version: 1 }], page: { has_more: false } } });
    if (path === `/admin/v1/environments/${ids.environment}/config-revisions` && method === "POST") { state.draft = { document: live, etag: '"d1"' }; return Promise.resolve({ data: { created_at: instant, created_by: "adm_0123456789abcdef", document: live, environment_id: ids.environment, id: ids.draftRevision, state: "draft", version: 2 }, etag: '"d1"' }); }
    if (path === `/admin/v1/config-revisions/${ids.draftRevision}` && method === "GET" && state.draft) return Promise.resolve({ data: { created_at: instant, created_by: "adm_0123456789abcdef", document: state.draft.document, environment_id: ids.environment, id: ids.draftRevision, state: "valid", version: 2 }, etag: state.draft.etag });
    if (path === `/admin/v1/config-revisions/${ids.draftRevision}` && method === "PATCH") { state.draft = { document: options?.body as JSONRecord, etag: '"d2"' }; return Promise.resolve({ data: { created_at: instant, created_by: "adm_0123456789abcdef", document: state.draft.document, environment_id: ids.environment, id: ids.draftRevision, state: "draft", version: 2 }, etag: '"d2"' }); }
    if (path.endsWith("/validate")) return Promise.resolve({ data: { checked_at: instant, issues: [], valid: true } });
    if (path.endsWith("/plan")) return Promise.resolve({ data: { changes: [], from_revision_id: ids.activeRevision, to_revision_id: ids.draftRevision, warnings: [] } });
    if (path.startsWith("/admin/v1/secrets?")) return Promise.resolve({ data: { items: state.secrets, page: { has_more: false } } });
    if (path === "/admin/v1/secrets" && method === "POST") { const created = secret(String(options?.body?.name), "sec_2123456789abcdef"); state.secrets = [...state.secrets, created]; return Promise.resolve({ data: created }); }
    const removed = /^\/admin\/v1\/secrets\/(sec_[A-Za-z0-9]+)$/.exec(path);
    if (removed && method === "DELETE") { state.secrets = state.secrets.filter((item) => item.id !== removed[1]); return Promise.resolve({ data: undefined }); }
    return Promise.reject(new Error(`Unexpected request: ${method} ${path}`));
  });
  return state;
}

beforeEach(() => {
  adminRequestMock.mockReset();
  compatibility.mutationAllowed = true;
});

describe("Applications", () => {
  it("adds an environment and disables one only with a reason, the typed app/env and an acknowledgement", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<ApplicationsSettingsPage />);
    expect(await screen.findByText(ids.activeRevision)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add Environment" }));
    const drawer = screen.getByRole("complementary", { name: "Add environment" });
    await user.click(within(drawer).getByRole("radio", { name: /Staging/ }));
    expect(within(drawer).getByLabelText("Slug")).toHaveValue("staging");
    await user.click(within(drawer).getByRole("button", { name: "Add Environment" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toContain(`POST /admin/v1/applications/${ids.application}/environments`));
    expect(adminRequestMock.mock.calls.find(([, , options]) => (options as Options)?.method === "POST")?.[2]).toMatchObject({ body: { display_name: "Staging", kind: "staging", slug: "staging" } });

    const row = (await screen.findAllByText("production", { selector: "td" }))[0]?.closest("tr") as HTMLElement;
    await user.click(within(row).getByRole("button", { name: "Disable" }));
    const dialog = screen.getByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: "Disable Environment" });
    await user.type(within(dialog).getByLabelText("Reason"), "Leaked build in the wild");
    await user.type(within(dialog).getByLabelText(/to confirm/), "mobile/production");
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(confirm);
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toContain(`POST /admin/v1/environments/${ids.environment}/disable`));
    expect(adminRequestMock.mock.calls.find(([path]) => String(path).endsWith("/disable"))?.[2]).toEqual({ body: { reason: "Leaked build in the wild" }, method: "POST" });
  });
});

describe("Secrets", () => {
  it("adds a secret whose value is cleared before the request settles", async () => {
    const user = userEvent.setup();
    server();
    let duringRequest: string | undefined;
    const base = adminRequestMock.getMockImplementation();
    adminRequestMock.mockImplementation((path: string, schema: unknown, options: Options) => {
      if (path === "/admin/v1/secrets" && options?.method === "POST") duringRequest = (document.getElementById("secret-value") as HTMLInputElement).value;
      return base?.(path, schema, options);
    });
    renderWithWorkspace(<SecretsPage />);
    expect(await screen.findByText("Not rotated in 90 days: openai_key.")).toBeInTheDocument();
    expect(screen.getByText(/AI connection openai \(live\)/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add Secret" }));
    const drawer = screen.getByRole("complementary", { name: "Add secret" });
    await user.type(within(drawer).getByLabelText("Name"), "unused_key");
    expect(within(drawer).getByText("This name already exists here. Rotate it instead.")).toBeInTheDocument();
    await user.clear(within(drawer).getByLabelText("Name"));
    await user.type(within(drawer).getByLabelText("Name"), "anthropic_key");
    fireEvent.change(within(drawer).getByLabelText("Value"), { target: { value: "sk-test-only-value" } });
    await user.click(within(drawer).getByRole("button", { name: "Add Secret" }));
    expect(await screen.findByText(/anthropic_key was added/)).toBeInTheDocument();
    expect(adminRequestMock.mock.calls.find(([path, , options]) => path === "/admin/v1/secrets" && (options as Options)?.method === "POST")?.[2]).toMatchObject({ body: { environment_id: ids.environment, name: "anthropic_key", value: "sk-test-only-value" } });
    expect(duringRequest).toBe("");
  });

  it("blocks deleting a secret that configuration uses, and deletes an unused one after its name is typed", async () => {
    const user = userEvent.setup();
    server();
    renderWithWorkspace(<SecretsPage />);
    const used = (await screen.findByText("openai_key", { selector: ".lw-mono" })).closest("tr") as HTMLElement;
    await user.click(within(used).getByRole("button", { name: "Delete" }));
    const blocked = screen.getByRole("alertdialog", { name: "openai_key is still in use" });
    expect(blocked).toHaveTextContent("AI connection openai (live)");
    await user.click(within(blocked).getByRole("button", { name: "Close" }));
    const unused = screen.getByText("unused_key", { selector: ".lw-mono" }).closest("tr") as HTMLElement;
    await user.click(within(unused).getByRole("button", { name: "Delete" }));
    const dialog = screen.getByRole("alertdialog", { name: "Delete unused_key?" });
    expect(dialog).toHaveTextContent("can never be used again");
    fireEvent.change(within(dialog).getByLabelText(/to confirm/), { target: { value: "unused_key" } });
    await user.click(within(dialog).getByRole("button", { name: "Delete Secret" }));
    await waitFor(() => expect(mutationsOf(adminRequestMock)).toEqual(["DELETE /admin/v1/secrets/sec_1123456789abcdef"]));
  });

  it("closes an open rotation form when the console turns read-only", async () => {
    const user = userEvent.setup();
    server();
    const view = renderWithWorkspace(<SecretsPage />);
    const row = (await screen.findByText("unused_key", { selector: ".lw-mono" })).closest("tr") as HTMLElement;
    await user.click(within(row).getByRole("button", { name: "Rotate" }));
    fireEvent.change(screen.getByLabelText("New value"), { target: { value: "half-typed" } });
    compatibility.mutationAllowed = false;
    view.rerenderPage(<SecretsPage />);
    expect(screen.queryByLabelText("New value")).not.toBeInTheDocument();
  });
});

describe("Import / Export", () => {
  it("imports a pasted document into the draft, never publishing it", async () => {
    const user = userEvent.setup();
    const state = server();
    renderWithWorkspace(<DraftChangesPage />);
    await user.click(await screen.findByRole("button", { name: "Import / Export" }));
    const drawer = screen.getByRole("complementary", { name: "Import / Export" });
    expect(within(drawer).getByText(/secretRef: secret\/openai_key/)).toBeInTheDocument();
    const imported = { ...live, spec: { upstreams: [{ authentication: { type: "none" }, baseUrl: "https://gateway.example.test/v1", id: "openai", type: "openai_compatible" }] } };
    fireEvent.change(within(drawer).getByLabelText("Or paste"), { target: { value: JSON.stringify(imported) } });
    await user.click(within(drawer).getByRole("button", { name: "Check Pasted Text" }));
    await user.click(within(drawer).getByRole("button", { name: "Import to Draft" }));
    expect(await within(drawer).findByText(/pasted text is now the draft/)).toBeInTheDocument();
    expect(state.draft?.document).toEqual(imported);
    expect(mutationsOf(adminRequestMock).some((call) => call.endsWith("/activate"))).toBe(false);
  });
});

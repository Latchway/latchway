import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: adminRequestMock
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({
    data: {
      mode: "configured",
      session: {
        capabilities: ["activate_configuration", "inspect_users", "manage_secrets"],
        organization_id: "org_0123456789abcdef"
      }
    }
  })
}));

import {
  ApplicationsPage,
  ConfigurationRevisionsPage,
  EnvironmentsPage,
  SecretsPage,
  UserOverridesPage
} from "./resource-management-pages";

const ids = {
  activeRevision: "rev_1123456789abcdef",
  application: "app_0123456789abcdef",
  environment: "env_0123456789abcdef",
  previousRevision: "rev_0123456789abcdef",
  secret: "sec_0123456789abcdef",
  user: "usr_0123456789abcdef"
};
const instant = "2026-08-29T00:00:00Z";
const secretMetadata = {
  algorithm: "xchacha20poly1305",
  created_at: instant,
  environment_id: ids.environment,
  id: ids.secret,
  master_key_id: "master-key",
  name: "primary_api_key",
  version: 1
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => { resolve = promiseResolve; });
  return { promise, resolve };
}

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("resource-management pages", () => {
  it("creates applications and environments through their tenant-scoped endpoints", async () => {
    const user = userEvent.setup();
    adminRequestMock.mockResolvedValueOnce({ data: {
      created_at: instant,
      display_name: "Mobile App",
      id: ids.application,
      organization_id: "org_0123456789abcdef",
      slug: "mobile-app",
      status: "active"
    } });
    const applicationView = render(<ApplicationsPage />);
    await user.type(screen.getByLabelText("Display name"), "Mobile App");
    await user.type(screen.getByLabelText("Slug"), "mobile-app");
    await user.click(screen.getByRole("button", { name: "Create application" }));

    await screen.findByText(ids.application);
    expect(adminRequestMock).toHaveBeenCalledWith("/admin/v1/applications", expect.anything(), {
      body: { display_name: "Mobile App", organization_id: "org_0123456789abcdef", slug: "mobile-app" },
      method: "POST"
    });

    applicationView.unmount();
    adminRequestMock.mockReset();
    adminRequestMock.mockResolvedValueOnce({ data: {
      application_id: ids.application,
      created_at: instant,
      display_name: "Production",
      id: ids.environment,
      kind: "production",
      slug: "production",
      status: "active"
    } });
    render(<EnvironmentsPage />);
    await user.type(screen.getByLabelText("Application ID"), ids.application);
    await user.type(screen.getByLabelText("Display name"), "Production");
    await user.type(screen.getByLabelText("Slug"), "production");
    await user.click(screen.getByRole("button", { name: "Create environment" }));

    await screen.findByText(ids.environment);
    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/applications/${ids.application}/environments`,
      expect.anything(),
      { body: { display_name: "Production", kind: "production", slug: "production" }, method: "POST" }
    );
  });

  it("requires explicit application disable confirmation and never restores revoked credentials on enable", async () => {
    const user = userEvent.setup();
    const active = {
      created_at: instant,
      display_name: "Mobile App",
      id: ids.application,
      organization_id: "org_0123456789abcdef",
      slug: "mobile-app",
      status: "active" as const
    };
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { body?: unknown; method?: string }) => {
      if (path.startsWith("/admin/v1/applications?") && !options?.method) {
        return Promise.resolve({ data: { items: [active], page: { has_more: false } } });
      }
      if (path === `/admin/v1/applications/${ids.application}/disable` && options?.method === "POST") {
        return Promise.resolve({ data: { ...active, disabled_at: "2026-08-29T00:10:00Z", status: "disabled" } });
      }
      if (path === `/admin/v1/applications/${ids.application}/enable` && options?.method === "POST") {
        return Promise.resolve({ data: active });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<ApplicationsPage />);
    await user.click(screen.getByRole("button", { name: "Load applications" }));
    await screen.findByText(ids.application);
    await user.click(screen.getByRole("button", { name: "Disable" }));
    expect(screen.getByRole("button", { name: "Disable application" })).toBeDisabled();
    await user.type(screen.getByLabelText("Reason"), "Compromised client release");
    await user.click(screen.getByLabelText("I understand active credentials in this application will be revoked."));
    await user.click(screen.getByRole("button", { name: "Disable application" }));

    await screen.findByRole("button", { name: "Enable" });
    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/applications/${ids.application}/disable`,
      expect.anything(),
      { body: { reason: "Compromised client release" }, method: "POST" }
    );
    await user.click(screen.getByRole("button", { name: "Enable" }));
    await waitFor(() => expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/applications/${ids.application}/enable`,
      expect.anything(),
      { method: "POST" }
    ));
  });

  it("scopes environment lifecycle actions to the exact environment", async () => {
    const user = userEvent.setup();
    const active = {
      application_id: ids.application,
      created_at: instant,
      display_name: "Production",
      id: ids.environment,
      kind: "production" as const,
      slug: "production",
      status: "active" as const
    };
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { body?: unknown; method?: string }) => {
      if (path === `/admin/v1/applications/${ids.application}/environments` && !options?.method) {
        return Promise.resolve({ data: { items: [active] } });
      }
      if (path === `/admin/v1/environments/${ids.environment}/disable` && options?.method === "POST") {
        return Promise.resolve({ data: { ...active, disabled_at: "2026-08-29T00:10:00Z", status: "disabled" } });
      }
      if (path === `/admin/v1/environments/${ids.environment}/enable` && options?.method === "POST") {
        return Promise.resolve({ data: active });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<EnvironmentsPage />);
    await user.type(screen.getByLabelText("Application ID"), ids.application);
    await user.click(screen.getByRole("button", { name: "Load environments" }));
    await screen.findByText(ids.environment);
    await user.click(screen.getByRole("button", { name: "Disable" }));
    await user.type(screen.getByLabelText("Reason"), "Isolate production traffic");
    await user.click(screen.getByLabelText("I understand active credentials in this environment will be revoked."));
    await user.click(screen.getByRole("button", { name: "Disable environment" }));

    await screen.findByRole("button", { name: "Enable" });
    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/environments/${ids.environment}/disable`,
      expect.anything(),
      { body: { reason: "Isolate production traffic" }, method: "POST" }
    );
    await user.click(screen.getByRole("button", { name: "Enable" }));
    await waitFor(() => expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/environments/${ids.environment}/enable`,
      expect.anything(),
      { method: "POST" }
    ));
  });

  it("clears write-only secret plaintext before the request completes and never persists it", async () => {
    const user = userEvent.setup();
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const pendingCreate = deferred<{ data: typeof secretMetadata }>();
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        return Promise.resolve({ data: { items: [secretMetadata], page: { has_more: false } } });
      }
      if (path === "/admin/v1/secrets" && options?.method === "POST") return pendingCreate.promise;
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<SecretsPage />);
    await user.type(screen.getByLabelText("Environment ID"), ids.environment);
    await user.click(screen.getByRole("button", { name: "Load secret metadata" }));
    await screen.findByText(ids.secret);
    await user.type(screen.getByLabelText("Secret name"), "secondary_api_key");
    const valueInput = screen.getByLabelText("Secret value");
    await user.type(valueInput, "transient-secret-value");
    await user.click(screen.getByRole("button", { name: "Create secret" }));

    await waitFor(() => expect(adminRequestMock).toHaveBeenCalledTimes(2));
    expect(valueInput).toHaveValue("");
    expect(screen.queryByDisplayValue("transient-secret-value")).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("transient-secret-value");
    expect(storageSpy).not.toHaveBeenCalled();

    await act(async () => pendingCreate.resolve({ data: { ...secretMetadata, id: "sec_1123456789abcdef", name: "secondary_api_key" } }));
    await screen.findByText("secondary_api_key");
    expect(storageSpy).not.toHaveBeenCalled();
  });

  it("requires cancellable typed confirmation and deletes only the exact current secret ID", async () => {
    const user = userEvent.setup();
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { method?: string }) => {
      if (path.startsWith("/admin/v1/secrets?") && !options?.method) {
        return Promise.resolve({ data: { items: [secretMetadata], page: { has_more: false } } });
      }
      if (path === `/admin/v1/secrets/${ids.secret}` && options?.method === "DELETE") {
        return Promise.resolve({ data: undefined });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<SecretsPage />);
    await user.type(screen.getByLabelText("Environment ID"), ids.environment);
    await user.click(screen.getByRole("button", { name: "Load secret metadata" }));
    await screen.findByText(ids.secret);

    await user.click(screen.getByRole("button", { name: "Delete unreferenced" }));
    expect(screen.getAllByText(ids.secret).some((element) => element.tagName === "CODE")).toBe(true);
    expect(screen.getByRole("button", { name: "Permanently delete secret" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Cancel deletion" }));
    expect(screen.queryByRole("heading", { name: "Permanently delete primary_api_key" })).not.toBeInTheDocument();
    expect(adminRequestMock.mock.calls.some(([path, , options]) => path === `/admin/v1/secrets/${ids.secret}` && options?.method === "DELETE")).toBe(false);

    await user.click(screen.getByRole("button", { name: "Delete unreferenced" }));
    const confirmation = screen.getByLabelText("Type primary_api_key to confirm");
    await user.type(confirmation, "primary_api_key");
    await user.click(screen.getByRole("button", { name: "Permanently delete secret" }));
    await waitFor(() => expect(screen.queryByText(ids.secret)).not.toBeInTheDocument());
    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/secrets/${ids.secret}`,
      expect.anything(),
      { method: "DELETE" }
    );
  });

  it("inspects, replaces, and clears one environment-scoped user override", async () => {
    const user = userEvent.setup();
    const baseUser = {
      created_at: instant,
      environment_id: ids.environment,
      id: ids.user,
      identity_providers: ["firebase"],
      normalized_claims: { plan: "standard" },
      status: "active"
    };
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { body?: unknown; method?: string }) => {
      if (path.includes(`/users/${ids.user}?`) && !options?.method) return Promise.resolve({ data: baseUser });
      if (path.includes(`/users/${ids.user}/limit-override?`) && options?.method === "PUT") return Promise.resolve({ data: {
        ...baseUser,
        limit_plan_override: { created_at: instant, id: "uov_0123456789abcdef", limit_plan: "subscriber", reason: "support-approved" }
      } });
      if (path.includes(`/users/${ids.user}/limit-override?`) && options?.method === "DELETE") return Promise.resolve({ data: undefined });
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<UserOverridesPage />);
    await user.type(screen.getByLabelText("Environment ID"), ids.environment);
    await user.type(screen.getByLabelText("User ID"), ids.user);
    await user.click(screen.getByRole("button", { name: "Inspect override" }));
    await screen.findByText("No override");
    await user.type(screen.getByLabelText("Limit plan"), "subscriber");
    await user.type(screen.getByLabelText("Reason"), "support-approved");
    await user.click(screen.getByRole("button", { name: "Set override" }));
    await screen.findByText("subscriber");

    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/users/${ids.user}/limit-override?environment_id=${ids.environment}`,
      expect.anything(),
      { body: { limit_plan: "subscriber", reason: "support-approved" }, method: "PUT" }
    );
    await user.click(screen.getByRole("button", { name: "Clear override" }));
    await waitFor(() => expect(screen.getByText("No override")).toBeInTheDocument());
    expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/users/${ids.user}/limit-override?environment_id=${ids.environment}`,
      expect.anything(),
      { method: "DELETE" }
    );
  });

  it("refreshes the active strong ETag immediately before exact-revision rollback", async () => {
    const user = userEvent.setup();
    const previous = {
      activated_at: instant,
      created_at: instant,
      created_by: "adm_0123456789abcdef",
      document: { apiVersion: "latchway.dev/v1alpha1", kind: "EnvironmentConfig", metadata: {}, spec: {} },
      environment_id: ids.environment,
      id: ids.previousRevision,
      state: "superseded",
      version: 1
    };
    const active = { ...previous, document: { ...previous.document, spec: { features: [{ id: "assistant" }] } }, id: ids.activeRevision, state: "active", version: 2 };
    let activeReads = 0;
    adminRequestMock.mockImplementation((path: string, _schema: unknown, options?: { etag?: string; method?: string }) => {
      if (path.includes("/config-revisions?")) return Promise.resolve({ data: { items: [previous], page: { has_more: false } } });
      if (path.endsWith("/config")) {
        activeReads += 1;
        return Promise.resolve({ data: active, etag: activeReads === 1 ? '"etag-at-load"' : '"etag-at-click"' });
      }
      if (path.endsWith("/rollback") && options?.method === "POST") return Promise.resolve({ data: { ...previous, state: "active" }, etag: '"etag-restored"' });
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<ConfigurationRevisionsPage />);
    await user.type(screen.getByLabelText("Environment ID"), ids.environment);
    await user.click(screen.getByRole("button", { name: "Load newest revision" }));
    await screen.findByText(/Active revision:/);
    await user.click(screen.getByRole("button", { name: "Review rollback" }));
    expect(screen.getByRole("heading", { name: "Replace active revision 2 with revision 1?" })).toBeInTheDocument();
    expect(screen.getByText("$.spec.features")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Operator reason"), "restore known-good revision");
    await user.click(screen.getByRole("button", { name: "Confirm rollback to revision 1" }));

    await waitFor(() => expect(adminRequestMock).toHaveBeenCalledWith(
      `/admin/v1/environments/${ids.environment}/rollback`,
      expect.anything(),
      { body: { reason: "restore known-good revision", revision_id: ids.previousRevision }, etag: '"etag-at-click"', method: "POST" }
    ));
    expect(activeReads).toBe(2);
  });
});

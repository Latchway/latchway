import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  adminRequest: vi.fn(),
  compatibility: { mutationAllowed: false }
}));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: mocks.adminRequest
}));

vi.mock("../api/session", () => ({
  useConsoleSession: () => ({
    data: {
      mode: "configured",
      session: {
        capabilities: ["activate_configuration", "inspect_users", "manage_owners", "manage_secrets", "run_self_tests"],
        organization_id: "org_0123456789abcdef"
      }
    }
  })
}));

vi.mock("../app/console-compatibility-context", () => ({
  useConsoleCompatibility: () => mocks.compatibility
}));

import { APITokensPage } from "./api-tokens-page";
import { AdministratorsPage } from "./administrators-page";
import { SelfTestsPage } from "./control-plane-pages";
import { ApplicationsPage, SecretsPage } from "./resource-management-pages";

afterEach(cleanup);

beforeEach(() => {
  mocks.adminRequest.mockReset();
  mocks.compatibility.mutationAllowed = false;
});

describe("global Console read-only safe mode", () => {
  it("preserves application inventory reads while removing application mutations", async () => {
    mocks.adminRequest.mockResolvedValueOnce({ data: { items: [], page: { has_more: false } } });
    const user = userEvent.setup();
    render(<ApplicationsPage />);

    expect(screen.queryByRole("button", { name: "Create application" })).not.toBeInTheDocument();
    const load = screen.getByRole("button", { name: "Load applications" });
    expect(load).toBeEnabled();
    await user.click(load);

    expect(await screen.findByText("No matching records.")).toBeInTheDocument();
    expect(mocks.adminRequest).toHaveBeenCalledOnce();
    expect(mocks.adminRequest.mock.calls[0]?.[2]).toBeUndefined();
  });

  it("preserves API-token inventory reads while disabling token creation", async () => {
    mocks.adminRequest.mockResolvedValueOnce({ data: { items: [] } });
    const user = userEvent.setup();
    render(<APITokensPage />);

    expect(screen.getByRole("button", { name: "Create API token" })).toBeDisabled();
    const load = screen.getByRole("button", { name: "Load API tokens" });
    expect(load).toBeEnabled();
    await user.click(load);

    expect(await screen.findByText("No API tokens")).toBeInTheDocument();
    expect(mocks.adminRequest).toHaveBeenCalledWith("/admin/v1/api-tokens", expect.anything());
    expect(mocks.adminRequest.mock.calls[0]?.[2]).toBeUndefined();
  });

  it("scrubs a revealed one-time API token on compatibility loss and does not reveal it after recovery", async () => {
    mocks.compatibility.mutationAllowed = true;
    mocks.adminRequest.mockResolvedValueOnce({ data: {
      metadata: { created_at: "2026-08-29T00:00:00Z", id: "tok_0123456789abcdef", name: "automation", revoked: false, scopes: ["run_self_tests"] },
      token: "one-time-token-material-0123456789"
    } });
    const user = userEvent.setup();
    const view = render(<APITokensPage />);
    await user.type(screen.getByLabelText("Token name"), "automation");
    await user.click(screen.getByLabelText("Run self-tests"));
    await user.click(screen.getByRole("button", { name: "Create API token" }));
    expect(await screen.findByLabelText("One-time API token")).toHaveValue("one-time-token-material-0123456789");

    mocks.compatibility.mutationAllowed = false;
    view.rerender(<APITokensPage />);
    await waitFor(() => expect(screen.queryByLabelText("One-time API token")).not.toBeInTheDocument());
    mocks.compatibility.mutationAllowed = true;
    view.rerender(<APITokensPage />);

    expect(screen.queryByLabelText("One-time API token")).not.toBeInTheDocument();
  });

  it("unmounts populated administrator password inputs when compatibility closes", async () => {
    mocks.compatibility.mutationAllowed = true;
    const user = userEvent.setup();
    const view = render(<AdministratorsPage />);
    await user.type(screen.getByLabelText(/^Initial password/), "temporary-secret-123");
    expect(screen.getByLabelText(/^Initial password/)).toHaveValue("temporary-secret-123");

    mocks.compatibility.mutationAllowed = false;
    view.rerender(<AdministratorsPage />);

    expect(screen.queryByLabelText(/^Initial password/)).not.toBeInTheDocument();
  });

  it("unmounts an open populated secret-rotation input when compatibility closes", async () => {
    mocks.compatibility.mutationAllowed = true;
    mocks.adminRequest.mockResolvedValueOnce({ data: { items: [{
      algorithm: "xchacha20poly1305", created_at: "2026-08-29T00:00:00Z",
      environment_id: "env_0123456789abcdef", id: "sec_0123456789abcdef",
      master_key_id: "master-key", name: "primary_api_key", version: 1
    }], page: { has_more: false } } });
    const user = userEvent.setup();
    const view = render(<SecretsPage />);
    await user.type(screen.getByLabelText("Environment ID"), "env_0123456789abcdef");
    await user.click(screen.getByRole("button", { name: "Load secret metadata" }));
    await user.click(await screen.findByRole("button", { name: "Rotate" }));
    await user.type(screen.getByLabelText("Replacement secret value"), "temporary-provider-secret");

    mocks.compatibility.mutationAllowed = false;
    view.rerender(<SecretsPage />);

    expect(screen.queryByLabelText("Replacement secret value")).not.toBeInTheDocument();
  });

  it("unmounts a populated scheduled-self-test token form when compatibility closes", async () => {
    mocks.compatibility.mutationAllowed = true;
    const user = userEvent.setup();
    const view = render(<SelfTestsPage />);
    await user.type(screen.getByLabelText(/^Durable Admin API token/), "tok_temporary_0123456789abcdef");

    mocks.compatibility.mutationAllowed = false;
    view.rerender(<SelfTestsPage />);

    expect(screen.queryByLabelText(/^Durable Admin API token/)).not.toBeInTheDocument();
    expect(screen.getByText("Scheduled self-test creation is unavailable until Console compatibility is restored.")).toBeInTheDocument();
  });
});

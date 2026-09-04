import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  adminRequest: vi.fn(),
  session: {
    data: {
      mode: "configured" as const,
      session: {
        administrator: {
          email: "owner@example.test",
          enabled: true,
          id: "adm_0123456789abcdef"
        },
        capabilities: ["secrets.manage", "configuration.activate"],
        expires_at: null,
        memberships: [
          { organization_id: "org_0123456789abcdef", role: "owner" as const }
        ],
        organization_id: "org_0123456789abcdef"
      }
    },
    generation: 1
  }
}));

vi.mock("../api/admin", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/admin")>()),
  adminRequest: mocks.adminRequest
}));
vi.mock("../api/session", () => ({
  useConsoleSession: () => mocks.session
}));

import {
  consoleCompatibilityBackgroundExpiry,
  consoleCompatibilityPollInterval,
  consoleCompatibilityQueryOptions,
  requiredConsoleServerCapabilities
} from "../api/console-compatibility";
import { ConsoleCompatibilityProvider } from "./console-compatibility";
import { useConsoleCompatibility } from "./console-compatibility-context";

const compatibleStatus = {
  contract_version: "1.0.0",
  database_schema_version: "27",
  mutation_ready: true,
  protocol_versions: [1, 2],
  ready: false,
  role: "all" as const,
  server_capabilities: [...requiredConsoleServerCapabilities],
  server_version: "1.0.0"
};

const incompatibleStatus = {
  ...compatibleStatus,
  server_capabilities: compatibleStatus.server_capabilities.filter(
    (capability) => capability !== "opaque_http"
  )
};

function configuredSession(
  generation: number,
  administratorID = "adm_0123456789abcdef",
  organizationID = "org_0123456789abcdef"
) {
  return {
    data: {
      mode: "configured" as const,
      session: {
        administrator: {
          email: "owner@example.test",
          enabled: true,
          id: administratorID
        },
        capabilities: ["secrets.manage", "configuration.activate"],
        expires_at: null,
        memberships: [{ organization_id: organizationID, role: "owner" as const }],
        organization_id: organizationID
      }
    },
    generation
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, reject, resolve };
}

function Probe() {
  const state = useConsoleCompatibility();
  return <div>
    <span>{state.mutationAllowed ? "mutations open" : "mutations closed"}</span>
    <span>{state.status?.ready ? "traffic ready" : "traffic not ready"}</span>
    <span>{state.error ? "compatibility error" : "no compatibility error"}</span>
    {state.mutationAllowed ? <input aria-label="Write-only provider secret" /> : null}
    <button onClick={() => void state.refresh()} type="button">Refresh compatibility</button>
  </div>;
}

function providerTree(queryClient: QueryClient) {
  return <QueryClientProvider client={queryClient}>
    <ConsoleCompatibilityProvider><Probe /></ConsoleCompatibilityProvider>
  </QueryClientProvider>;
}

function renderProvider() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(providerTree(queryClient));
  return {
    ...view,
    queryClient,
    rerenderProvider: () => view.rerender(providerTree(queryClient))
  };
}

function setVisibility(state: "hidden" | "visible") {
  Object.defineProperty(document, "visibilityState", { configurable: true, value: state });
  fireEvent(document, new Event("visibilitychange"));
}

beforeEach(() => {
  mocks.adminRequest.mockReset();
  mocks.session = configuredSession(1);
  Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
});

describe("ConsoleCompatibilityProvider", () => {
  it("binds foreground polling to the authenticated session identity and generation", () => {
    const identity = {
      administratorID: "adm_0123456789abcdef",
      generation: 7,
      organizationID: "org_0123456789abcdef"
    };
    const options = consoleCompatibilityQueryOptions(identity);

    expect(options.queryKey).toEqual(["console-compatibility", identity]);
    expect(options.refetchInterval).toBe(consoleCompatibilityPollInterval);
    expect(options.refetchInterval).toBe(15_000);
    expect(options.refetchIntervalInBackground).toBe(false);
    expect(options.refetchOnWindowFocus).toBe(false);
    expect(options.staleTime).toBe(consoleCompatibilityBackgroundExpiry);
  });

  it("fails closed while status is absent, then opens after the complete contract is verified", async () => {
    const request = deferred<{ data: typeof compatibleStatus }>();
    mocks.adminRequest.mockReturnValue(request.promise);

    renderProvider();
    expect(screen.getByText("mutations closed")).toBeInTheDocument();

    request.resolve({ data: compatibleStatus });
    expect(await screen.findByText("mutations open")).toBeInTheDocument();
    expect(screen.getByText("traffic not ready")).toBeInTheDocument();
  });

  it("fails closed when the first status request errors", async () => {
    mocks.adminRequest.mockRejectedValue(new Error("status unavailable"));
    renderProvider();

    expect(await screen.findByText("compatibility error")).toBeInTheDocument();
    expect(screen.getByText("mutations closed")).toBeInTheDocument();
    expect(mocks.adminRequest).toHaveBeenCalledWith(
      "/admin/v1/system",
      expect.anything(),
      expect.objectContaining({ signal: expect.any(AbortSignal) })
    );
  });

  it("fails closed for a missing capability even when traffic and the database are ready", async () => {
    mocks.adminRequest.mockResolvedValue({ data: { ...incompatibleStatus, ready: true } });
    renderProvider();

    expect(await screen.findByText("traffic ready")).toBeInTheDocument();
    expect(screen.getByText("mutations closed")).toBeInTheDocument();
  });

  it("retains a populated secret form while a foreground refresh is pending, then closes on error until a new compatible response", async () => {
    const failedRefresh = deferred<{ data: typeof compatibleStatus }>();
    const recovery = deferred<{ data: typeof compatibleStatus }>();
    mocks.adminRequest
      .mockResolvedValueOnce({ data: compatibleStatus })
      .mockReturnValueOnce(failedRefresh.promise)
      .mockReturnValueOnce(recovery.promise);
    renderProvider();
    expect(await screen.findByText("mutations open")).toBeInTheDocument();
    const secret = screen.getByRole("textbox", { name: "Write-only provider secret" });
    fireEvent.change(secret, { target: { value: "still-populated" } });

    fireEvent.click(screen.getByRole("button", { name: "Refresh compatibility" }));
    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledTimes(2));
    expect(screen.getByText("mutations open")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Write-only provider secret" })).toHaveValue("still-populated");

    failedRefresh.reject(new Error("status unavailable"));
    expect(await screen.findByText("compatibility error")).toBeInTheDocument();
    expect(screen.getByText("mutations closed")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Write-only provider secret" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Refresh compatibility" }));
    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledTimes(3));
    expect(screen.getByText("mutations closed")).toBeInTheDocument();
    recovery.resolve({ data: compatibleStatus });
    expect(await screen.findByText("mutations open")).toBeInTheDocument();
  });

  it("retains a populated secret form during a normal foreground poll, then expires it if the poll stalls", async () => {
    vi.useFakeTimers();
    const poll = deferred<{ data: typeof compatibleStatus }>();
    mocks.adminRequest
      .mockResolvedValueOnce({ data: compatibleStatus })
      .mockReturnValueOnce(poll.promise);
    const rendered = renderProvider();
    try {
      await vi.waitFor(() => expect(screen.getByText("mutations open")).toBeInTheDocument());
      fireEvent.change(screen.getByRole("textbox", { name: "Write-only provider secret" }), {
        target: { value: "poll-keeps-this" }
      });

      await act(async () => {
        await vi.advanceTimersByTimeAsync(consoleCompatibilityPollInterval);
      });

      expect(mocks.adminRequest).toHaveBeenCalledTimes(2);
      expect(screen.getByText("mutations open")).toBeInTheDocument();
      expect(screen.getByRole("textbox", { name: "Write-only provider secret" })).toHaveValue("poll-keeps-this");

      await act(async () => {
        await vi.advanceTimersByTimeAsync(
          consoleCompatibilityBackgroundExpiry - consoleCompatibilityPollInterval
        );
      });
      expect(screen.getByText("mutations closed")).toBeInTheDocument();
      expect(screen.queryByRole("textbox", { name: "Write-only provider secret" })).not.toBeInTheDocument();

      poll.resolve({ data: compatibleStatus });
      await vi.waitFor(() => expect(screen.getByText("mutations open")).toBeInTheDocument());
    } finally {
      rendered.unmount();
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });

  it("closes an open grant when a foreground refresh loses a required capability", async () => {
    mocks.adminRequest
      .mockResolvedValueOnce({ data: compatibleStatus })
      .mockResolvedValueOnce({ data: incompatibleStatus });
    renderProvider();
    expect(await screen.findByText("mutations open")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Refresh compatibility" }));

    expect(await screen.findByText("mutations closed")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Write-only provider secret" })).not.toBeInTheDocument();
  });

  it.each(["visibility", "focus"] as const)(
    "keeps a fresh grant across a short %s interruption without refetching",
    async (kind) => {
      let wall = 1_000_000;
      let monotonic = 10_000;
      const date = vi.spyOn(Date, "now").mockImplementation(() => wall);
      const performanceNow = vi.spyOn(performance, "now").mockImplementation(() => monotonic);
      mocks.adminRequest.mockResolvedValue({ data: compatibleStatus });
      try {
        renderProvider();
        expect(await screen.findByText("mutations open")).toBeInTheDocument();
        wall += 1_000;
        monotonic += 1_000;
        if (kind === "visibility") setVisibility("hidden");
        else fireEvent.blur(window);
        wall += 10_000;
        monotonic += 10_000;
        if (kind === "visibility") setVisibility("visible");
        else fireEvent.focus(window);

        expect(screen.getByText("mutations open")).toBeInTheDocument();
        expect(mocks.adminRequest).toHaveBeenCalledTimes(1);
      } finally {
        date.mockRestore();
        performanceNow.mockRestore();
      }
    }
  );

  it.each(["visibility", "focus"] as const)(
    "synchronously closes an expired %s grant and reopens only after a newly compatible response",
    async (kind) => {
      let wall = 2_000_000;
      let monotonic = 20_000;
      const date = vi.spyOn(Date, "now").mockImplementation(() => wall);
      const performanceNow = vi.spyOn(performance, "now").mockImplementation(() => monotonic);
      const expiredRefetch = deferred<{ data: typeof compatibleStatus }>();
      const recovery = deferred<{ data: typeof compatibleStatus }>();
      mocks.adminRequest
        .mockResolvedValueOnce({ data: compatibleStatus })
        .mockImplementationOnce(() => {
          expect(screen.getByText("mutations closed")).toBeInTheDocument();
          expect(screen.queryByRole("textbox", { name: "Write-only provider secret" })).not.toBeInTheDocument();
          return expiredRefetch.promise;
        })
        .mockReturnValueOnce(recovery.promise);
      try {
        renderProvider();
        expect(await screen.findByText("mutations open")).toBeInTheDocument();
        wall += 1_000;
        monotonic += 1_000;
        if (kind === "visibility") setVisibility("hidden");
        else fireEvent.blur(window);
        wall += consoleCompatibilityBackgroundExpiry;
        monotonic += consoleCompatibilityBackgroundExpiry;
        if (kind === "visibility") setVisibility("visible");
        else fireEvent.focus(window);

        expect(screen.getByText("mutations closed")).toBeInTheDocument();
        await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledTimes(2));
        expiredRefetch.reject(new Error("status unavailable"));
        expect(await screen.findByText("compatibility error")).toBeInTheDocument();
        expect(screen.getByText("mutations closed")).toBeInTheDocument();

        fireEvent.click(screen.getByRole("button", { name: "Refresh compatibility" }));
        await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledTimes(3));
        expect(screen.getByText("mutations closed")).toBeInTheDocument();
        recovery.resolve({ data: compatibleStatus });
        expect(await screen.findByText("mutations open")).toBeInTheDocument();
      } finally {
        date.mockRestore();
        performanceNow.mockRestore();
      }
    }
  );

  it("expires an old accepted observation after a short hidden interval, even if the wall clock rolls back", async () => {
    let wall = 3_000_000;
    let monotonic = 30_000;
    const date = vi.spyOn(Date, "now").mockImplementation(() => wall);
    const performanceNow = vi.spyOn(performance, "now").mockImplementation(() => monotonic);
    const revalidation = deferred<{ data: typeof compatibleStatus }>();
    mocks.adminRequest
      .mockResolvedValueOnce({ data: compatibleStatus })
      .mockImplementationOnce(() => {
        expect(screen.getByText("mutations closed")).toBeInTheDocument();
        return revalidation.promise;
      });
    try {
      renderProvider();
      expect(await screen.findByText("mutations open")).toBeInTheDocument();
      wall += 25_000;
      monotonic += 25_000;
      setVisibility("hidden");
      // Only ten seconds were hidden. The wall clock moves backwards, while
      // the monotonic age proves the accepted observation is now 35s old.
      wall -= 5_000;
      monotonic += 10_000;
      setVisibility("visible");

      expect(screen.getByText("mutations closed")).toBeInTheDocument();
      await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledTimes(2));
      expect(screen.getByText("mutations closed")).toBeInTheDocument();
      revalidation.resolve({ data: compatibleStatus });
      expect(await screen.findByText("mutations open")).toBeInTheDocument();
    } finally {
      date.mockRestore();
      performanceNow.mockRestore();
    }
  });

  it("never inherits a compatibility grant or cache across session generation and identity changes", async () => {
    const generationResponse = deferred<{ data: typeof compatibleStatus }>();
    const identityResponse = deferred<{ data: typeof compatibleStatus }>();
    mocks.adminRequest
      .mockResolvedValueOnce({ data: compatibleStatus })
      .mockReturnValueOnce(generationResponse.promise)
      .mockReturnValueOnce(identityResponse.promise);
    const rendered = renderProvider();
    expect(await screen.findByText("mutations open")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", { name: "Write-only provider secret" }), {
      target: { value: "must-not-cross-sessions" }
    });

    mocks.session = configuredSession(2);
    rendered.rerenderProvider();
    expect(screen.getByText("mutations closed")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Write-only provider secret" })).not.toBeInTheDocument();
    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledTimes(2));
    generationResponse.resolve({ data: compatibleStatus });
    expect(await screen.findByText("mutations open")).toBeInTheDocument();

    mocks.session = configuredSession(2, "adm_fedcba9876543210");
    rendered.rerenderProvider();
    expect(screen.getByText("mutations closed")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Write-only provider secret" })).not.toBeInTheDocument();
    await waitFor(() => expect(mocks.adminRequest).toHaveBeenCalledTimes(3));

    expect(rendered.queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toEqual(expect.arrayContaining([
      ["console-compatibility", {
        administratorID: "adm_0123456789abcdef",
        generation: 1,
        organizationID: "org_0123456789abcdef"
      }],
      ["console-compatibility", {
        administratorID: "adm_0123456789abcdef",
        generation: 2,
        organizationID: "org_0123456789abcdef"
      }],
      ["console-compatibility", {
        administratorID: "adm_fedcba9876543210",
        generation: 2,
        organizationID: "org_0123456789abcdef"
      }]
    ]));
  });
});

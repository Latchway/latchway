import { describe, expect, it, vi } from "vitest";

import { adminSessionEndpoint, fetchConsoleSession } from "./session";

describe("fetchConsoleSession", () => {
  it("recognizes an explicit first-owner setup response", async () => {
    const fetcher = vi.fn(async () =>
      Promise.resolve(
        new Response(JSON.stringify({ authenticated: false, setup_required: true }), {
          headers: { "Content-Type": "application/json" },
          status: 200
        })
      )
    ) as unknown as typeof fetch;

    await expect(fetchConsoleSession(undefined, fetcher)).resolves.toEqual({
      mode: "setup-required"
    });
    expect(fetcher).toHaveBeenCalledWith(
      adminSessionEndpoint,
      expect.objectContaining({ credentials: "same-origin", method: "GET" })
    );
  });

  it("uses a safe unknown mode while the Admin API is unavailable", async () => {
    const fetcher = vi.fn(async () => Promise.reject(new TypeError("offline"))) as unknown as typeof fetch;

    await expect(fetchConsoleSession(undefined, fetcher)).resolves.toEqual({
      mode: "unknown"
    });
  });
});

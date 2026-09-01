import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Link,
  Outlet,
  RouterProvider
} from "@tanstack/react-router";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { useDirtyEditProtection } from "./use-dirty-edit-protection";

function GuardHarness({ withLink = true }: { withLink?: boolean }) {
  const [value, setValue] = useState("");
  useDirtyEditProtection(Boolean(value));
  return <><label>Draft<input value={value} onChange={(event) => setValue(event.target.value)} /></label>{withLink ? <Link to="/system-health">Next page</Link> : null}</>;
}

function routerForTest() {
  const root = createRootRoute({ component: Outlet });
  const editor = createRoute({ component: GuardHarness, getParentRoute: () => root, path: "/" });
  const next = createRoute({ component: () => <h1>Next</h1>, getParentRoute: () => root, path: "/system-health" });
  return createRouter({
    history: createMemoryHistory({ initialEntries: ["/"] }),
    routeTree: root.addChildren([editor, next])
  });
}

describe("dirty edit protection", () => {
  it("prevents a document unload while an editor has unsaved changes", async () => {
    const user = userEvent.setup();
    render(<GuardHarness withLink={false} />);
    await user.type(screen.getByLabelText("Draft"), "changed");

    const event = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(event)).toBe(false);
    expect(event.defaultPrevented).toBe(true);
  });

  it("blocks internal TanStack navigation until the operator confirms discard", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    const router = routerForTest();
    const user = userEvent.setup();
    render(<RouterProvider router={router} />);
    await user.type(await screen.findByLabelText("Draft"), "changed");

    await user.click(screen.getByRole("link", { name: "Next page" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/"));
    expect(screen.getByLabelText("Draft")).toHaveValue("changed");

    await user.click(screen.getByRole("link", { name: "Next page" }));
    expect(await screen.findByRole("heading", { name: "Next" })).toBeInTheDocument();
    expect(confirm).toHaveBeenCalledTimes(2);
  });
});

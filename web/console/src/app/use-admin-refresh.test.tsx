import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { dispatchAdminRefresh } from "../api/admin-events";
import { useAdminRefreshTopic } from "./use-admin-refresh";

function Fixture({ enabled = true, refresh }: { enabled?: boolean; refresh: () => void }) {
  useAdminRefreshTopic("requests", refresh, enabled);
  return null;
}

describe("useAdminRefreshTopic", () => {
  it("subscribes to one topic, uses the latest callback, and cleans up", () => {
    const first = vi.fn();
    const second = vi.fn();
    const view = render(<Fixture refresh={first} />);
    dispatchAdminRefresh(["usage"]);
    dispatchAdminRefresh(["requests"]);
    expect(first).toHaveBeenCalledTimes(1);

    view.rerender(<Fixture refresh={second} />);
    dispatchAdminRefresh(["requests"]);
    expect(first).toHaveBeenCalledTimes(1);
    expect(second).toHaveBeenCalledTimes(1);

    view.unmount();
    dispatchAdminRefresh(["requests"]);
    expect(second).toHaveBeenCalledTimes(1);
  });

  it("does not subscribe when disabled", () => {
    const refresh = vi.fn();
    render(<Fixture enabled={false} refresh={refresh} />);
    dispatchAdminRefresh(["requests"]);
    expect(refresh).not.toHaveBeenCalled();
  });
});

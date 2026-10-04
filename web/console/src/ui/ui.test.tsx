import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import {
  AttentionList,
  Button,
  checkCustomRange,
  ConfirmDialog,
  DataTable,
  DAY_MS,
  EnvironmentBadge,
  Icon,
  ImpactDialog,
  Menu,
  niceScale,
  ProportionBar,
  type RangeValue,
  RangePicker,
  rangeText,
  Segmented,
  sortAttention,
  StatusBadge,
  StatusRail,
  Tabs,
  VolumeChart
} from "./index";

const NOW = Date.UTC(2026, 9, 2, 15, 30);

describe("Icon", () => {
  it("is hidden from assistive technology unless labelled", () => {
    const { container } = render(<><Icon name="search" /><Icon label="Production" name="alert" /></>);
    expect(container.querySelector(".lw-icon")).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByRole("img", { name: "Production" })).toBeInTheDocument();
  });

  it("renders filled and stroke icons as inline SVG", () => {
    const { container } = render(<><Icon name="overview" /><Icon name="requests" /></>);
    const svgs = container.querySelectorAll("svg");
    expect(svgs).toHaveLength(2);
    expect(svgs[1]).toHaveAttribute("stroke", "currentColor");
  });
});

describe("Button", () => {
  it("disables and marks itself busy while loading", () => {
    render(<Button loading variant="primary">Publish</Button>);
    const button = screen.getByRole("button", { name: "Publish" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    expect(button).toHaveClass("lw-btn", "lw-btn--primary", "lw-btn--loading");
  });

  it("uses the icon-only class when there is no text", () => {
    render(<Button aria-label="Close" icon="x" variant="ghost" />);
    expect(screen.getByRole("button", { name: "Close" })).toHaveClass("lw-btn--icon", "lw-btn--ghost");
  });
});

describe("badges", () => {
  it("names the status in words", () => {
    render(<><StatusBadge status="draft" /><StatusBadge status="failed">Rejected</StatusBadge></>);
    expect(screen.getByText("Draft").closest(".lw-badge")).toHaveClass("lw-badge--warning");
    expect(screen.getByText("Rejected").closest(".lw-badge")).toHaveClass("lw-badge--danger");
  });

  it("fills production so it is never mistaken for a test environment", () => {
    render(<><EnvironmentBadge kind="production">prod</EnvironmentBadge><EnvironmentBadge kind="custom">qa</EnvironmentBadge></>);
    expect(screen.getByText("prod").closest(".lw-badge")).toHaveClass("lw-badge--filled", "lw-badge--warning");
    expect(screen.getByText("qa").closest(".lw-badge")).toHaveClass("lw-badge--soft", "lw-badge--violet");
  });
});

describe("Tabs and Segmented", () => {
  it("report selection through ARIA state", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<>
      <Tabs items={[{ id: "a", label: "Alpha" }, { id: "b", label: "Beta" }]} label="Views" onChange={onChange} value="a" />
      <Segmented items={[{ id: "24h", label: "24h" }, { id: "7d", label: "7d" }]} label="Range" onChange={onChange} value="7d" />
    </>);
    expect(screen.getByRole("tab", { name: "Alpha" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("button", { name: "7d" })).toHaveAttribute("aria-pressed", "true");
    await user.click(screen.getByRole("tab", { name: "Beta" }));
    expect(onChange).toHaveBeenCalledWith("b");
  });
});

describe("attention", () => {
  const items = [
    { id: "1", severity: "info", title: "Info one" },
    { id: "2", severity: "critical", title: "Critical one" },
    { id: "3", severity: "warning", title: "Warning one" },
    { id: "4", severity: "critical", title: "Critical two" }
  ] as const;

  it("sorts by severity and keeps order within a severity", () => {
    expect(sortAttention(items).map((item) => item.id)).toEqual(["2", "4", "3", "1"]);
  });

  it("caps the list and expands on request", async () => {
    const user = userEvent.setup();
    render(<AttentionList items={items} limit={2} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("Critical one")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show all 4" }));
    expect(screen.getAllByRole("listitem")).toHaveLength(4);
  });

  it("says when nothing needs attention", () => {
    render(<AttentionList items={[]} />);
    expect(screen.getByText("Nothing needs attention")).toBeInTheDocument();
  });
});

describe("StatusRail", () => {
  it("shows the first state and brings a waiting one forward", async () => {
    const user = userEvent.setup();
    render(<StatusRail items={[
      { id: "safe", title: "Read-only safe mode.", tone: "danger" },
      { chip: "Draft", id: "draft", title: "Unpublished changes.", tone: "draft" }
    ]} />);
    const rail = screen.getByRole("region", { name: "Status" });
    expect(within(rail).getByRole("status")).toHaveTextContent("Read-only safe mode.");
    await user.click(within(rail).getByRole("button", { name: "Draft" }));
    expect(within(rail).getByRole("status")).toHaveTextContent("Unpublished changes.");
    expect(rail).toHaveClass("lw-status--draft");
  });

  it("renders nothing without states", () => {
    const { container } = render(<StatusRail items={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ranges", () => {
  it("formats presets and custom ranges", () => {
    expect(rangeText({ id: "7d" })).toBe("7d");
    expect(rangeText({ end: Date.UTC(2026, 2, 10), id: "custom", start: Date.UTC(2026, 2, 3) })).toBe("Mar 3 – Mar 9");
    expect(rangeText({ end: Date.UTC(2026, 2, 4), id: "custom", start: Date.UTC(2026, 2, 3) })).toBe("Mar 3");
  });

  it("validates whole UTC days", () => {
    expect(checkCustomRange("2026-09-01", "2026-09-30", 90, NOW)).toMatchObject({ days: 30, errors: {} });
    expect(checkCustomRange("2026-09-10", "2026-09-01", 90, NOW).errors.to).toBe("End on or after the start date.");
    expect(checkCustomRange("2026-09-01", "2026-10-03", 90, NOW).errors.to).toBe("Choose today or earlier.");
    expect(checkCustomRange("2026-01-01", "2026-10-01", 90, NOW).errors.to).toMatch(/^Choose at most 90 days/);
    expect(checkCustomRange("", "2026-10-01", 90, NOW).errors.from).toBe("Choose a start date.");
  });

  it("applies a custom range from the picker", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn<(value: RangeValue) => void>();
    render(<RangePicker maxDays={90} now={NOW} onChange={onChange} presets={["24h", "7d"]} value={{ id: "24h" }} />);
    await user.click(screen.getByRole("button", { name: "7d" }));
    expect(onChange).toHaveBeenLastCalledWith({ id: "7d" });
    await user.click(screen.getByRole("button", { name: "Custom…" }));
    const dialog = screen.getByRole("dialog", { name: "Custom range" });
    await user.click(within(dialog).getByRole("button", { name: "Apply" }));
    const today = Math.floor(NOW / DAY_MS) * DAY_MS;
    expect(onChange).toHaveBeenLastCalledWith({ end: today + DAY_MS, id: "custom", start: today - 13 * DAY_MS });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("charts", () => {
  it("picks a 1/2/5 scale that covers the maximum", () => {
    expect(niceScale(37)).toMatchObject({ step: 10, top: 40, ticks: [0, 10, 20, 30, 40] });
    expect(niceScale(1200).top).toBeGreaterThanOrEqual(1200);
    expect(niceScale(0).top).toBeGreaterThan(0);
  });

  it("totals each series in the legend and opens a bucket from the keyboard", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<VolumeChart bars={["succeeded", "failed"]} label="Requests" labels={{ failed: "Failed", succeeded: "Succeeded" }} onSelect={onSelect} points={[
      { label: "Mon", values: { failed: 2, succeeded: 10 } },
      { label: "Tue", values: { failed: 1, succeeded: 20 } }
    ]} />);
    const legend = screen.getByRole("list");
    expect(legend).toHaveTextContent("Succeeded30");
    expect(legend).toHaveTextContent("Failed3");
    screen.getByRole("button", { name: "Tue: Succeeded 20, Failed 1" }).focus();
    await user.keyboard("{Enter}");
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ label: "Tue" }), 1);
  });

  it("describes proportions in its accessible name", () => {
    render(<ProportionBar segments={[{ color: "red", label: "Denied", value: 1 }, { color: "blue", label: "Allowed", value: 3 }]} />);
    expect(screen.getByRole("img", { name: "Denied 1, Allowed 3" })).toBeInTheDocument();
  });
});

describe("DataTable", () => {
  const rows = [{ id: "a", name: "Alpha" }, { id: "b", name: "Beta" }];

  it("selects rows by click or keyboard and sorts by column", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const onSort = vi.fn();
    render(<DataTable caption="Things" columns={[{ header: "Name", key: "name", render: (row) => row.name, sortable: true }]} onSelect={onSelect} onSort={onSort} rowKey={(row) => row.id} rows={rows} selectedKey="b" sort={{ dir: "asc", key: "name" }} />);
    expect(screen.getByRole("columnheader", { name: "Name" })).toHaveAttribute("aria-sort", "ascending");
    await user.click(screen.getByRole("button", { name: "Name" }));
    expect(onSort).toHaveBeenCalledWith("name");
    await user.click(screen.getByText("Alpha"));
    expect(onSelect).toHaveBeenLastCalledWith(rows[0]);
    screen.getByText("Beta").closest("tr")?.focus();
    await user.keyboard(" ");
    expect(onSelect).toHaveBeenLastCalledWith(rows[1]);
    expect(screen.getByText("Beta").closest("tr")).toHaveAttribute("aria-selected", "true");
  });
});

describe("dialogs", () => {
  function Harness({ onConfirm = vi.fn() }: { onConfirm?: () => void }) {
    const [open, setOpen] = useState(false);
    return <>
      <button onClick={() => setOpen(true)} type="button">Delete token</button>
      {open ? <ConfirmDialog confirmLabel="Delete" destructive onCancel={() => setOpen(false)} onConfirm={onConfirm} title="Delete this token?" /> : null}
    </>;
  }

  it("traps focus, cancels on Escape and returns focus to the opener", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const opener = screen.getByRole("button", { name: "Delete token" });
    await user.click(opener);
    const dialog = screen.getByRole("alertdialog", { name: "Delete this token?" });
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.tab();
    expect(within(dialog).getByRole("button", { name: "Delete" })).toHaveFocus();
    await user.tab();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("enables an impact confirmation only after ID, reason and acknowledgement", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    render(<ImpactDialog confirmLabel="Revoke" impacts={[{ count: 3, label: "installations" }]} onCancel={vi.fn()} onConfirm={onConfirm} targetId="usr_123" title="Revoke user" />);
    const confirm = screen.getByRole("button", { name: "Revoke" });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText("Reason"), "Contain incident");
    await user.type(screen.getByLabelText(/to confirm/), "usr_123");
    expect(confirm).toBeDisabled();
    await user.click(screen.getByRole("checkbox"));
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith({ confirm: "usr_123", reason: "Contain incident" });
  });
});

describe("Menu", () => {
  it("moves focus with arrow keys and closes after choosing", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSignOut = vi.fn();
    render(<Menu entries={[{ label: "Theme", onSelect: vi.fn() }, { kind: "separator" }, { destructive: true, label: "Sign out", onSelect: onSignOut }]} label="Account" onClose={onClose} />);
    expect(screen.getByRole("menuitem", { name: "Theme" })).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(screen.getByRole("menuitem", { name: "Sign out" })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(onSignOut).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalled();
  });
});

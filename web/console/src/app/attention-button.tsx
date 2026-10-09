import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useCallback, useRef, useState } from "react";

import { adminRequest, queryPath, UsageSummarySchema } from "../api/admin";
import { useDismiss } from "../components/use-dismiss";
import { iso } from "../pages/analytics/usage-model";
import { ATTENTION_GROUPS, attentionItems } from "../pages/overview/attention-model";
import { useAttentionSources } from "../pages/overview/use-attention";
import { AttentionList, cx, Icon } from "../ui";
import { scopeSearch } from "./navigation";
import { useWorkspace } from "./workspace-context-value";

/** Wall-clock reads happen when a query runs or the popover opens, never while rendering. */
const clock = (): number => Date.now();

/**
 * The header's count of things to look at, from the same server records as Overview's "Needs attention", with the
 * last 24 hours of usage. Opening it lists them; nothing is dismissable.
 */
export function AttentionButton() {
  const workspace = useWorkspace();
  const navigate = useNavigate();
  const environmentID = workspace.environment?.id ?? "";
  const [open, setOpen] = useState(false);
  const [now, setNow] = useState(clock);
  const anchor = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => {
    setOpen(false);
    button.current?.focus();
  }, []);
  useDismiss(open, anchor, close);
  const sources = useAttentionSources(environmentID);
  const summary = useQuery({
    enabled: Boolean(environmentID),
    queryFn: async () => {
      const end = clock();
      return (await adminRequest(queryPath("/admin/v1/usage/summary", { breakdown_limit: "50", end: iso(end), environment_id: environmentID, start: iso(end - 86_400_000) }), UsageSummarySchema)).data;
    },
    queryKey: ["usage-summary", environmentID, "attention-24h"],
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: 5 * 60_000
  });
  const items = attentionItems({ ...sources, application: workspace.application, environment: workspace.environment, now, summary: summary.data });
  const pressing = items.filter((item) => item.severity !== "info");
  const critical = pressing.some((item) => item.severity === "critical");
  const label = pressing.length ? `${pressing.length} ${pressing.length === 1 ? "thing needs" : "things need"} attention` : "Nothing needs attention";
  return (
    <span className="lw-console__account" ref={anchor}>
      <button
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label={label}
        className="lw-btn lw-btn--ghost lw-btn--icon lw-attn-btn"
        onClick={() => { if (!open) setNow(clock()); setOpen(!open); }}
        ref={button}
        title={label}
        type="button"
      >
        <Icon name="bell" />
        {pressing.length ? <span aria-hidden="true" className={cx("lw-attn-btn__count", critical && "is-critical")}>{pressing.length > 9 ? "9+" : pressing.length}</span> : null}
      </button>
      {open ? (
        <div aria-label="Needs attention" className="lw-console__popover lw-attn-pop" role="dialog">
          <div className="lw-attn-pop__head">
            <strong>Needs attention</strong>
            <span className="lw-faint">{workspace.environment ? `${workspace.environment.display_name} · usage from the last 24 hours` : "No environment selected"}</span>
          </div>
          <AttentionList
            compact
            emptyText="Configuration, usage, API tokens, gateway readiness and the server self-check look fine."
            groups={ATTENTION_GROUPS}
            items={items.map((item) => ({ ...item, onAction: () => { setOpen(false); void navigate({ search: (previous) => ({ ...scopeSearch(previous), ...item.search }), to: item.to }); } }))}
            limit={6}
          />
          <div className="lw-attn-pop__foot">
            <Link className="lw-link" onClick={() => setOpen(false)} search={scopeSearch} to="/">Open Overview</Link>
          </div>
        </div>
      ) : null}
    </span>
  );
}

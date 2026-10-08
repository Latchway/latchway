import { useInfiniteQuery, useQueries, useQuery } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";

import { adminRequest, queryPath, RequestFacetsSchema, type UserOverridePage } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { listOverrides, usageDistribution } from "../../api/policy-insights";
import { Badge, Button, type Column, DataTable, EmptyState, Notice, Segmented } from "../../ui";
import type { JSONRecord } from "../configuration-slice";
import { ProblemNotice } from "../control-plane-pages";
import { impactRange, projectableLimit } from "./policy-insights-model";

/** Wall-clock reads happen when a query runs, never while rendering. */
const clock = (): number => Date.now();

function count(value: number, noun: string): string {
  return `${value.toLocaleString()} ${noun}${value === 1 ? "" : "s"}`;
}

/**
 * How many users each calendar limit would have stopped over a recent stretch, from the server's per-user usage in
 * the same calendar windows enforcement uses. Nothing is estimated in the browser.
 */
export function LimitImpact({ environmentID, limits, plan }: { environmentID: string; limits: readonly JSONRecord[]; plan?: string }) {
  const projected = limits.map((limit) => projectableLimit(limit));
  const results = useQueries({
    queries: projected.map((limit, index) => ({
      enabled: Boolean(environmentID && limit),
      queryFn: async () => {
        if (!limit) throw new Error("This limit can't be projected.");
        const range = impactRange(limit.window, clock());
        return { distribution: await usageDistribution({ ...range, environmentID, limitPlan: plan, maximum: limit.maximum, metric: limit.metric, scope: limit.scope, timezone: limit.timezone, window: limit.window }), days: range.days };
      },
      queryKey: ["usage-distribution", environmentID, plan ?? "", index, JSON.stringify(limit)],
      retry: false,
      staleTime: 5 * 60_000
    }))
  });
  if (!limits.length) return null;
  return (
    <div className="lw-stack lw-stack--tight">
      <strong className="lw-note">Who these limits would have stopped</strong>
      <ul className="lw-impact">
        {projected.map((limit, index) => {
          const result = results[index];
          const label = `Limit ${index + 1}`;
          if (!limit) return <li className="lw-faint lw-note" key={index}>{label}: not projected. Only calendar limits on users, features or installations with a usage metric can be.</li>;
          if (result?.error) return <li className="lw-note" key={index}>{label}: <span className="lw-text-warning">{problemFromError(result.error).detail}</span></li>;
          if (!result?.data) return <li className="lw-faint lw-note" key={index} role="status">{label}: counting…</li>;
          const { distribution, days } = result.data;
          const over = distribution.over_users ?? 0;
          return (
            <li className="lw-note" key={index}>
              <strong>{label}:</strong> {distribution.users ? <>{count(over, "user")} of {distribution.users.toLocaleString()} would have reached it at least once in the last {days} days{plan ? ` on ${plan}` : ""}.</> : <>no usage in the last {days} days{plan ? ` on ${plan}` : ""}.</>}
              {distribution.subjects ? <span className="lw-faint"> Busiest window per {limit.scope.join(" and ")}: median {distribution.peaks.p50.toLocaleString()} · 90th percentile {distribution.peaks.p90.toLocaleString()} · max {distribution.peaks.max.toLocaleString()}.</span> : null}
            </li>
          );
        })}
      </ul>
      {!plan ? <p className="lw-secondary lw-note">This plan isn&apos;t published, so the counts cover every user&apos;s traffic as if they were on it.</p> : null}
    </div>
  );
}

/** Users whose active override names this plan; removing the plan leaves their overrides pointing nowhere. */
export function PlanOverrides({ environmentID, onOpenUser, plan }: { environmentID: string; onOpenUser?: (userID: string) => void; plan: string }) {
  const overrides = useQuery({
    enabled: Boolean(environmentID),
    queryFn: () => listOverrides(environmentID, { limitPlan: plan, pageSize: 20, status: "active" }),
    queryKey: ["user-overrides", environmentID, "active", plan],
    retry: false
  });
  if (overrides.error) return <ProblemNotice problem={problemFromError(overrides.error)} />;
  if (!overrides.data) return <p className="lw-page-status" role="status">Checking overrides…</p>;
  const items = overrides.data.items;
  if (!items.length) return <Notice tone="info">No user has an active override to {plan}.</Notice>;
  return (
    <Notice title={`${items.length}${overrides.data.page.has_more ? "+" : ""} active override${items.length === 1 && !overrides.data.page.has_more ? "" : "s"} use ${plan}`} tone="warning">
      <p className="lw-note">Their overrides stop working once {plan} is gone. Clear or change them under Overrides before publishing.</p>
      <ul className="lw-issue-list">
        {items.slice(0, 5).map((item) => (
          <li key={item.id}>{onOpenUser ? <button className="lw-link lw-mono lw-mono--sm" onClick={() => onOpenUser(item.user_id)} type="button">{item.user_id}</button> : <span className="lw-mono lw-mono--sm">{item.user_id}</span>}{item.expires_at ? <span className="lw-faint"> · until {new Date(item.expires_at).toLocaleDateString()}</span> : null}</li>
        ))}
      </ul>
      {items.length > 5 || overrides.data.page.has_more ? <p className="lw-faint lw-note">and more.</p> : null}
    </Notice>
  );
}

/** Which plans this feature's requests got over the last week: the server's record of each request's selected plan. */
export function PlanShare({ environmentID, feature }: { environmentID: string; feature: string }) {
  const share = useQuery({
    enabled: Boolean(environmentID && feature),
    queryFn: async () => {
      const end = clock();
      const response = (await adminRequest(queryPath("/admin/v1/requests/facets", {
        end: new Date(end).toISOString(), environment_id: environmentID, feature, limit: "20", start: new Date(end - 7 * 86_400_000).toISOString()
      }), RequestFacetsSchema)).data;
      if (response.environment_id !== environmentID || response.feature !== feature) throw new Error("The plan counts belonged to another feature.");
      return response;
    },
    queryKey: ["plan-share", environmentID, feature],
    retry: false,
    staleTime: 5 * 60_000
  });
  if (share.error) return <ProblemNotice problem={problemFromError(share.error)} />;
  if (!share.data) return <p className="lw-page-status" role="status">Counting recent requests…</p>;
  const values = share.data.facets.limit_plan.values;
  const total = values.reduce((sum, item) => sum + item.count, 0);
  if (!total) return <p className="lw-secondary lw-note">No requests for {feature} in the last 7 days, so there&apos;s no split to show yet.</p>;
  return (
    <div className="lw-stack lw-stack--tight">
      <strong className="lw-note">Last 7 days</strong>
      <ul aria-label="Plan share" className="lw-share">
        {values.map((item) => {
          const percent = Math.round((item.count / total) * 1000) / 10;
          return (
            <li className="lw-share__row" key={item.value}>
              <span className="lw-mono lw-mono--sm lw-share__plan">{item.value}</span>
              <span aria-hidden="true" className="lw-share__bar"><span style={{ width: `${Math.max(percent, 1)}%` }} /></span>
              <span className="lw-num lw-share__value">{percent}% · {item.count.toLocaleString()}</span>
            </li>
          );
        })}
      </ul>
      <p className="lw-secondary lw-note">Counted from each request&apos;s recorded plan, including overrides. A change you save here applies from the next publish.</p>
    </div>
  );
}

type OverrideItem = UserOverridePage["items"][number];

const STATUS_BADGE: Readonly<Record<OverrideItem["status"], ReactNode>> = {
  active: <Badge color="success" variant="soft">Active</Badge>,
  expired: <Badge variant="soft">Expired</Badge>,
  revoked: <Badge variant="soft">Cleared</Badge>
};

/** Every override in the environment, active or ended, newest first. */
export function OverrideList({ environmentID, onOpenUser, selectedUser }: { environmentID: string; onOpenUser: (userID: string) => void; selectedUser?: string }) {
  const [status, setStatus] = useState<"active" | "ended">("active");
  const list = useInfiniteQuery({
    enabled: Boolean(environmentID),
    getNextPageParam: (page: UserOverridePage) => (page.page.has_more ? page.page.next_cursor : undefined),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => listOverrides(environmentID, { cursor: pageParam, pageSize: 50, status }),
    queryKey: ["user-overrides", environmentID, status, "list"],
    retry: false
  });
  const rows = list.data?.pages.flatMap((page) => page.items) ?? [];
  const columns: Array<Column<OverrideItem>> = [
    { header: "User", key: "user", render: (item) => <span className="lw-mono lw-mono--sm">{item.user_id}</span> },
    { header: "Plan", key: "plan", render: (item) => <strong>{item.limit_plan}</strong> },
    { header: "Status", key: "status", render: (item) => STATUS_BADGE[item.status] },
    { header: "Reason", key: "reason", render: (item) => <span className="lw-note lw-clamp" title={item.reason}>{item.reason}</span> },
    {
      header: status === "active" ? "Ends" : "Ended",
      key: "ends",
      render: (item) => {
        const ended = item.revoked_at ?? item.expires_at;
        return ended ? <span className="lw-secondary">{new Date(ended).toLocaleString()}</span> : <span className="lw-faint">No expiry</span>;
      }
    }
  ];
  return (
    <div className="lw-stack lw-stack--tight">
      <div className="lw-row lw-row--spread">
        <strong className="lw-note">Overrides in this environment</strong>
        <Segmented items={[{ id: "active", label: "Active" }, { id: "ended", label: "Ended" }]} label="Override status" onChange={setStatus} value={status} />
      </div>
      {list.error ? <ProblemNotice problem={problemFromError(list.error)} /> : null}
      {list.isPending ? <p className="lw-page-status" role="status">Loading overrides…</p> : rows.length ? (
        <DataTable caption="Overrides" columns={columns} onSelect={(item) => onOpenUser(item.user_id)} rowKey={(item) => item.id} rows={rows} selectedKey={rows.find((item) => item.user_id === selectedUser)?.id} />
      ) : <EmptyState icon="policies" orientation="horizontal" title={status === "active" ? "No active overrides" : "No ended overrides"}>{status === "active" ? "Every user's claims pick their plan." : "Cleared and expired overrides appear here."}</EmptyState>}
      {list.hasNextPage ? <div><Button loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()} size="sm">Load More</Button></div> : null}
    </div>
  );
}

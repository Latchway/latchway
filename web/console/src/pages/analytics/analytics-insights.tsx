import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { adminRequest, DoctorReportSchema, queryPath, RequestFacetsSchema, UsageSummarySchema } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { connectionHealth, OPERATIONS_HISTORY } from "../../api/operations-history";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { buttonClass, Card, type Column, DataTable, MetricTile, Notice, StatStrip } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";
import { successRate } from "../operate/operations-history-model";
import { formatMs } from "../requests/request-format";
import { formatCount, formatMoney, iso, monthWindows, percentChange, projectMonthEnd, recorded, type UsageWindow } from "./usage-model";

/** The half-open range a breakdown covers, in epoch milliseconds. */
type Range = Pick<UsageWindow, "end" | "start">;

/** Request facets and connection health cover at most 90 days. */
const BREAKDOWN_MAX_MS = 90 * 86_400_000;
const REQUEST_SEARCH = "admin_request_search";

/** Wall-clock reads happen when a component mounts or a query runs, never while rendering. */
const clock = (): number => Date.now();

const MONTH = new Intl.DateTimeFormat("en-US", { month: "long", timeZone: "UTC" });

function useServerCapability(name: string): boolean {
  return useConsoleCompatibility().status?.server_capabilities.includes(name) ?? false;
}

/**
 * Says when usage totals are behind: requests waiting for usage settlement, no worker to settle them, or a stale
 * reconciliation job. Read from the server's self-check, which covers the whole server.
 */
export function SettlementNotice({ workspaceSearch }: { workspaceSearch: Record<string, string | undefined> }) {
  const doctor = useQuery({ queryFn: async () => (await adminRequest("/admin/v1/system/doctor", DoctorReportSchema)).data, queryKey: ["system", "doctor"], retry: false, staleTime: 60_000 });
  const report = doctor.data;
  if (!report) return null;
  const backlog = report.facts.jobs.usage_settlement_backlog;
  const noWorker = report.facts.replicas.fresh_workers === 0;
  const reconciliation = report.checks.find((check) => check.id === "usage_reconciliation_freshness");
  const stale = reconciliation?.state === "warning" || reconciliation?.state === "failed";
  if (!backlog && !noWorker && !stale) return null;
  const reasons: string[] = [];
  if (backlog) reasons.push(`${backlog.toLocaleString()} request${backlog === 1 ? " is" : "s are"} waiting for usage settlement on this server.`);
  if (noWorker) reasons.push("No background worker is running, so requests that ended without a final usage report aren't settled.");
  else if (stale) reasons.push("Usage reconciliation hasn't run in the last few minutes.");
  return (
    <div className="lw-page-notice">
      <Notice action={<Link className={buttonClass({ size: "sm" })} search={workspaceSearch} to="/system-health">Open System Health</Link>} title="Recent totals may be low" tone="warning">
        {reasons.join(" ")} Their tokens and cost are added once settled; nothing is lost.
      </Notice>
    </div>
  );
}

async function costSummary(environmentID: string, start: number, end: number) {
  return (await adminRequest(queryPath("/admin/v1/usage/summary", { breakdown_limit: "50", end: iso(end), environment_id: environmentID, start: iso(start) }), UsageSummarySchema)).data;
}

/** This UTC month so far, a straight-line month-end projection from it, and last month for scale. */
export function MonthToDateCard({ environmentID }: { environmentID: string }) {
  const [months] = useState(() => monthWindows(clock()));
  const current = useQuery({
    enabled: Boolean(environmentID),
    queryFn: () => costSummary(environmentID, months.start, months.now),
    queryKey: ["usage-summary", environmentID, months.start, months.now, "50", "month-to-date"],
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: 5 * 60_000
  });
  const previous = useQuery({
    enabled: Boolean(environmentID),
    queryFn: () => costSummary(environmentID, months.previousStart, months.start),
    queryKey: ["usage-summary", environmentID, months.previousStart, months.start, "50", "last-month"],
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: 60 * 60_000
  });
  const monthName = MONTH.format(months.start);
  const previousName = MONTH.format(months.previousStart);
  const problem = current.error ?? previous.error;
  const cost = current.data ? recorded(current.data.values, "cost_nano_usd") : null;
  const lastCost = previous.data ? recorded(previous.data.values, "cost_nano_usd") : null;
  const projection = projectMonthEnd(cost, months);
  const unpriced = current.data?.analytics.by_model.items.some((item) => item.request_count > 0 && recorded(item.values, "cost_nano_usd") === null) ?? false;
  return (
    <Card
      flush
      footer={<p className="lw-secondary lw-note lw-an-foot">
        A straight line from {monthName} so far, at your configured prices: it doesn&apos;t know about launches, seasons or limit changes.
        {unpriced ? " Some models recorded no cost this month, so both figures are lower than the provider's bill." : ""}
      </p>}
      icon="cost"
      meta="UTC calendar months"
      title="This month"
    >
      {problem ? <div className="lw-an-empty"><ProblemNotice problem={problemFromError(problem)} /></div> : null}
      <StatStrip flush>
        <MetricTile footnote={`${monthName} 1 to now`} label="Month to date" value={current.data ? formatMoney(cost) : "…"} />
        <MetricTile
          delta={percentChange(projection, lastCost)}
          footnote={projection === null ? (cost === null && current.data ? "No recorded cost to project" : "Projects after the first full day") : `If the rest of ${monthName} runs at this pace`}
          higherIsBetter={false}
          label="Projected month end"
          value={current.data ? formatMoney(projection) : "…"}
        />
        <MetricTile footnote={previousName} label="Last month" value={previous.data ? formatMoney(lastCost) : "…"} />
      </StatStrip>
    </Card>
  );
}

type Mode = "cost" | "performance" | "reliability";

const CONNECTION_TITLE: Readonly<Record<Mode, string>> = { cost: "Cost by AI connection", performance: "Latency by AI connection", reliability: "Failures by AI connection" };

/** One row per AI connection over the analytics range, from upstream attempts the server recorded. */
export function ConnectionBreakdownCard({ environmentID, mode, onOpen, window }: { environmentID: string; mode: Mode; onOpen: (upstream: string) => void; window: Range }) {
  const supported = useServerCapability(OPERATIONS_HISTORY);
  const inRange = window.end - window.start <= BREAKDOWN_MAX_MS;
  const health = useQuery({
    enabled: Boolean(environmentID) && supported && inRange,
    queryFn: () => connectionHealth(environmentID, iso(window.start), iso(window.end)),
    queryKey: ["usage", "connections", environmentID, window.start, window.end],
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: 60_000
  });
  const title = CONNECTION_TITLE[mode];
  if (!supported) return <Card icon="connections" title={title}><p className="lw-secondary lw-note">This server can&apos;t break usage down by AI connection.</p></Card>;
  if (!inRange) return <Card icon="connections" title={title}><p className="lw-secondary lw-note">Connection breakdowns cover at most 90 days. Choose a shorter range.</p></Card>;
  if (health.error) return <Card icon="connections" title={title}><ProblemNotice problem={problemFromError(health.error)} /></Card>;
  if (!health.data) return <Card icon="connections" title={title}><p className="lw-page-status" role="status">Loading connections…</p></Card>;
  const rows = health.data.connections;
  type Row = (typeof rows)[number];
  const totalCost = rows.reduce((sum, row) => sum + (recorded(row.usage, "cost_nano_usd") ?? 0), 0);
  const name: Column<Row> = { header: "Connection", key: "upstream", render: (row) => <span className="lw-mono lw-mono--sm">{row.upstream}</span> };
  const attempts: Column<Row> = { align: "right", header: "Attempts", key: "attempts", render: (row) => <span className="lw-num">{row.attempts.toLocaleString()}</span> };
  const columns: Array<Column<Row>> = mode === "cost" ? [
    name,
    { align: "right", header: "Requests", key: "requests", render: (row) => <span className="lw-num">{formatCount(row.usage.logical_requests)}</span> },
    { align: "right", header: "Tokens", key: "tokens", render: (row) => <span className="lw-num">{formatCount(recorded(row.usage, "total_tokens"))}</span> },
    { align: "right", header: "Cost", key: "cost", render: (row) => <span className="lw-num">{formatMoney(recorded(row.usage, "cost_nano_usd"))}</span> },
    { align: "right", header: "Share", key: "share", render: (row) => { const cost = recorded(row.usage, "cost_nano_usd"); return <span className="lw-num lw-secondary">{cost === null || !totalCost ? "—" : `${Math.round((cost / totalCost) * 1000) / 10}%`}</span>; } }
  ] : mode === "performance" ? [
    name,
    attempts,
    { align: "right", header: "First byte p50 · p95", key: "first", render: (row) => row.first_byte.samples ? <span className="lw-num">{formatMs(row.first_byte.p50_ms)} · {formatMs(row.first_byte.p95_ms)}</span> : <span className="lw-faint">—</span> },
    { align: "right", header: "Duration p50 · p95", key: "duration", render: (row) => row.duration.samples ? <span className="lw-num">{formatMs(row.duration.p50_ms)} · {formatMs(row.duration.p95_ms)}</span> : <span className="lw-faint">—</span> }
  ] : [
    name,
    attempts,
    { align: "right", header: "Succeeded", key: "success", render: (row) => { const rate = successRate(row.succeeded, row.failed); return <span className={`lw-num${rate !== undefined && rate < 95 ? " lw-text-warning" : ""}`}>{rate === undefined ? "—" : `${rate}%`}</span>; } },
    { align: "right", header: "429 · 5xx", key: "errors", render: (row) => <span className="lw-num">{row.rate_limited.toLocaleString()} · {row.server_errors.toLocaleString()}</span> },
    { align: "right", header: "Fell back", key: "fallback", render: (row) => <span className="lw-num">{row.fell_back.toLocaleString()}</span> },
    { header: "Top failure", key: "failure", render: (row) => row.failures[0] ? <span className="lw-mono lw-mono--sm">{row.failures[0].code} ×{row.failures[0].count.toLocaleString()}</span> : <span className="lw-faint">None</span> }
  ];
  const sorted = mode === "cost" ? [...rows].sort((a, b) => (recorded(b.usage, "cost_nano_usd") ?? -1) - (recorded(a.usage, "cost_nano_usd") ?? -1)) : rows;
  return (
    <Card
      flush
      footer={<p className="lw-secondary lw-note lw-an-foot">
        {mode === "cost" ? "Usage recorded for the attempt that answered, at your configured prices." : mode === "performance" ? "Per attempt, so a request that fell back counts once for each connection it tried." : "Per attempt: a failure another connection recovered from still counts here. Fell back counts failed attempts another attempt followed."}
        {rows.length ? " Select a row to see its requests." : ""}
      </p>}
      icon="connections"
      meta={health.data.truncated ? "The 200 busiest connections" : `${rows.length.toLocaleString()} connection${rows.length === 1 ? "" : "s"}`}
      title={title}
    >
      {rows.length ? (
        <DataTable caption={title} columns={columns} onSelect={(row) => onOpen(row.upstream)} rowKey={(row) => row.upstream} rows={sorted} />
      ) : <p className="lw-secondary lw-an-empty">No attempts reached an AI connection in this range.</p>}
    </Card>
  );
}

/** Requests by recorded error code over the range, from request facets. */
export function ErrorCodesCard({ environmentID, onOpen, window }: { environmentID: string; onOpen: (code: string) => void; window: Range }) {
  const supported = useServerCapability(REQUEST_SEARCH);
  const inRange = window.end - window.start <= BREAKDOWN_MAX_MS;
  const facets = useQuery({
    enabled: Boolean(environmentID) && supported && inRange,
    queryFn: async () => {
      const response = (await adminRequest(queryPath("/admin/v1/requests/facets", { end: iso(window.end), environment_id: environmentID, limit: "20", start: iso(window.start) }), RequestFacetsSchema)).data;
      if (response.environment_id !== environmentID) throw new Error("The error counts belonged to another environment.");
      return response;
    },
    queryKey: ["request-facets", environmentID, window.start, window.end, "errors"],
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: 60_000
  });
  if (!supported) return <Notice title="This server can't count requests by error code" tone="info">Open Requests and filter by outcome or error to see which errors happened and where.</Notice>;
  if (!inRange) return <Notice title="Error counts cover at most 90 days" tone="info">Choose a shorter range to count requests by error code.</Notice>;
  const values = facets.data?.facets.error_code.values ?? [];
  const total = facets.data?.requests ?? 0;
  return (
    <Card icon="alert" meta={facets.data ? `${total.toLocaleString()} requests in range` : undefined} title="Errors by code">
      {facets.error ? <ProblemNotice problem={problemFromError(facets.error)} /> : !facets.data ? <p className="lw-page-status" role="status">Counting errors…</p> : values.length ? (
        <ul aria-label="Errors by code" className="lw-share">
          {values.map((item) => {
            const share = total ? Math.round((item.count / total) * 1000) / 10 : 0;
            return (
              <li className="lw-share__row" key={item.value}>
                <button className="lw-link lw-mono lw-mono--sm lw-share__plan" onClick={() => onOpen(item.value)} type="button">{item.value}</button>
                <span aria-hidden="true" className="lw-share__bar"><span style={{ width: `${Math.max(share, 1)}%` }} /></span>
                <span className="lw-num lw-share__value">{item.count.toLocaleString()} · {share}%</span>
              </li>
            );
          })}
        </ul>
      ) : <p className="lw-secondary lw-note">No request in this range ended with an error code.</p>}
      {facets.data?.facets.error_code.truncated ? <p className="lw-faint lw-note">The 20 most common codes; others are left out.</p> : null}
      <p className="lw-secondary lw-note">Each request&apos;s final error code, including refusals by limits and app verification. Select a code to see those requests.</p>
    </Card>
  );
}

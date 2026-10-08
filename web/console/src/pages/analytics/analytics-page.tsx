import { Link, useNavigate } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";

import type { UsageSummary } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { type AnalyticsRouteSearch, AnalyticsRouteSearchSchema, type RequestRouteSearch } from "../../app/route-search";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import { downloadText } from "../../components/download";
import { MenuButton } from "../../components/menu-button";
import {
  Badge,
  Button,
  buttonClass,
  Card,
  type ChartPoint,
  type Column,
  DataTable,
  EmptyState,
  MetricTile,
  Notice,
  PageHeader,
  ProportionBar,
  RangePicker,
  Segmented,
  StatStrip,
  VolumeChart
} from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { ConnectionBreakdownCard, ErrorCodesCard, MonthToDateCard, SettlementNotice } from "./analytics-insights";
import { formatMs } from "../requests/request-format";
import {
  BREAKDOWN_LABEL,
  breakdownCsv,
  breakdownKeyLabel,
  breakdownOf,
  type Bucket,
  buckets,
  bucketSize,
  cliCommands,
  CUSTOM_PERIOD_MAX_DAYS,
  formatAxisMoney,
  formatCount,
  formatMoney,
  fraction,
  iso,
  percent,
  percentChange,
  PERIOD_PRESETS,
  periodOf,
  periodPatch,
  pointChange,
  PROVENANCE,
  ratePercent,
  recorded,
  timeseriesCsv,
  type UsageWindow,
  windowLabel
} from "./usage-model";
import { isUsageContextMismatch, useUsage } from "./use-usage";

export type AnalyticsTab = "usage" | "cost" | "performance" | "reliability";

const TAB_COPY: Record<AnalyticsTab, string> = {
  cost: "What that usage costs, at the prices you set for each model.",
  performance: "How long requests take, end to end and to the first token.",
  reliability: "How often requests fail, are refused by limits or need a fallback.",
  usage: "How much your apps use AI through Latchway: requests, people and tokens."
};

type Workspace = ReturnType<typeof useWorkspace>;
type Usage = ReturnType<typeof useUsage>;
type RequestDrill = Partial<Pick<RequestRouteSearch, "error_code" | "feature" | "latency_min_ms" | "model" | "status" | "upstream">>;

function tickEvery(count: number): number {
  return count <= 8 ? 1 : count <= 24 ? 3 : count <= 31 ? 5 : count <= 92 ? 14 : 30;
}

/** Opens Requests with real API filters for a time window; the usage API itself can't list requests. */
function useOpenRequests(workspace: Workspace) {
  const navigate = useNavigate();
  return (filters: RequestDrill, start: number, end: number) => void navigate({
    search: {
      application: workspace.search.application,
      end: iso(end),
      environment: workspace.search.environment,
      organization: workspace.search.organization,
      start: iso(start),
      ...filters
    },
    to: "/requests"
  });
}

function UsageChart({ metric, onSelect, previousLabel, usage }: { metric: "requests" | "tokens" | "cost"; onSelect: (bucket: Bucket) => void; previousLabel: string; usage: Usage }) {
  const current = buckets(usage.window, usage.series);
  const previous = usage.previousSeries ? buckets(usage.previousWindow, usage.previousSeries) : undefined;
  const points: ChartPoint[] = current.map((bucket, index) => {
    const values: Record<string, number> = metric === "tokens"
      ? { input: recorded(bucket.values, "input_tokens") ?? 0, output: recorded(bucket.values, "output_tokens") ?? 0 }
      : metric === "cost"
        ? { cost: recorded(bucket.values, "cost_nano_usd") ?? 0 }
        : { requests: bucket.values?.logical_requests ?? 0 };
    const earlier = previous?.[index]?.values;
    if (previous) values.previous = metric === "tokens" ? recorded(earlier, "total_tokens") ?? 0 : metric === "cost" ? recorded(earlier, "cost_nano_usd") ?? 0 : earlier?.logical_requests ?? 0;
    return { label: bucket.label, title: bucket.title, values };
  });
  const what = metric === "cost" ? "Cost" : metric === "tokens" ? "Input and output tokens" : "Requests";
  return (
    <VolumeChart
      bars={metric === "tokens" ? ["input", "output"] : [metric]}
      colors={{ cost: "var(--orange)", requests: "var(--accent-subtle)" }}
      dashed={previous ? ["previous"] : []}
      format={metric === "cost" ? formatAxisMoney : (value) => formatCount(value)}
      label={`${what} per ${usage.window.interval} (UTC). Select a bar to see its requests.`}
      labels={{ cost: "Cost", input: "Input tokens", output: "Output tokens", previous: previousLabel, requests: "Requests" }}
      legendFormat={metric === "cost" ? (value) => formatMoney(value) : (value) => formatCount(value)}
      onSelect={(_, index) => { const bucket = current[index]; if (bucket) onSelect(bucket); }}
      partialLast={usage.window.partialLast}
      points={points}
      tickEvery={tickEvery(points.length)}
    />
  );
}

function ChartCard({ children, interval, options }: { children: ReactNode; interval: "hour" | "day"; options?: ReactNode }) {
  return (
    <Card actions={options} flush icon="analytics" title={`Per ${interval} · UTC`}>
      {children}
      <p className="lw-an-chartnote">Select a bar to open its requests. The hatched {interval} is still counting.</p>
    </Card>
  );
}

function BreakdownCard({ by, limit, mode, onBy, onLimit, onOpen, previous, summary }: {
  by: "feature" | "model" | "plan";
  limit: "5" | "50" | "200";
  mode: "usage" | "cost";
  onBy: (by: "feature" | "model" | "plan") => void;
  onLimit: (limit: "5" | "50" | "200") => void;
  onOpen: (key: string) => void;
  previous?: UsageSummary;
  summary: UsageSummary;
}) {
  const [showAll, setShowAll] = useState(false);
  const breakdown = breakdownOf(summary, by);
  const previousItems = previous ? breakdownOf(previous, by).items : undefined;
  const value = (values: UsageSummary["values"], count: number) => (mode === "cost" ? recorded(values, "cost_nano_usd") : count);
  const items = [...breakdown.items].sort((a, b) => (value(b.values, b.request_count) ?? -1) - (value(a.values, a.request_count) ?? -1) || b.request_count - a.request_count);
  const total = mode === "cost" ? recorded(summary.values, "cost_nano_usd") ?? 0 : summary.analytics.request_count;
  type Item = typeof items[number];
  const columns: Array<Column<Item>> = [
    { header: BREAKDOWN_LABEL[by], key: "key", render: (item) => { const key = breakdownKeyLabel(item.key, by); return <span className="lw-an-key"><span className={by === "model" ? "lw-mono lw-mono--sm" : undefined}>{key.label}</span>{key.note ? <span className="lw-faint">{key.note}</span> : null}</span>; } },
    { align: "right", header: "Active users", key: "users", render: (item) => formatCount(item.active_users) },
    { align: "right", header: "Requests", key: "requests", render: (item) => formatCount(item.request_count) },
    ...(mode === "usage" ? [
      { align: "right" as const, header: "Input tokens", key: "input", render: (item: Item) => <span className={recorded(item.values, "input_tokens") === null ? "lw-faint" : undefined} title={recorded(item.values, "input_tokens") === null ? "No record" : undefined}>{formatCount(recorded(item.values, "input_tokens"))}</span> },
      { align: "right" as const, header: "Output tokens", key: "output", render: (item: Item) => <span className={recorded(item.values, "output_tokens") === null ? "lw-faint" : undefined} title={recorded(item.values, "output_tokens") === null ? "No record" : undefined}>{formatCount(recorded(item.values, "output_tokens"))}</span> }
    ] : []),
    { align: "right", header: "Cost", key: "cost", render: (item) => recorded(item.values, "cost_nano_usd") === null ? <span className="lw-an-unpriced">No cost recorded</span> : formatMoney(recorded(item.values, "cost_nano_usd")) },
    ...(mode === "cost" ? [{ align: "right" as const, header: "Per request", key: "per", render: (item: Item) => { const cost = recorded(item.values, "cost_nano_usd"); return cost === null || !item.request_count ? "—" : formatMoney(cost / item.request_count); } }] : []),
    ...(previousItems ? [{
      align: "right" as const,
      header: "Change",
      key: "change",
      render: (item: Item) => {
        const before = previousItems.find((candidate) => candidate.key === item.key);
        if (!before) return <Badge color="green" variant="soft">New</Badge>;
        const change = percentChange(value(item.values, item.request_count), value(before.values, before.request_count));
        return change === undefined ? "—" : <span className="lw-an-chg">{change > 0 ? "+" : ""}{change}%</span>;
      }
    }] : []),
    {
      header: "Share",
      key: "share",
      render: (item) => {
        const share = total ? ((value(item.values, item.request_count) ?? 0) / total) * 100 : 0;
        return <span className="lw-an-share"><span className="lw-an-share__bar"><span style={{ width: `${share}%` }} /></span><span className="lw-num">{share > 0 && share < 1 ? "<1%" : `${Math.round(share)}%`}</span></span>;
      },
      width: 140
    }
  ];
  const shown = showAll ? items : items.slice(0, 10);
  return (
    <Card
      actions={<Segmented items={[{ id: "feature", label: "Feature" }, { id: "model", label: "Model" }, { id: "plan", label: "Plan" }]} label="Break down by" onChange={onBy} value={by} />}
      flush
      footer={
        <div className="lw-an-foot">
          <span>
            {breakdown.truncated
              ? `Showing the ${breakdown.limit} rows Latchway returned. Others are left out of this table but counted in the totals.`
              : `${items.length} ${BREAKDOWN_LABEL[by].toLowerCase()}${items.length === 1 ? "" : "s"} · ${by === "plan" ? "select a row to open Policies & Limits" : "select a row to see its requests"}`}
          </span>
          <span className="lw-row"><span className="lw-faint">Rows</span><Segmented items={[{ id: "5", label: "5" }, { id: "50", label: "50" }, { id: "200", label: "200" }]} label="Rows to fetch" onChange={onLimit} value={limit} /></span>
        </div>
      }
      icon="features"
      title={mode === "cost" ? "Cost by" : "Breakdown"}
    >
      {items.length ? <>
        <DataTable caption={`${mode === "cost" ? "Cost" : "Usage"} by ${BREAKDOWN_LABEL[by].toLowerCase()}`} columns={columns} onSelect={(item) => onOpen(item.key)} rowKey={(item) => item.key} rows={shown} />
        {items.length > 10 ? <button className="lw-alist__more" onClick={() => setShowAll(!showAll)} type="button">{showAll ? "Show top 10" : `Show all ${items.length}`}</button> : null}
      </> : <p className="lw-secondary lw-an-empty">Nothing in this range.</p>}
    </Card>
  );
}

function ProvenanceCard({ kind, summary }: { kind: "tokens" | "cost"; summary: UsageSummary }) {
  const rows = summary.analytics.usage_by_provenance.map((row) => ({ ...row, amount: recorded(row.values, kind === "cost" ? "cost_nano_usd" : "total_tokens") ?? 0 }));
  const total = rows.reduce((sum, row) => sum + row.amount, 0);
  const uncertain = total ? rows.filter((row) => row.provenance === "estimated" || row.provenance === "unknown").reduce((sum, row) => sum + row.amount, 0) / total : 0;
  const reportedCost = summary.analytics.usage_by_provenance.filter((row) => row.provenance === "upstream_reported" && row.cost_source);
  return (
    <Card className="lw-an-provcard" icon="shield" meta={kind === "cost" ? "By cost" : "By tokens"} title={kind === "cost" ? "Where the cost comes from" : "How sure these numbers are"}>
      {total ? <ProportionBar segments={rows.filter((row) => row.amount > 0).map((row) => ({ color: PROVENANCE[row.provenance].color, display: percent(row.amount, total), key: row.provenance, label: PROVENANCE[row.provenance].label, value: row.amount }))} showValues /> : <p className="lw-secondary lw-note">Nothing recorded in this range.</p>}
      <dl className="lw-an-prov">
        {rows.map((row) => (
          <div key={row.provenance}>
            <dt><span aria-hidden="true" className="lw-swatch" style={{ background: PROVENANCE[row.provenance].color }} />{PROVENANCE[row.provenance].label}<span className="lw-faint lw-num">{total ? `${percent(row.amount, total)} · ` : ""}{kind === "cost" ? formatMoney(row.amount) : formatCount(row.amount)}</span></dt>
            <dd>{PROVENANCE[row.provenance].text}{row.cost_source ? ` Source: ${row.cost_source}.` : ""}</dd>
          </div>
        ))}
      </dl>
      {kind === "cost" ? <p className="lw-an-note">{reportedCost.length ? <>Provider-reported cost comes from {reportedCost.map((row) => <code key={row.cost_source}>{row.cost_source}</code>)} and is never mixed with your prices.</> : "No provider-reported cost in this range. Only some connections report cost directly; it's labeled with its source when present."}</p> : null}
      {uncertain > 0.05 ? <Notice title={`${Math.round(uncertain * 100)}% estimated or unknown`} tone="warning">Totals may include conservative quota charges, so they can run higher than your provider's bill.</Notice> : null}
    </Card>
  );
}

function LatencyCard({ current, previous, text, title }: { current: UsageSummary["analytics"]["request_latency"]; previous?: UsageSummary["analytics"]["request_latency"]; text: string; title: string }) {
  const maximum = Math.max(current.p99_ms, previous?.p99_ms ?? 0, 1);
  const rows: Array<["p50" | "p95" | "p99", string]> = [["p50", "Half of requests are faster"], ["p95", "19 in 20 are faster"], ["p99", "99 in 100 are faster"]];
  return (
    <Card icon="clock" meta={`${current.samples.toLocaleString()} samples`} title={title}>
      <p className="lw-secondary lw-card-lede">{text}</p>
      {current.samples ? (
        <div className="lw-an-lat">
          {rows.map(([quantile, hint]) => {
            const value = current[`${quantile}_ms`];
            const before = previous?.samples ? previous[`${quantile}_ms`] : undefined;
            const change = before ? percentChange(value, before) : undefined;
            return (
              <div className="lw-an-lat__row" key={quantile}>
                <span className="lw-an-lat__q">{quantile}</span>
                <span className="lw-an-lat__track">
                  <span className="lw-an-lat__fill" style={{ width: `${(value / maximum) * 100}%` }} />
                  {before ? <span className="lw-an-lat__prev" style={{ left: `${(before / maximum) * 100}%` }} title={`Previous: ${formatMs(before)}`} /> : null}
                </span>
                <strong className="lw-num">{formatMs(value)}</strong>
                {change !== undefined ? <span className={`lw-an-chg${change > 0 ? " is-bad" : change < 0 ? " is-good" : ""}`}>{change > 0 ? "+" : ""}{change}%</span> : <span />}
                <span className="lw-an-lat__hint">{hint}</span>
              </div>
            );
          })}
        </div>
      ) : <p className="lw-secondary lw-note">No samples in this range.</p>}
    </Card>
  );
}

type RateKey = "failure_rate" | "quota_denial_rate" | "attestation_failure_rate" | "fallback_rate";

function RateCard({ action, current, denominatorLabel, icon, previous, text, title }: { action: ReactNode; current: UsageSummary["analytics"][RateKey]; denominatorLabel: string; icon: "alert" | "policies" | "trust" | "split"; previous?: UsageSummary["analytics"][RateKey]; text: string; title: string }) {
  const change = pointChange(current, previous);
  return (
    <Card actions={action} className="lw-an-rate" icon={icon} title={title}>
      <div className="lw-an-rate__num">
        <strong className="lw-num">{ratePercent(current, 2)}</strong>
        {change !== undefined && change !== 0 ? <span className={`lw-an-chg${change > 0 ? " is-bad" : " is-good"}`}>{change > 0 ? "+" : ""}{change} pts</span> : null}
      </div>
      <p className="lw-an-rate__count lw-num">{current.numerator.toLocaleString()} of {current.denominator.toLocaleString()} {denominatorLabel}{previous ? ` · ${ratePercent(previous, 2)} before` : ""}</p>
      <p className="lw-secondary lw-note">{text}</p>
    </Card>
  );
}

function AnalyticsView({ tab }: { tab: AnalyticsTab }) {
  const workspace = useWorkspace();
  const environment = workspace.environment;
  const environmentID = environment?.id ?? "";
  const search = AnalyticsRouteSearchSchema.parse(workspace.search);
  const period = periodOf(search);
  const compare = search.compare !== "off";
  const breakdownLimit = search.breakdown_limit ?? "50";
  const by = search.by ?? "feature";
  const usage = useUsage({ breakdownLimit, compare, environmentID, period });
  const openRequests = useOpenRequests(workspace);
  const navigate = useNavigate();
  const [copied, setCopied] = useState<string>();
  const update = (patch: Partial<AnalyticsRouteSearch>) => workspace.updateSearch(patch);
  const summary = usage.summary;
  const previous = usage.previous;
  const periodName = period.id === "custom" ? "period" : period.id;
  const workspaceLinkSearch = { application: search.application, environment: search.environment, organization: search.organization };
  const window: UsageWindow = usage.window;
  const drillBucket = (bucket: Bucket, filters: RequestDrill = {}) => openRequests(filters, bucket.start, bucket.start + bucketSize(window));
  const drillRange = (filters: RequestDrill) => openRequests(filters, window.start, window.end);
  const currentBuckets = buckets(window, usage.series);

  function copyCli(): void {
    const command = cliCommands(environmentID, window, breakdownLimit);
    try {
      void navigator.clipboard.writeText(command).then(() => setCopied("CLI commands copied: latchway usage summary and timeseries for this range."), () => setCopied(command));
    } catch {
      setCopied(command);
    }
  }

  const header = (
    <>
      <PageHeader
        actions={
          <div className="lw-an-actions">
            <RangePicker label="Range" maxDays={CUSTOM_PERIOD_MAX_DAYS} onChange={(next) => update(periodPatch(next))} presets={PERIOD_PRESETS} value={period} />
            <MenuButton entries={[
              { heading: windowLabel(window), kind: "heading" },
              ...(summary ? [{ label: "Breakdowns as CSV", onSelect: () => downloadText(`usage-${environment?.slug ?? "environment"}-breakdowns-${iso(window.start).slice(0, 10)}.csv`, breakdownCsv(summary)) }] : []),
              ...(usage.series ? [{ label: "Timeseries as CSV", onSelect: () => downloadText(`usage-${environment?.slug ?? "environment"}-timeseries-${iso(window.start).slice(0, 10)}.csv`, timeseriesCsv(currentBuckets)) }] : []),
              { kind: "separator" },
              { icon: "code", label: "Copy CLI Command", onSelect: copyCli }
            ]} icon="upload" label="Export">Export</MenuButton>
          </div>
        }
        description={TAB_COPY[tab]}
        title="Analytics"
      />
      <div className="lw-an-bar">
        <label className="lw-check">
          <input checked={compare} onChange={(event) => update({ compare: event.target.checked ? undefined : "off" })} type="checkbox" />
          <span>Compare with the previous {periodName}</span>
        </label>
        <span className="lw-an-bar__range">{windowLabel(window)}</span>
        <span className="lw-spacer" />
        <span className="lw-an-live" title="Refreshes when Latchway reports new usage">
          <span aria-hidden="true" className="lw-an-live__dot" />
          {usage.updatedAt ? `Live · updated ${new Date(usage.updatedAt).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}` : "Live"}
        </span>
      </div>
      <SettlementNotice workspaceSearch={workspaceLinkSearch} />
      {copied ? <div className="lw-page-notice"><Notice action={<Button onClick={() => setCopied(undefined)} size="sm">Dismiss</Button>} title={copied.startsWith("latchway") ? "Copy these commands" : "Copied"} tone="success">{copied.startsWith("latchway") ? <pre className="lw-code-block">{copied}</pre> : copied}</Notice></div> : null}
    </>
  );

  if (usage.error) {
    const problem = isUsageContextMismatch(usage.error)
      ? { code: "invalid_response", detail: "The usage time series did not match the requested interval.", retryable: true, status: 0, title: "Analytics context mismatch" }
      : problemFromError(usage.error);
    return <div className="lw-page">{header}<div className="lw-body"><ProblemNotice problem={problem} /></div></div>;
  }
  if (usage.isPending || !summary) return <div className="lw-page">{header}<p className="lw-page-status" role="status">Loading usage…</p></div>;
  if (!summary.analytics.request_count && !summary.values.logical_requests) {
    return (
      <div className="lw-page">{header}<div className="lw-body">
        <EmptyState action={period.id === "30d" ? <Link className={buttonClass()} search={workspaceLinkSearch} to="/features">Open Features</Link> : <Button onClick={() => update(periodPatch({ id: "30d" }))}>Show Last 30 Days</Button>} icon="analytics" orientation="horizontal" title="No usage in this range">
          {period.id === "30d" ? "Usage appears here within a minute of the first request through Latchway." : "Try a longer range."}
        </EmptyState>
      </div></div>
    );
  }

  const analytics = summary.analytics;
  const before = previous?.analytics;
  const versus = (text: string) => (previous ? `vs ${text} before` : undefined);
  const chartMetric = search.chart ?? "requests";
  const previousLabel = `Previous ${periodName}`;
  function openBreakdown(key: string): void {
    if (by === "plan") {
      // Requests can't filter by plan, so plan rows open the plans themselves.
      void navigate({ search: workspaceLinkSearch, to: "/limit-plans" });
      return;
    }
    if (key === "legacy_unknown") return;
    drillRange(by === "feature" ? { feature: key } : { model: key });
  }

  let body: ReactNode;

  if (tab === "usage") {
    const input = recorded(summary.values, "input_tokens");
    const output = recorded(summary.values, "output_tokens");
    const perActive = fraction(analytics.requests_per_active_user);
    body = <>
      <Card flush>
        <StatStrip flush>
          <MetricTile color="var(--accent-subtle)" delta={percentChange(analytics.request_count, before?.request_count)} footnote={versus(formatCount(before?.request_count ?? 0)) ?? "Logical requests, counted once however many attempts"} label="Requests" onClick={() => update({ chart: undefined })} value={formatCount(analytics.request_count)} />
          <MetricTile color="var(--accent-primary)" delta={percentChange(analytics.active_users, before?.active_users)} footnote={perActive === null ? "No active users" : `${perActive.toLocaleString(undefined, { maximumFractionDigits: 1 })} requests each`} label="Active users" value={formatCount(analytics.active_users)} />
          <MetricTile delta={percentChange(input, previous ? recorded(previous.values, "input_tokens") : undefined)} footnote={input === null || !analytics.request_count ? "No record" : `${Math.round(input / analytics.request_count).toLocaleString()} per request`} label="Input tokens" onClick={() => update({ chart: "tokens" })} value={formatCount(input)} />
          <MetricTile delta={percentChange(output, previous ? recorded(previous.values, "output_tokens") : undefined)} footnote={output === null || !analytics.request_count ? "No record" : `${Math.round(output / analytics.request_count).toLocaleString()} per request`} label="Output tokens" onClick={() => update({ chart: "tokens" })} value={formatCount(output)} />
        </StatStrip>
      </Card>
      <ChartCard interval={window.interval} options={<Segmented items={[{ id: "requests", label: "Requests" }, { id: "tokens", label: "Tokens" }]} label="Chart" onChange={(value) => update({ chart: value === "requests" ? undefined : value })} value={chartMetric} />}>
        <UsageChart metric={chartMetric} onSelect={(bucket) => drillBucket(bucket)} previousLabel={previousLabel} usage={usage} />
      </ChartCard>
      <BreakdownCard by={by} limit={breakdownLimit} mode="usage" onBy={(value) => update({ by: value === "feature" ? undefined : value })} onLimit={(value) => update({ breakdown_limit: value === "50" ? undefined : value })} onOpen={(key) => openBreakdown(key)} previous={previous} summary={summary} />
      <ProvenanceCard kind="tokens" summary={summary} />
    </>;
  } else if (tab === "cost") {
    const cost = recorded(summary.values, "cost_nano_usd");
    const unpriced = analytics.by_model.items.filter((item) => item.request_count > 0 && recorded(item.values, "cost_nano_usd") === null);
    const perUser = fraction(analytics.cost_per_active_user_nano_usd);
    const previousPerUser = before ? fraction(before.cost_per_active_user_nano_usd) : undefined;
    const perThousand = cost === null || !analytics.request_count ? null : (cost / analytics.request_count) * 1000;
    const previousCost = previous ? recorded(previous.values, "cost_nano_usd") : undefined;
    const previousPerThousand = before && previousCost !== null && previousCost !== undefined && before.request_count ? (previousCost / before.request_count) * 1000 : undefined;
    body = <>
      {unpriced.length ? (
        <Notice action={<Link className={buttonClass({ size: "sm" })} search={workspaceLinkSearch} to="/models-pricing">Set Prices</Link>} title={unpriced.length === 1 ? "1 model has no recorded cost" : `${unpriced.length} models have no recorded cost`} tone="warning">
          {unpriced.map((item) => `${item.key} (${formatCount(item.request_count)} requests)`).join(", ")} recorded no cost, so the total is lower than what you'll be billed. A missing cost is not a zero bill.
        </Notice>
      ) : null}
      <Card flush>
        <StatStrip flush>
          <MetricTile color="var(--orange)" delta={percentChange(cost, previousCost)} footnote={versus(formatMoney(previousCost ?? null)) ?? "At your configured prices"} higherIsBetter={false} label="Cost" value={formatMoney(cost)} />
          <MetricTile delta={percentChange(perUser, previousPerUser)} footnote={`${formatCount(analytics.active_users)} active users`} higherIsBetter={false} label="Per active user" value={formatMoney(perUser)} />
          <MetricTile delta={percentChange(perThousand, previousPerThousand)} footnote="Across all requests in the range" higherIsBetter={false} label="Per 1,000 requests" value={formatMoney(perThousand)} />
        </StatStrip>
      </Card>
      <MonthToDateCard environmentID={environmentID} />
      <ChartCard interval={window.interval}>
        <UsageChart metric="cost" onSelect={(bucket) => drillBucket(bucket)} previousLabel={previousLabel} usage={usage} />
      </ChartCard>
      <BreakdownCard by={by} limit={breakdownLimit} mode="cost" onBy={(value) => update({ by: value === "feature" ? undefined : value })} onLimit={(value) => update({ breakdown_limit: value === "50" ? undefined : value })} onOpen={(key) => openBreakdown(key)} previous={previous} summary={summary} />
      <ConnectionBreakdownCard environmentID={environmentID} mode="cost" onOpen={(upstream) => drillRange({ upstream })} window={window} />
      <div className="lw-hgrid lw-hgrid--2">
        <ProvenanceCard kind="cost" summary={summary} />
        <Card icon="bell" meta="Latchway has no budgets yet" title="Get alerted">
          <p className="lw-secondary lw-card-lede">Run this hourly from cron or CI with a view-only Admin API token in <code className="lw-code-inline">LATCHWAY_ADMIN_API_TOKEN</code>. It fails when today's cost passes your limit.</p>
          <pre className="lw-code-block">{`LIMIT_USD=25\nSTART=$(date -u +%Y-%m-%dT00:00:00Z)\nNANO=$(latchway usage summary --environment ${environmentID} \\\n  --start "$START" --output json | jq '.values.cost_nano_usd')\n[ "$NANO" -le $((LIMIT_USD * 1000000000)) ] || {\n  echo "Latchway cost today: $((NANO / 1000000000)) USD"; exit 1; }`}</pre>
        </Card>
      </div>
    </>;
  } else if (tab === "performance") {
    body = <>
      <div className="lw-hgrid lw-hgrid--2">
        <LatencyCard current={analytics.request_latency} previous={before?.request_latency} text="From the gateway receiving a request to the last byte sent back, including fallbacks." title="Request latency" />
        <LatencyCard current={analytics.time_to_first_token} previous={before?.time_to_first_token} text="Streaming requests only: how long until the user sees the first token." title="Time to first token" />
      </div>
      <div className="lw-hgrid lw-hgrid--2">
        <Card actions={<Link className={buttonClass({ size: "md" })} search={workspaceLinkSearch} to="/routes">Open Routing</Link>} icon="split" meta={`${ratePercent(analytics.fallback_rate)} of requests that reached a provider`} title="Fallbacks">
          <p className="lw-secondary lw-note">{analytics.fallback_rate.numerator.toLocaleString()} requests needed a second route{before ? ` (${before.fallback_rate.numerator.toLocaleString()} before)` : ""}. Each fallback adds the first attempt's time to latency.</p>
        </Card>
        <Card actions={<Button onClick={() => drillRange({ latency_min_ms: "2000" })} size="md">Show Requests Over 2 s</Button>} icon="requests" title="Find slow requests">
          <p className="lw-secondary lw-note">These percentiles cover the whole range, not each feature or hour. Requests shows each slow request with its route and attempts.</p>
        </Card>
      </div>
      <ConnectionBreakdownCard environmentID={environmentID} mode="performance" onOpen={(upstream) => drillRange({ upstream })} window={window} />
    </>;
  } else {
    body = <>
      <Card flush>
        <StatStrip flush>
          <MetricTile color="var(--destructive)" delta={pointChange(analytics.failure_rate, before?.failure_rate)} deltaUnit=" pts" footnote={`${analytics.failure_rate.numerator.toLocaleString()} of ${analytics.request_count.toLocaleString()} requests`} higherIsBetter={false} label="Failed" value={ratePercent(analytics.failure_rate, 2)} />
          <MetricTile color="var(--orange)" delta={pointChange(analytics.quota_denial_rate, before?.quota_denial_rate)} deltaUnit=" pts" footnote="Refused by a limit plan" higherIsBetter={false} label="Denied by limits" value={ratePercent(analytics.quota_denial_rate, 2)} />
          <MetricTile color="var(--grey)" delta={pointChange(analytics.attestation_failure_rate, before?.attestation_failure_rate)} deltaUnit=" pts" footnote={`${analytics.attestation_failure_rate.numerator.toLocaleString()} of ${analytics.attestation_failure_rate.denominator.toLocaleString()} checks`} higherIsBetter={false} label="Failed app verification" value={ratePercent(analytics.attestation_failure_rate, 2)} />
          <MetricTile delta={pointChange(analytics.fallback_rate, before?.fallback_rate)} deltaUnit=" pts" footnote="Requests that needed a second route" higherIsBetter={false} label="Fallbacks" value={ratePercent(analytics.fallback_rate, 2)} />
        </StatStrip>
      </Card>
      <div className="lw-an-rates">
        <RateCard action={<Button onClick={() => drillRange({ status: "failed" })} size="md">See Failed Requests</Button>} current={analytics.failure_rate} denominatorLabel="requests" icon="alert" previous={before?.failure_rate} text="The AI provider errored or timed out after every allowed fallback. Users saw an error." title="Failures" />
        <RateCard action={<Button onClick={() => drillRange({ error_code: "quota_exceeded", status: "denied" })} size="md">See Denied Requests</Button>} current={analytics.quota_denial_rate} denominatorLabel="requests" icon="policies" previous={before?.quota_denial_rate} text="A limit plan refused the request before it reached a provider. Expected when limits work; a jump means limits are tight or someone is pushing them." title="Quota denials" />
        <RateCard action={<Link className={buttonClass({ size: "md" })} search={workspaceLinkSearch} to="/attestation">Open App Verification</Link>} current={analytics.attestation_failure_rate} denominatorLabel="verification checks" icon="trust" previous={before?.attestation_failure_rate} text="App Attest, Play Integrity, App Check or Turnstile didn't vouch for the app. Counted per verification check, not per request." title="App verification failures" />
        <RateCard action={<Link className={buttonClass({ size: "md" })} search={workspaceLinkSearch} to="/routes">Open Routing</Link>} current={analytics.fallback_rate} denominatorLabel="requests that reached a provider" icon="split" previous={before?.fallback_rate} text="The first route failed and a later one answered. Users were served, but slower." title="Fallbacks" />
      </div>
      <ErrorCodesCard environmentID={environmentID} onOpen={(code) => drillRange({ error_code: code })} window={window} />
      <ConnectionBreakdownCard environmentID={environmentID} mode="reliability" onOpen={(upstream) => drillRange({ upstream })} window={window} />
    </>;
  }

  return <div className="lw-page lw-analytics">{header}<div className="lw-body">{body}</div></div>;
}

function AnalyticsWorkspace({ tab }: { tab: AnalyticsTab }) {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><AnalyticsView tab={tab} /></EnvironmentRequired>;
}

/** Traffic → Analytics, on GET /admin/v1/usage/summary and /usage/timeseries for one environment. */
export function AnalyticsPage({ tab }: { tab: AnalyticsTab }) {
  return <AnalyticsWorkspace tab={tab} />;
}

export function UsageAnalyticsPage() { return <AnalyticsPage tab="usage" />; }
export function CostAnalyticsPage() { return <AnalyticsPage tab="cost" />; }
export function PerformanceAnalyticsPage() { return <AnalyticsPage tab="performance" />; }
export function ReliabilityAnalyticsPage() { return <AnalyticsPage tab="reliability" />; }


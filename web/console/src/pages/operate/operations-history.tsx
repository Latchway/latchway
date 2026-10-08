import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import type { SelfTestRun } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { connectionHealth, healthHistory, listSelfTests, type SelfTestPage } from "../../api/operations-history";
import { Badge, Button, type Column, DataTable, EmptyState, Segmented } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";
import { formatUsd } from "../requests/request-format";
import { healthIncidents, healthyShare, successRate } from "./operations-history-model";

/** Wall-clock reads happen when a query runs, never while rendering. */
const clock = (): number => Date.now();

const STATE_LABEL = { degraded: "Degraded", healthy: "Healthy", unhealthy: "Unhealthy" } as const;

/** The server's own self-check over time, sampled by a worker every five minutes. */
export function HealthTimeline({ checkName }: { checkName: (id: string) => string }) {
  const [days, setDays] = useState<"1" | "7">("1");
  const history = useQuery({
    queryFn: () => {
      const end = clock();
      return healthHistory(new Date(end - Number(days) * 86_400_000).toISOString(), new Date(end).toISOString());
    },
    queryKey: ["system", "health-history", days],
    refetchInterval: 5 * 60_000,
    retry: false
  });
  const samples = history.data?.samples ?? [];
  const share = healthyShare(samples);
  const incidents = history.data ? healthIncidents(samples, history.data.interval_seconds).reverse() : [];
  return (
    <div className="lw-stack lw-stack--tight">
      <div className="lw-row lw-row--spread">
        <span className="lw-note">{share === undefined ? (history.data ? "No samples yet: a worker records one every five minutes." : "") : <><strong>{Math.round(share * 1000) / 10}%</strong> of samples healthy in the last {days === "1" ? "24 hours" : "7 days"}</>}</span>
        <Segmented items={[{ id: "1", label: "24 hours" }, { id: "7", label: "7 days" }]} label="History range" onChange={setDays} value={days} />
      </div>
      {history.error ? <ProblemNotice problem={problemFromError(history.error)} /> : null}
      {samples.length ? (
        <ol aria-label="Health samples" className="lw-health-strip">
          {samples.map((sample) => <li className={`lw-health-strip__cell is-${sample.overall_state}`} key={sample.sampled_at} title={`${new Date(sample.sampled_at).toLocaleString()} · ${STATE_LABEL[sample.overall_state]}`}><span className="lw-sr">{new Date(sample.sampled_at).toLocaleString()}: {STATE_LABEL[sample.overall_state]}</span></li>)}
        </ol>
      ) : null}
      {incidents.length ? (
        <ul aria-label="Incidents" className="lw-issue-list lw-note">
          {incidents.slice(0, 10).map((incident) => (
            <li key={incident.start}>
              <Badge color={incident.state === "unhealthy" ? "red" : "orange"} variant="soft">{STATE_LABEL[incident.state]}</Badge>{" "}
              {new Date(incident.start).toLocaleString()} to {new Date(incident.end).toLocaleTimeString()}
              {incident.checks.length ? <span className="lw-faint"> · {incident.checks.map(checkName).join(", ")}</span> : null}
            </li>
          ))}
        </ul>
      ) : samples.length ? <p className="lw-secondary lw-note">No incidents in this range.</p> : null}
      <p className="lw-secondary lw-note">Gaps mean no worker was running. Samples are kept for 30 days.</p>
    </div>
  );
}

/** How each AI connection did for this environment's requests over the last day. Nothing probes the providers. */
export function ConnectionHealthTable({ environmentID, environmentName }: { environmentID: string; environmentName: string }) {
  const health = useQuery({
    queryFn: () => {
      const end = clock();
      return connectionHealth(environmentID, new Date(end - 86_400_000).toISOString(), new Date(end).toISOString());
    },
    queryKey: ["usage", "connections", environmentID, "24h"],
    refetchInterval: 5 * 60_000,
    retry: false
  });
  if (health.error) return <ProblemNotice problem={problemFromError(health.error)} />;
  if (!health.data) return <p className="lw-page-status" role="status">Loading connection health…</p>;
  if (!health.data.connections.length) return <p className="lw-secondary lw-note">No attempts in {environmentName} in the last 24 hours.</p>;
  type Row = (typeof health.data.connections)[number];
  const columns: Array<Column<Row>> = [
    { header: "Connection", key: "upstream", render: (row) => <span className="lw-mono lw-mono--sm">{row.upstream}</span> },
    { align: "right", header: "Attempts", key: "attempts", render: (row) => <span className="lw-num">{row.attempts.toLocaleString()}</span> },
    { align: "right", header: "Succeeded", key: "success", render: (row) => { const rate = successRate(row.succeeded, row.failed); return <span className={`lw-num${rate !== undefined && rate < 95 ? " lw-text-warning" : ""}`}>{rate === undefined ? "—" : `${rate}%`}</span>; } },
    { align: "right", header: "429 · 5xx", key: "errors", render: (row) => <span className="lw-num">{row.rate_limited.toLocaleString()} · {row.server_errors.toLocaleString()}</span> },
    { align: "right", header: "Fell back", key: "fallback", render: (row) => <span className="lw-num">{row.fell_back.toLocaleString()}</span> },
    { align: "right", header: "First byte p50 · p95", key: "latency", render: (row) => row.first_byte.samples ? <span className="lw-num">{row.first_byte.p50_ms.toLocaleString()} · {row.first_byte.p95_ms.toLocaleString()} ms</span> : <span className="lw-faint">—</span> },
    { header: "Top failure", key: "failure", render: (row) => row.failures[0] ? <span className="lw-mono lw-mono--sm">{row.failures[0].code} ×{row.failures[0].count}</span> : <span className="lw-faint">None</span> },
    { align: "right", header: "Cost", key: "cost", render: (row) => <span className="lw-num">{formatUsd(row.usage.cost_nano_usd)}</span> }
  ];
  return (
    <div className="lw-stack lw-stack--tight">
      <DataTable caption={`AI connections in ${environmentName}`} columns={columns} rowKey={(row) => row.upstream} rows={health.data.connections} />
      <p className="lw-secondary lw-note">Last 24 hours of attempts in {environmentName}, from what requests recorded. Fell back counts failed attempts that another attempt followed.</p>
    </div>
  );
}

const RUN_BADGE: Readonly<Record<SelfTestRun["state"], { color?: "success" | "red" | "orange"; label: string }>> = {
  canceled: { label: "Canceled" },
  failed: { color: "red", label: "Failed" },
  passed: { color: "success", label: "Passed" },
  queued: { color: "orange", label: "Queued" },
  running: { color: "orange", label: "Running" }
};

/** Recent runs for this environment, newest first. */
export function SelfTestRuns({ environmentID, onOpen, selected }: { environmentID: string; onOpen: (run: SelfTestRun) => void; selected?: string }) {
  const runs = useInfiniteQuery({
    getNextPageParam: (page: SelfTestPage) => (page.page.has_more ? page.page.next_cursor : undefined),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => listSelfTests(environmentID, pageParam),
    queryKey: ["self-tests", environmentID, "runs"],
    retry: false
  });
  const rows = runs.data?.pages.flatMap((page) => page.items) ?? [];
  const columns: Array<Column<SelfTestRun>> = [
    { header: "Run", key: "id", render: (run) => <span className="lw-mono lw-mono--sm">{run.id}</span> },
    { header: "Kind", key: "kind", render: (run) => <span className="lw-note">{run.kind}{run.schedule_id ? " · scheduled" : ""}</span> },
    { header: "Result", key: "state", render: (run) => <Badge color={RUN_BADGE[run.state].color} variant="soft">{RUN_BADGE[run.state].label}</Badge> },
    { header: "Started", key: "created", render: (run) => <span className="lw-secondary">{new Date(run.created_at).toLocaleString()}</span> }
  ];
  if (runs.error) return <ProblemNotice problem={problemFromError(runs.error)} />;
  if (runs.isPending) return <p className="lw-page-status" role="status">Loading runs…</p>;
  if (!rows.length) return <EmptyState icon="selftest" orientation="horizontal" title="No runs yet">Runs appear here once you run a test or a schedule fires.</EmptyState>;
  return (
    <div className="lw-stack lw-stack--tight">
      <DataTable caption="Recent runs" columns={columns} onSelect={onOpen} rowKey={(run) => run.id} rows={rows} selectedKey={selected} />
      {runs.hasNextPage ? <div><Button loading={runs.isFetchingNextPage} onClick={() => void runs.fetchNextPage()} size="sm">Load More</Button></div> : null}
    </div>
  );
}

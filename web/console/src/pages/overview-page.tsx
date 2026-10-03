import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { adminRequest, APITokenPageSchema, queryPath, RequestPageSchema, RevisionSchema } from "../api/admin";
import { problemFromError } from "../api/auth";
import { useSystemHealth } from "../api/health";
import { useConsoleSession } from "../api/session";
import { latestConfigurationRevisionQueryOptions } from "../api/workspace";
import { AnalyticsRouteSearchSchema } from "../app/route-search";
import { useWorkspace } from "../app/workspace-context-value";
import { AdminAccessPanel } from "../components/admin-access-panel";
import { AttentionList, buttonClass, Card, Icon, MetricTile, PageHeader, ProportionBar, RangePicker, StatStrip, VolumeChart } from "../ui";
import {
  buckets,
  CUSTOM_PERIOD_MAX_DAYS,
  formatCount,
  formatMoney,
  iso,
  percent,
  percentChange,
  PERIOD_PRESETS,
  periodOf,
  periodPatch,
  pointChange,
  ratePercent,
  recorded,
  windowLabel
} from "./analytics/usage-model";
import { useUsage } from "./analytics/use-usage";
import { ProblemNotice } from "./control-plane-pages";
import { ATTENTION_GROUPS, attentionItems } from "./overview/attention-model";
import { formatMs } from "./requests/request-format";

function SignedOutOverview() {
  return (
    <div className="access-page">
      <section className="access-intro" aria-labelledby="access-heading">
        <p className="eyebrow">Same-origin administration</p>
        <h1 id="access-heading">Sign in to the control plane.</h1>
        <p className="hero__lede">
          Use an administrator account to operate this gateway. If this is a new
          installation, the one-time bootstrap token can create its first organization
          and owner.
        </p>
        <Link className="secondary-action access-intro__health" to="/system-health">
          Review system health
          <span aria-hidden="true">→</span>
        </Link>

        <dl className="access-safeguards">
          <div>
            <dt>Session boundary</dt>
            <dd>Secure, same-site cookies remain scoped to this gateway.</dd>
          </div>
          <div>
            <dt>Secret handling</dt>
            <dd>Passwords and bootstrap tokens are sent once and never stored here.</dd>
          </div>
          <div>
            <dt>First-owner setup</dt>
            <dd>The bootstrap path closes permanently after its successful use.</dd>
          </div>
        </dl>
      </section>

      <AdminAccessPanel />
    </div>
  );
}

function SessionUnavailableOverview({
  isRefreshing,
  retry
}: {
  isRefreshing: boolean;
  retry: () => void;
}) {
  return (
    <section className="empty-state" aria-labelledby="session-unavailable-heading">
      <p className="eyebrow">Administrator session</p>
      <h1 id="session-unavailable-heading">The console cannot confirm your session.</h1>
      <p>
        Check same-origin routing and gateway availability. Credentials are not needed
        until the session endpoint responds.
      </p>
      <button
        className="primary-action"
        disabled={isRefreshing}
        onClick={retry}
        type="button"
      >
        {isRefreshing ? "Checking session…" : "Try session check again"}
      </button>
    </section>
  );
}

function SessionCheckingOverview() {
  return (
    <section className="empty-state" aria-labelledby="session-checking-heading" role="status">
      <p className="eyebrow">Administrator session</p>
      <h1 id="session-checking-heading">Confirming your console access.</h1>
      <p>The gateway is checking for a secure administrator session.</p>
    </section>
  );
}

function OperatingOverview() {
  const workspace = useWorkspace();
  const { readiness } = useSystemHealth();
  const navigate = useNavigate();
  const environment = workspace.environment;
  const environmentID = environment?.id ?? "";
  const search = AnalyticsRouteSearchSchema.safeParse(workspace.search);
  const analyticsSearch = search.success ? search.data : {};
  const period = periodOf(analyticsSearch);
  const workspaceLinkSearch = { application: workspace.search.application, environment: workspace.search.environment, organization: workspace.search.organization };
  const usage = useUsage({ breakdownLimit: "50", compare: analyticsSearch.compare !== "off", environmentID, period, previousSeries: false });
  const [now] = useState(() => Date.now());
  const configuration = useQuery({
    enabled: Boolean(environment?.active_revision_id),
    queryFn: async () => (await adminRequest(`/admin/v1/environments/${environment?.id}/config`, RevisionSchema)).data,
    queryKey: ["environment", environment?.id ?? "none", "active-configuration", "overview"],
    retry: false
  });
  const latestRevision = useQuery({
    ...latestConfigurationRevisionQueryOptions(environmentID),
    enabled: Boolean(environmentID)
  });
  const recentRequests = useQuery({
    enabled: Boolean(environmentID),
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/requests", { environment_id: environmentID, page_size: "1" }), RequestPageSchema)).data,
    queryKey: ["environment", environmentID || "none", "recent-request", "overview"],
    retry: false
  });
  // Token metadata needs a capability some administrators lack; without it, token expiry simply isn't listed.
  const apiTokens = useQuery({
    queryFn: async () => (await adminRequest("/admin/v1/api-tokens", APITokenPageSchema)).data.items,
    queryKey: ["api-tokens", "overview"],
    retry: false
  });

  const spec = configuration.data?.document.spec;
  const configObject = spec && typeof spec === "object" && !Array.isArray(spec) ? spec as Record<string, unknown> : undefined;
  const configuredCount = (key: string): number => Array.isArray(configObject?.[key]) ? configObject[key].length : 0;
  const setupSteps = [
    { complete: true, label: "Administrator access established", to: "/administrators" as const },
    { complete: Boolean(workspace.application && environment), label: "Application and environment created", to: "/environments" as const },
    { complete: configuredCount("identityProviders") > 0, label: "User authentication configured", to: "/authentication-providers" as const },
    { complete: configuredCount("attestationPolicies") > 0, label: "Client verification configured", to: "/attestation" as const },
    { complete: configuredCount("upstreams") > 0, label: "AI connection added", to: "/upstreams" as const },
    { complete: configuredCount("features") > 0, label: "First feature published", to: "/features" as const },
    { complete: Boolean(recentRequests.data?.items.length), label: "Client request verified", to: "/requests" as const }
  ];
  const completedSteps = setupSteps.filter((step) => step.complete).length;

  const attention = attentionItems({
    apiTokens: apiTokens.data,
    application: workspace.application,
    environment,
    latestRevisionState: latestRevision.data?.items[0]?.state,
    now,
    readiness: readiness.data,
    summary: usage.summary
  });
  const pressing = attention.filter((item) => item.severity !== "info").length;
  const summary = usage.summary;
  const analytics = summary?.analytics;
  const before = usage.previous?.analytics;
  const cost = summary ? recorded(summary.values, "cost_nano_usd") : null;
  const previousCost = usage.previous ? recorded(usage.previous.values, "cost_nano_usd") : undefined;
  const periodName = period.id === "custom" ? "period" : period.id;
  const openAnalytics = (to: "/analytics/usage" | "/analytics/cost" | "/analytics/performance" | "/analytics/reliability") => void navigate({ search: (previous) => previous, to });
  const points = buckets(usage.window, usage.series).map((bucket) => ({ label: bucket.label, title: bucket.title, values: { requests: bucket.values?.logical_requests ?? 0 } }));
  const topFeatures = [...(analytics?.by_feature.items ?? [])].sort((a, b) => b.request_count - a.request_count).slice(0, 5);
  const modelTotal = analytics?.by_model.items.reduce((sum, item) => sum + item.request_count, 0) ?? 0;
  const modelColors = ["var(--accent-primary)", "var(--accent-subtle)", "var(--orange)", "var(--success)", "var(--grey)"];
  const models = [...(analytics?.by_model.items ?? [])].sort((a, b) => b.request_count - a.request_count);

  return (
    <div className="lw-page lw-overview">
      <PageHeader
        actions={<div className="lw-an-actions">
          <RangePicker label="Range" maxDays={CUSTOM_PERIOD_MAX_DAYS} onChange={(next) => workspace.updateSearch(periodPatch(next))} presets={PERIOD_PRESETS} value={period} />
          <Link className={buttonClass()} search={(previous) => previous} to="/route-simulator">Test a Request</Link>
        </div>}
        description={environment && workspace.application
          ? `${workspace.application.display_name} in ${environment.display_name}. ${environment.active_revision_id ? `Revision ${environment.active_revision_id} is live.` : "No configuration is live yet."}`
          : "Choose an application and environment to see how it's doing."}
        title="Overview"
      />
      <div className="lw-body">
        {completedSteps < setupSteps.length ? (
          <Card icon="rocket" meta={`${completedSteps} of ${setupSteps.length} done`} title={`Set up ${workspace.application?.display_name ?? "your application"}${environment ? ` / ${environment.display_name}` : ""}`}>
            <ol className="lw-checklist-steps">
              {setupSteps.map((step) => (
                <li className={step.complete ? "is-done" : undefined} key={step.label}>
                  <Icon label={step.complete ? "Done" : "Not done"} name={step.complete ? "check" : "minus"} />
                  <Link className="lw-link" search={(previous) => previous} to={step.to}>{step.label}</Link>
                </li>
              ))}
            </ol>
          </Card>
        ) : null}

        <Card flush icon="alert" meta={attention.length ? `${pressing} to look at · ${attention.length} in all` : "All clear"} title="Needs attention">
          <AttentionList
            emptyText="Checked just now: configuration, usage, API tokens and gateway readiness look fine."
            groups={ATTENTION_GROUPS}
            items={attention.map((item) => ({
              ...item,
              onAction: () => void navigate({ search: { ...workspaceLinkSearch, ...item.search }, to: item.to })
            }))}
            limit={5}
          />
        </Card>

        {usage.error ? <ProblemNotice problem={problemFromError(usage.error)} /> : null}
        {analytics && summary ? (
          <Card flush>
            <StatStrip>
              <MetricTile color="var(--accent-subtle)" delta={percentChange(analytics.request_count, before?.request_count)} footnote={before ? `vs previous ${periodName}` : "Logical requests"} label="Requests" onClick={() => openAnalytics("/analytics/usage")} value={formatCount(analytics.request_count)} />
              <MetricTile color="var(--destructive)" delta={pointChange(analytics.failure_rate, before?.failure_rate)} deltaUnit=" pts" footnote={`${analytics.failure_rate.numerator.toLocaleString()} failed requests`} higherIsBetter={false} label="Failed" onClick={() => openAnalytics("/analytics/reliability")} value={ratePercent(analytics.failure_rate, 2)} />
              <MetricTile delta={before?.time_to_first_token.samples ? percentChange(analytics.time_to_first_token.p95_ms, before.time_to_first_token.p95_ms) : undefined} footnote={`${analytics.time_to_first_token.samples.toLocaleString()} streaming requests`} higherIsBetter={false} label="p95 first token" onClick={() => openAnalytics("/analytics/performance")} value={analytics.time_to_first_token.samples ? formatMs(analytics.time_to_first_token.p95_ms) : "—"} />
              <MetricTile color="var(--orange)" delta={percentChange(cost, previousCost)} footnote="At your configured prices" higherIsBetter={false} label="Cost" onClick={() => openAnalytics("/analytics/cost")} value={formatMoney(cost)} />
            </StatStrip>
            <VolumeChart
              bars={["requests"]}
              label={`Requests per ${usage.window.interval} (UTC), ${windowLabel(usage.window)}`}
              labels={{ requests: "Requests" }}
              legendFormat={(value) => formatCount(value)}
              partialLast={usage.window.partialLast}
              points={points}
              tickEvery={points.length <= 8 ? 1 : points.length <= 24 ? 3 : points.length <= 31 ? 5 : points.length <= 92 ? 14 : 30}
            />
          </Card>
        ) : usage.isPending ? <p className="lw-page-status" role="status">Loading usage…</p> : null}

        {analytics ? (
          <div className="lw-hgrid lw-hgrid--2">
            <Card flush icon="features" meta={`Requests · ${windowLabel(usage.window)}`} title="Top features">
              {topFeatures.length ? (
                <ul className="lw-rank">
                  {topFeatures.map((item) => (
                    <li key={item.key}>
                      <Link className="lw-link" search={{ ...workspaceLinkSearch, end: iso(usage.window.end), feature: item.key, start: iso(usage.window.start) }} to="/requests">{item.key}</Link>
                      <span className="lw-faint">{formatCount(item.active_users)} active users</span>
                      <strong className="lw-num">{formatCount(item.request_count)}</strong>
                    </li>
                  ))}
                </ul>
              ) : <p className="lw-secondary lw-an-empty">No requests in this range.</p>}
            </Card>
            <Card icon="split" meta="Share of requests that reached a provider" title="Requests by model">
              {modelTotal ? (
                <ProportionBar
                  segments={models.slice(0, 5).map((item, index) => ({ color: modelColors[index] ?? "var(--grey)", display: percent(item.request_count, modelTotal, 0), key: item.key, label: item.key === "legacy_unknown" ? "Before model tracking" : item.key, value: item.request_count }))}
                  showValues
                />
              ) : <p className="lw-secondary lw-note">No requests reached a provider in this range.</p>}
            </Card>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function OverviewPage() {
  const session = useConsoleSession();

  if (session.isPending && !session.data) {
    return <SessionCheckingOverview />;
  }
  if (session.data?.mode === "signed-out") {
    return <SignedOutOverview />;
  }
  if (session.data?.mode !== "configured") {
    return (
      <SessionUnavailableOverview
        isRefreshing={session.isFetching}
        retry={() => void session.refetch()}
      />
    );
  }

  return <OperatingOverview />;
}

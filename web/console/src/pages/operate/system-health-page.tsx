import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";

import { adminRequest, type DoctorReport, DoctorReportSchema, type SupportBundle, SupportBundleSchema, SystemStatusSchema } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { useAdminRefreshTopic } from "../../app/use-admin-refresh";
import { downloadText } from "../../components/download";
import { Badge, Button, buttonClass, Card, ConfirmDialog, Icon, Notice, PageHeader, Properties, Segmented } from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { CopyButton } from "../requests/request-detail";
import { ago, ALERT_CRON, bySeverity, CHECK_INFO, checkName, formatBytes, type HealthCard, needsAttention, overdue, STATE_LABEL, statusSentence } from "./health-model";

const wallClock = (): number => Date.now();

const STATE_ICON = { failed: "x", passed: "check", skipped: "minus", warning: "alert" } as const;

function scoped(previous: Record<string, unknown>) {
  return { application: previous.application as string | undefined, environment: previous.environment as string | undefined, organization: previous.organization as string | undefined };
}

function scrollToCard(card: HealthCard): void {
  document.getElementById(`health-${card}`)?.scrollIntoView?.({ behavior: "smooth", block: "start" });
}

function GatewayCard({ children, id, meta, title, icon }: { children: ReactNode; icon: "server" | "health" | "settings" | "refresh" | "changes" | "key" | "history"; id: HealthCard; meta?: ReactNode; title: string }) {
  return <div className="lw-health-card" id={`health-${id}`}><Card icon={icon} meta={meta} title={title}>{children}</Card></div>;
}

function SupportBundleDialog({ onClose }: { onClose: () => void }) {
  const bundle = useQuery({ queryFn: async () => (await adminRequest("/admin/v1/system/support-bundle", SupportBundleSchema)).data, queryKey: ["system", "support-bundle"], retry: false, staleTime: 0 });
  const data: SupportBundle | undefined = bundle.data;
  return (
    <ConfirmDialog confirmDisabled={!data} confirmLabel="Download Bundle" onCancel={onClose} onConfirm={() => { if (data) { downloadText("latchway-support-bundle.json", `${JSON.stringify(data, null, 2)}\n`, "application/json"); onClose(); } }} size="xl" title="Support bundle">
      <p className="lw-note"><strong>Included:</strong> the overall state and every check, versions, counts, key expiry dates and retention.</p>
      {data ? <p className="lw-note"><strong>Never included:</strong> {data.redaction.excluded.map((item) => <code className="lw-code-inline" key={item}>{item}</code>).reduce<ReactNode[]>((all, item, index) => (index ? [...all, ", ", item] : [item]), [])}.</p> : null}
      <p className="lw-secondary lw-note">Redaction is a structural allowlist: only listed fields are copied, so a new field can&apos;t leak by default.</p>
      {bundle.error ? <ProblemNotice problem={problemFromError(bundle.error)} /> : null}
      {bundle.isPending ? <p role="status">Preparing…</p> : null}
      {data ? <pre className="lw-code-block lw-bundle-preview">{JSON.stringify(data, null, 2)}</pre> : null}
    </ConfirmDialog>
  );
}

function Gateway({ now, report, server }: { now: number; report: DoctorReport; server?: { mutation_ready: boolean; ready: boolean } }) {
  const facts = report.facts;
  const runtime = facts.runtime;
  const database = facts.database;
  const jobs = facts.jobs;
  const configuration = facts.configuration;
  const security = facts.security;
  const retention = facts.retention;
  const poolPercent = Math.round(database.pool_utilization_ppm / 10_000);
  const upToDate = runtime.server_version === runtime.latest_compatible_version;
  const jobRows: Array<[string, string | undefined, number]> = [
    ["Usage rollups", jobs.last_usage_rollup_at, 2 * 3_600_000],
    ["Usage reconciliation", jobs.last_usage_reconciliation_at, 5 * 60_000],
    ["Operational retention", jobs.last_retention_at, 2 * 3_600_000],
    ["Signing key rotation", jobs.last_signing_key_rotation_at, 5 * 60_000],
    ["Sign-in provider keys", jobs.last_external_jwks_refresh_at, 15 * 60_000]
  ];
  const failedJobs = jobs.by_status.filter((entry) => entry.status === "failed" || entry.status === "dead").reduce((total, entry) => total + entry.count, 0);
  return (
    <div className="lw-hgrid lw-hgrid--2">
      <GatewayCard icon="server" id="server" meta={<Badge color={upToDate ? "success" : "orange"} variant="soft">{upToDate ? "Up to date" : `${runtime.latest_compatible_version} available`}</Badge>} title="Server">
        <Properties columns={2} items={[
          { label: "Version", value: runtime.server_version },
          { label: "Commit", value: <span className="lw-mono lw-mono--sm">{runtime.commit.slice(0, 12)}</span> },
          { label: "Built", value: runtime.build_date },
          { label: "Contract · protocols", value: `${runtime.contract_version} · ${runtime.protocol_versions.join(", ")}` },
          { label: "Role", value: runtime.role },
          { label: "Clock offset", value: <span className={Math.abs(runtime.clock_offset_ms) > 1000 ? "lw-text-warning" : undefined}>{runtime.clock_offset_ms} ms</span> },
          ...(server ? [{ label: "Changes allowed", value: server.mutation_ready ? "Yes" : "No (read-only)" }, { label: "Serving traffic", value: server.ready ? "Yes" : "No" }] : [])
        ]} />
      </GatewayCard>
      <GatewayCard icon="health" id="replicas" meta={`Last heartbeat ${ago(facts.replicas.newest_heartbeat_at, now)}`} title="Replicas">
        <div className="lw-stat-row">
          <div><strong>{facts.replicas.fresh_apis}</strong><span>API</span></div>
          <div><strong>{facts.replicas.fresh_workers}</strong><span>Worker</span></div>
          <div className={facts.replicas.stale_replicas ? "is-warn" : undefined}><strong>{facts.replicas.stale_replicas}</strong><span>Stale</span></div>
        </div>
      </GatewayCard>
      <GatewayCard icon="server" id="database" meta={`${database.latency_ms} ms`} title="Database">
        <div className="lw-stack lw-stack--tight">
          <div className="lw-meter" data-warn={poolPercent >= 80 ? "" : undefined}><span style={{ width: `${Math.min(100, poolPercent)}%` }} /></div>
          <span className="lw-note">Connections {database.pool_acquired} of {database.pool_maximum} in use ({poolPercent}%)</span>
          <Properties columns={2} items={[
            { label: "Migrations", value: database.schema_current >= database.schema_available ? `${database.schema_current} of ${database.schema_available} applied` : `${database.schema_available - database.schema_current} pending` },
            { label: "Size", value: formatBytes(database.size_bytes) }
          ]} />
        </div>
      </GatewayCard>
      <GatewayCard icon="refresh" id="jobs" title="Background jobs">
        <table className="lw-mini-table">
          <thead><tr><th>Job</th><th>Last run</th><th /></tr></thead>
          <tbody>{jobRows.map(([name, last, interval]) => { const late = overdue(last, interval, now); return <tr key={name}><td>{name}</td><td>{ago(last, now)}</td><td>{late === undefined ? <span className="lw-faint">Not run yet</span> : late ? <Badge color="orange" variant="soft">Overdue</Badge> : <Badge color="success" variant="soft">On time</Badge>}</td></tr>; })}</tbody>
        </table>
        <p className="lw-note">Settlement backlog: <strong>{jobs.usage_settlement_backlog}</strong>{jobs.usage_settlement_backlog ? " (usage and cost show late; nothing is lost)" : ""} · Failed or dead jobs: <strong>{failedJobs}</strong> · Expired quota reservations: <strong>{facts.expired_quota_reservations}</strong></p>
        <p className="lw-secondary lw-note">On time means within the freshness window the server&apos;s own checks use for that job.</p>
      </GatewayCard>
      <GatewayCard icon="changes" id="configuration" title="Configuration">
        <Properties columns={2} items={[
          { label: "Cache", value: `${configuration.cache.fresh_entries} fresh · ${configuration.cache.stale_entries} stale · ${configuration.cache.refreshes_in_flight} refreshing` },
          { label: "Newest load", value: ago(configuration.cache.newest_loaded_at, now) },
          { label: "Live environments", value: `${configuration.active_configurations} of ${configuration.active_environments}` },
          { label: "Drafts · invalid", value: `${configuration.draft_revisions} · ${configuration.invalid_revisions}` }
        ]} />
        <Link className="lw-link lw-note" search={scoped} to="/configuration-revisions">Open History</Link>
      </GatewayCard>
      <GatewayCard icon="key" id="keys" title="Security & keys">
        <Properties columns={2} items={[
          { label: "Signing keys", value: `${security.active_signing_keys} active · ${security.pending_signing_keys} next · ${security.retiring_signing_keys} retiring` },
          { label: "Active key expires", value: security.signing_key_expires_at ? new Date(security.signing_key_expires_at).toLocaleDateString() : "—" },
          { label: "Sign-in providers", value: `${security.identity_providers} · ${security.stale_identity_provider_jwks} with stale keys` },
          { label: "Secrets that decrypt", value: security.active_secret_records },
          { label: "App Attest credentials", value: `${security.apple_verification.resolved_credential_records} of ${security.apple_verification.credential_backed_selections} resolve` },
          { label: "Play Integrity credentials", value: `${security.google_verification.resolved_credential_records} of ${security.google_verification.credential_backed_selections} resolve` }
        ]} />
        <p className="lw-secondary lw-note">Key material never appears here.</p>
      </GatewayCard>
      <GatewayCard icon="history" id="retention" title="Retention">
        <Properties columns={2} items={[
          { label: "Oldest request", value: retention.oldest_request_at ? new Date(retention.oldest_request_at).toLocaleDateString() : "None" },
          { label: "Oldest usage", value: retention.oldest_usage_at ? new Date(retention.oldest_usage_at).toLocaleDateString() : "None" },
          { label: "Oldest audit event", value: retention.oldest_audit_at ? new Date(retention.oldest_audit_at).toLocaleDateString() : "None" },
          { label: "Console sessions kept", value: `${retention.admin_session_retention_hours} h` },
          { label: "Job history kept", value: `${retention.job_history_retention_hours} h` }
        ]} />
      </GatewayCard>
    </div>
  );
}

function HealthView() {
  const [now, setNow] = useState(wallClock);
  const [filter, setFilter] = useState<"open" | "all">("open");
  const [bundle, setBundle] = useState(false);
  const doctor = useQuery({ queryFn: async () => (await adminRequest("/admin/v1/system/doctor", DoctorReportSchema)).data, queryKey: ["system", "doctor"], refetchInterval: 30_000, retry: false });
  const status = useQuery({ queryFn: async () => (await adminRequest("/admin/v1/system", SystemStatusSchema)).data, queryKey: ["system", "status"], retry: false });
  const report = doctor.data;
  const refresh = async () => { await Promise.all([doctor.refetch(), status.refetch()]); setNow(wallClock()); };
  useAdminRefreshTopic("health", refresh);
  const attention = report ? needsAttention(report) : [];
  const checks = report ? bySeverity(report.checks).filter((check) => filter === "all" || check.state !== "passed") : [];
  return (
    <div className="lw-page">
      <PageHeader
        actions={<div className="lw-row">
          <CopyButton className={buttonClass()} label="Copy CLI" value={"latchway status --output json\n# on the server host:\nlatchway doctor --output json"}>Copy CLI</CopyButton>
          <Button onClick={() => setBundle(true)}>Support Bundle</Button>
          <Button loading={doctor.isFetching} onClick={() => void refresh()} variant="primary">Check Again</Button>
        </div>}
        description="Whether Latchway itself is OK, from the server's own self-check. Every application on this server shares it."
        title="System Health"
      />
      <div className="lw-body lw-stack">
        {doctor.error ? <ProblemNotice problem={problemFromError(doctor.error)} /> : null}
        {report ? (
          <div className={`lw-health-status lw-health-status--${report.overall_state}`} role="status">
            <span className="lw-health-status__dot" />
            <div>
              <strong>{doctor.isFetching ? "Checking…" : STATE_LABEL[report.overall_state]}</strong>
              <span>{statusSentence(report)}{report.overall_state !== "unhealthy" ? " Requests are still being served." : ""}</span>
              <span className="lw-faint lw-note">Checked {ago(report.generated_at, now)} · refreshes every 30 s</span>
            </div>
          </div>
        ) : doctor.isPending ? <p role="status">Running the server&apos;s self-check…</p> : null}
        {attention.length ? (
          <Card icon="alert" meta={`${attention.length}`} title="Needs attention">
            <ul className="lw-issues">
              {attention.map((check) => {
                const info = CHECK_INFO[check.id];
                return (
                  <li className={`lw-issue lw-issue--${check.state === "failed" ? "error" : "warning"}`} key={check.id}>
                    <Icon name="alert" size={16} />
                    <div className="lw-issue__text">
                      <strong>{checkName(check.id)}</strong>
                      <span>{check.summary}</span>
                      {check.remediation ? <span><strong>What to do:</strong> {check.remediation}</span> : null}
                      {info?.why ? <span className="lw-faint">{info.why}</span> : null}
                      <code>{check.id}</code>
                    </div>
                    {info?.link ? <Link className={buttonClass({ size: "sm" })} search={scoped} to={info.link.to}>{info.link.label}</Link> : info?.card ? <Button onClick={() => scrollToCard(info.card as HealthCard)} size="sm">See {info.card === "keys" ? "Keys" : info.card === "jobs" ? "Jobs" : info.card.charAt(0).toUpperCase() + info.card.slice(1)}</Button> : null}
                  </li>
                );
              })}
            </ul>
          </Card>
        ) : null}
        {report ? <><h2 className="lw-section-title">Gateway <span className="lw-faint lw-note">From the server&apos;s self-check</span></h2><Gateway now={now} report={report} server={status.data} /></> : null}
        <Card icon="connections" title="AI providers">
          <p className="lw-note">Latchway doesn&apos;t ping providers. Their health comes from the attempts your requests made: see errors, timeouts and latency per model on <Link className="lw-link" search={scoped} to="/analytics/reliability">Analytics › Reliability</Link>{report?.checks.some((check) => check.id === "ai_connection_health") ? <>, and the server&apos;s <code className="lw-code-inline">ai_connection_health</code> check below</> : null}.</p>
        </Card>
        {report ? (
          <Card actions={<Segmented items={[{ id: "open", label: "Not passed" }, { id: "all", label: "All" }]} label="Checks" onChange={setFilter} value={filter} />} icon="check" meta={`${report.checks.length}`} title="All checks">
            {checks.length ? (
              <ul className="lw-issues">
                {checks.map((check) => (
                  <li className={`lw-issue lw-issue--${check.state === "failed" ? "error" : check.state === "warning" ? "warning" : "ok"}`} key={check.id}>
                    <Icon name={STATE_ICON[check.state]} size={16} />
                    <div className="lw-issue__text"><strong>{checkName(check.id)} <span className="lw-faint lw-note">{check.state}</span></strong><span>{check.summary}</span><code>{check.id}</code></div>
                  </li>
                ))}
              </ul>
            ) : <p className="lw-secondary lw-note">Every check passed.</p>}
          </Card>
        ) : null}
        <Card icon="bell" title="Get alerted">
          <p className="lw-note">Latchway sends no notifications. Run a check on a schedule and alert from your own tooling:</p>
          <pre className="lw-code-block">{ALERT_CRON}</pre>
          <div className="lw-row"><CopyButton className={buttonClass({ size: "sm" })} label="Copy cron line" value={ALERT_CRON}>Copy</CopyButton></div>
        </Card>
        <Notice tone="info">Health history isn&apos;t kept: each report is a snapshot of now.</Notice>
      </div>
      {bundle ? <SupportBundleDialog onClose={() => setBundle(false)} /> : null}
    </div>
  );
}

/** Operate → System Health. */
export function SystemHealthPage() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <HealthView />;
}

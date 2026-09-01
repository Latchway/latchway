import { useState } from "react";

import {
  adminRequest,
  DoctorReportSchema,
  SupportBundleSchema,
  type DoctorReport
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";

function checkState(report: DoctorReport, id: string): string {
  return report.checks.find((check) => check.id === id)?.state ?? "unavailable";
}

export function SystemDoctorPanel() {
  const session = useConsoleSession();
  const [report, setReport] = useState<DoctorReport>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState<"run" | "copy" | "download">();
  const [notice, setNotice] = useState<string>();

  async function run(): Promise<DoctorReport | undefined> {
    if (session.data?.mode !== "configured") return undefined;
    setBusy("run"); setProblem(undefined); setNotice(undefined);
    try {
      const next = (await adminRequest("/admin/v1/system/doctor", DoctorReportSchema)).data;
      setReport(next);
      return next;
    } catch (error) {
      setProblem(problemFromError(error));
      return undefined;
    } finally { setBusy(undefined); }
  }

  async function copy(): Promise<void> {
    const current = report ?? await run();
    if (!current) return;
    setBusy("copy"); setNotice(undefined);
    try {
      await navigator.clipboard.writeText(JSON.stringify(current, null, 2));
      setNotice("Redaction-safe diagnostics copied.");
    } catch {
      setProblem({ code: "clipboard_unavailable", detail: "The browser did not allow diagnostics to be copied.", retryable: true, status: 0, title: "Copy unavailable" });
    } finally { setBusy(undefined); }
  }

  async function download(): Promise<void> {
    setBusy("download"); setProblem(undefined); setNotice(undefined);
    try {
      const bundle = (await adminRequest("/admin/v1/system/support-bundle", SupportBundleSchema)).data;
      const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2) + "\n"], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url; link.download = "latchway-support-bundle.json"; link.click();
      URL.revokeObjectURL(url);
      setReport(bundle.report); setNotice("Redacted support bundle downloaded.");
    } catch (error) { setProblem(problemFromError(error)); }
    finally { setBusy(undefined); }
  }

  return <section className="detail-card" aria-labelledby="doctor-heading">
    <div className="detail-card__heading"><div><p className="eyebrow">Canonical doctor</p><h2 id="doctor-heading">Deployment diagnostics</h2></div><div className="inline-actions">
      <button className="secondary-action" disabled={Boolean(busy)} onClick={() => void run()} type="button">{busy === "run" ? "Running…" : "Run checks"}</button>
      <button className="secondary-action" disabled={Boolean(busy)} onClick={() => void copy()} type="button">Copy results</button>
      <button className="secondary-action" disabled={Boolean(busy)} onClick={() => void download()} type="button">Download redacted support bundle</button>
    </div></div>
    {problem ? <p className="control-notice control-notice--error" role="alert">{problem.detail}</p> : null}
    {notice ? <p className="control-notice" role="status">{notice}</p> : null}
    {report ? <>
      <div className={`health-summary health-summary--${report.overall_state === "healthy" ? "available" : report.overall_state === "degraded" ? "degraded" : "unavailable"}`} role="status"><span className="health-summary__indicator" aria-hidden="true" /><span><strong>{report.overall_state}</strong><span>Generated {new Date(report.generated_at).toLocaleString()} · schema {report.facts.database.schema_current}/{report.facts.database.schema_available}</span></span></div>
      <div className="endpoint-grid">{report.checks.map((check) => <article className="endpoint-card" key={check.id}><div className="endpoint-card__heading"><h3>{check.id.replaceAll("_", " ")}</h3><span className={`state-badge state-badge--${check.state === "passed" ? "available" : check.state === "failed" ? "unavailable" : "degraded"}`}><span className="state-badge__dot" aria-hidden="true" />{check.state}</span></div><p>{check.summary}</p>{check.remediation ? <p><strong>Remediation:</strong> {check.remediation}</p> : null}</article>)}</div>
      <dl className="system-status-grid">
        <div><dt>Gateway API</dt><dd>{report.overall_state} · {report.facts.runtime.role}</dd></div>
        <div><dt>PostgreSQL</dt><dd>{checkState(report, "database_connectivity")} · {report.facts.database.latency_ms} ms</dd></div>
        <div><dt>Background workers</dt><dd>{checkState(report, "worker_heartbeat")} · {report.facts.replicas.fresh_workers} fresh</dd></div>
        <div><dt>Configuration</dt><dd>{report.facts.configuration.active_configurations} active · rev {report.facts.configuration.highest_revision_number}</dd></div>
        <div><dt>Configuration cache</dt><dd>{checkState(report, "configuration_cache_state")} · {report.facts.configuration.cache.fresh_entries}/{report.facts.configuration.cache.entries} fresh</dd></div>
        <div><dt>Session signing keys</dt><dd>{checkState(report, "signing_key_rotation")} · {report.facts.security.active_signing_keys} active</dd></div>
        <div><dt>JWKS refresh</dt><dd>{checkState(report, "external_jwks_reachability")}</dd></div>
        <div><dt>Apple verification</dt><dd>{checkState(report, "apple_verification_dependencies")} · {report.facts.security.apple_verification.configured_selections} configured</dd></div>
        <div><dt>Google verification</dt><dd>{checkState(report, "google_verification_dependencies")} · {report.facts.security.google_verification.configured_selections} configured</dd></div>
        <div><dt>Usage settlement backlog</dt><dd>{report.facts.jobs.usage_settlement_backlog}</dd></div>
        <div><dt>Storage retention</dt><dd>{checkState(report, "storage_retention")}</dd></div>
        <div><dt>Current version</dt><dd>{report.facts.runtime.server_version}</dd></div>
        <div><dt>Latest compatible version</dt><dd>{report.facts.runtime.latest_compatible_version} · embedded</dd></div>
        <div><dt>Pool utilization</dt><dd>{(report.facts.database.pool_utilization_ppm / 10_000).toFixed(1)}%</dd></div>
        <div><dt>Expired reservations</dt><dd>{report.facts.expired_quota_reservations}</dd></div>
      </dl>
    </> : <p>Run checks to inspect migrations, active revisions, key availability, job backlog, worker replicas, JWKS state, clock skew, pool pressure, and quota cleanup without reading request content or credentials.</p>}
  </section>;
}

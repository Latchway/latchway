import type { DoctorReport } from "../../api/admin";
import type { ConsoleRoute } from "../../app/navigation";

type Check = DoctorReport["checks"][number];

export type HealthCard = "server" | "replicas" | "database" | "jobs" | "configuration" | "keys" | "retention";

interface CheckInfo {
  /** A gateway card to scroll to, when the fix is on this page. */
  card?: HealthCard;
  /** A page that fixes it. */
  link?: { label: string; to: ConsoleRoute };
  name: string;
  why: string;
}

/** Plain names and deep links for the server's doctor checks (internal/diagnostics). */
export const CHECK_INFO: Readonly<Record<string, CheckInfo>> = {
  active_configuration: { link: { label: "Open Changes", to: "/changes" }, name: "Live configuration", why: "An environment without a live configuration refuses every request." },
  ai_connection_health: { link: { label: "Open Reliability", to: "/analytics/reliability" }, name: "AI connections", why: "Requests fail or slow down when a provider is degraded." },
  apple_verification_dependencies: { link: { label: "Open App verification", to: "/attestation" }, name: "Apple verification", why: "iOS apps can't prove they're genuine without it." },
  clock_skew: { card: "server", name: "Server clock", why: "Tokens and attestation depend on accurate time." },
  connection_pool_saturation: { card: "database", name: "Database connections", why: "A full pool makes requests wait or fail." },
  database_connectivity: { card: "database", name: "Database", why: "Nothing works without PostgreSQL." },
  database_storage_visibility: { card: "database", name: "Database size", why: "Running out of storage stops writes." },
  expired_quota_reservations: { card: "jobs", name: "Quota reservations", why: "Unsettled reservations hold quota users should have back." },
  external_jwks_reachability: { link: { label: "Open User sign-in", to: "/authentication-providers" }, name: "Sign-in provider keys", why: "Users can't sign in if their provider's keys can't be fetched." },
  google_verification_dependencies: { link: { label: "Open App verification", to: "/attestation" }, name: "Google verification", why: "Android apps can't prove they're genuine without it." },
  job_backlog: { card: "jobs", name: "Background jobs", why: "Backlogged jobs delay usage, retention and key rotation." },
  master_key_availability: { card: "keys", name: "Master key", why: "Without it, stored secrets can't be decrypted." },
  migration_status: { card: "database", name: "Database migrations", why: "Pending migrations block configuration changes." },
  quota_completion_pool_saturation: { card: "jobs", name: "Quota completion", why: "Slow completion delays when usage is counted." },
  storage_retention: { card: "retention", name: "Operational retention", why: "Old operational records aren't being cleaned up." },
  replica_coverage: { card: "replicas", name: "Replicas", why: "Missing API or worker replicas reduce capacity." },
  retention_job_freshness: { card: "jobs", name: "Retention job", why: "Old operational records aren't being cleaned up." },
  sdk_compatibility: { card: "server", name: "Client SDK compatibility", why: "Older SDKs may be refused." },
  signing_key_availability: { card: "keys", name: "Session signing keys", why: "Apps can't get sessions without a signing key." },
  signing_key_rotation: { card: "keys", name: "Signing key rotation", why: "Keys that aren't rotated expire." },
  usage_reconciliation_freshness: { card: "jobs", name: "Usage reconciliation", why: "Usage and cost show late; nothing is lost." },
  usage_rollup_freshness: { card: "jobs", name: "Usage rollups", why: "Analytics show late; nothing is lost." },
  usage_settlement_backlog: { card: "jobs", name: "Usage settlement", why: "Usage and cost show late; nothing is lost." },
  worker_heartbeat: { card: "replicas", name: "Background workers", why: "Without workers, jobs stop running." }
};

export function checkName(id: string): string {
  return CHECK_INFO[id]?.name ?? id.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

const RANK: Readonly<Record<Check["state"], number>> = { failed: 0, passed: 3, skipped: 2, warning: 1 };

export function bySeverity(checks: readonly Check[]): Check[] {
  return [...checks].sort((left, right) => RANK[left.state] - RANK[right.state] || left.id.localeCompare(right.id));
}

export function needsAttention(report: DoctorReport): Check[] {
  return bySeverity(report.checks.filter((check) => check.state === "failed" || check.state === "warning"));
}

export const STATE_LABEL: Readonly<Record<DoctorReport["overall_state"], string>> = { degraded: "Degraded", healthy: "Healthy", unhealthy: "Unhealthy" };

/** "2 things need attention: Sign-in provider keys and Usage settlement." */
export function statusSentence(report: DoctorReport): string {
  const attention = needsAttention(report);
  if (!attention.length) return "Every check passed.";
  const names = attention.slice(0, 2).map((check) => checkName(check.id));
  const rest = attention.length - names.length;
  return `${attention.length} ${attention.length === 1 ? "thing needs" : "things need"} attention: ${names.join(" and ")}${rest > 0 ? ` and ${rest} more` : ""}.`;
}

/** Whether a job's last success is outside the freshness window the server's own doctor uses for it. */
export function overdue(lastRun: string | undefined, maximumAgeMs: number, now: number): boolean | undefined {
  if (!lastRun) return undefined;
  return now - Date.parse(lastRun) > maximumAgeMs;
}

export function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export function ago(instant: string | undefined, now: number): string {
  if (!instant) return "never";
  const seconds = Math.max(0, Math.round((now - Date.parse(instant)) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86_400)} days ago`;
}

export const ALERT_CRON = `# Every 5 minutes: alert unless the gateway reports ready.
# Use a View-only API token (inspect_users) in LATCHWAY_ADMIN_API_TOKEN.
*/5 * * * * state=$(latchway status --output json | jq -r '.ready') && [ "$state" = "true" ] || your-alert-command "Latchway is not ready"`;

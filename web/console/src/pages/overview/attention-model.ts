import type { APITokenMetadata, UsageSummary } from "../../api/admin";
import type { HealthResult } from "../../api/health";
import type { ApplicationResource, EnvironmentResource } from "../../api/resources";
import type { ConsoleRoute } from "../../app/navigation";
import type { Severity } from "../../ui";
import { recorded } from "../analytics/usage-model";

export type AttentionGroup = "environment" | "organization" | "gateway";

export const ATTENTION_GROUPS: ReadonlyArray<{ id: AttentionGroup; label: string }> = [
  { id: "environment", label: "This environment" },
  { id: "organization", label: "Organization" },
  { id: "gateway", label: "Gateway" }
];

/** One thing to look at, with the page that fixes it. Every item comes from a server record; none are dismissable. */
export interface AttentionSource {
  actionLabel: string;
  detail: string;
  group: AttentionGroup;
  id: string;
  search?: Record<string, string>;
  severity: Severity;
  title: string;
  to: ConsoleRoute;
}

export interface AttentionInputs {
  application?: ApplicationResource;
  apiTokens?: readonly APITokenMetadata[];
  environment?: EnvironmentResource;
  latestRevisionState?: string;
  now: number;
  readiness?: HealthResult;
  summary?: UsageSummary;
}

const FAILURE_RATE_WARNING_PPM = 50_000;
const FAILURE_RATE_MIN_REQUESTS = 20;
const TOKEN_EXPIRY_WINDOW_MS = 14 * 86_400_000;

export function attentionItems({ apiTokens, application, environment, latestRevisionState, now, readiness, summary }: AttentionInputs): AttentionSource[] {
  const items: AttentionSource[] = [];
  const scope = application && environment ? `${application.display_name} · ${environment.display_name}` : "This environment";

  if (application?.status === "disabled" || environment?.status === "disabled") {
    items.push({ actionLabel: "Open Applications", detail: "Traffic and configuration changes are blocked until both the application and environment are active.", group: "environment", id: "scope-disabled", severity: "critical", title: `${scope} is disabled`, to: "/applications" });
  }
  if (environment && !environment.active_revision_id) {
    items.push({ actionLabel: "Continue Setup", detail: `${scope} can't serve feature traffic until a configuration is active.`, group: "environment", id: "no-active-configuration", severity: "warning", title: "No active configuration", to: "/setup" });
  }
  if (latestRevisionState === "invalid") {
    items.push({ actionLabel: "Open Changes", detail: "The newest revision has problems to fix before it can be published.", group: "environment", id: "draft-invalid", severity: "warning", title: "A draft has problems", to: "/configuration-revisions" });
  } else if (latestRevisionState === "draft" || latestRevisionState === "valid") {
    items.push({ actionLabel: "Open Changes", detail: latestRevisionState === "valid" ? "The newest revision is checked and ready to publish." : "The newest revision hasn't been validated yet.", group: "environment", id: "draft-pending", severity: "info", title: "Unpublished changes", to: "/configuration-revisions" });
  }
  if (summary) {
    const unpriced = summary.analytics.by_model.items.filter((item) => item.request_count > 0 && recorded(item.values, "cost_nano_usd") === null);
    if (unpriced.length) {
      items.push({ actionLabel: "Set Prices", detail: `${unpriced.map((item) => item.key).join(", ")} recorded usage with no cost, so cost totals are lower than the provider's bill.`, group: "environment", id: "models-unpriced", severity: "warning", title: unpriced.length === 1 ? "1 model has no recorded cost" : `${unpriced.length} models have no recorded cost`, to: "/models-pricing" });
    }
    const failures = summary.analytics.failure_rate;
    if (failures.denominator >= FAILURE_RATE_MIN_REQUESTS && failures.parts_per_million >= FAILURE_RATE_WARNING_PPM) {
      items.push({ actionLabel: "See Failed Requests", detail: `${failures.numerator.toLocaleString()} of ${failures.denominator.toLocaleString()} requests failed in this range after every allowed fallback.`, group: "environment", id: "failure-rate", search: { status: "failed" }, severity: "warning", title: `${(failures.parts_per_million / 10_000).toLocaleString(undefined, { maximumFractionDigits: 1 })}% of requests failed`, to: "/requests" });
    }
  }
  for (const token of apiTokens ?? []) {
    if (token.revoked || !token.expires_at) continue;
    const remaining = Date.parse(token.expires_at) - now;
    if (remaining < 0 || remaining > TOKEN_EXPIRY_WINDOW_MS) continue;
    const days = Math.ceil(remaining / 86_400_000);
    items.push({ actionLabel: "Open API Tokens", detail: "Automation using it stops when it expires. Create a replacement before then.", group: "organization", id: `token-${token.id}`, severity: days <= 1 ? "critical" : "warning", title: `API token "${token.name}" expires ${days <= 1 ? "within a day" : `in ${days} days`}`, to: "/api-tokens" });
  }
  if (readiness && readiness.state !== "available") {
    const failing = readiness.checks.filter((check) => check.state !== "available");
    if (failing.length) {
      for (const check of failing) {
        items.push({ actionLabel: "Open System Health", detail: check.detail ?? readiness.summary, group: "gateway", id: `check-${check.name}`, severity: check.state === "unavailable" ? "critical" : "warning", title: `${check.name} is ${check.state}`, to: "/system-health" });
      }
    } else {
      items.push({ actionLabel: "Open System Health", detail: readiness.summary, group: "gateway", id: "readiness", severity: readiness.state === "unavailable" ? "critical" : "warning", title: `The gateway is ${readiness.state}`, to: "/system-health" });
    }
  }
  return items;
}

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { adminRequest, queryPath, RequestPageSchema, RevisionSchema } from "../api/admin";
import { overallHealthState, useSystemHealth } from "../api/health";
import { useConsoleSession } from "../api/session";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { AdminAccessPanel } from "../components/admin-access-panel";

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
  const { liveness, readiness } = useSystemHealth();
  const workspace = useOptionalWorkspace();
  const environment = workspace?.environment;
  const state = overallHealthState(liveness.data, readiness.data);
  const configuration = useQuery({
    enabled: Boolean(environment?.id),
    queryFn: async () => (await adminRequest(`/admin/v1/environments/${environment?.id}/config`, RevisionSchema)).data,
    queryKey: ["environment", environment?.id ?? "none", "active-configuration", "overview"],
    retry: false
  });
  const recentRequests = useQuery({
    enabled: Boolean(environment?.id),
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/requests", { environment_id: environment?.id, page_size: "1" }), RequestPageSchema)).data,
    queryKey: ["environment", environment?.id ?? "none", "recent-request", "overview"],
    retry: false
  });
  const spec = configuration.data?.document.spec;
  const configObject = spec && typeof spec === "object" && !Array.isArray(spec) ? spec as Record<string, unknown> : undefined;
  const configuredCount = (key: string): number => Array.isArray(configObject?.[key]) ? configObject[key].length : 0;
  const setupSteps = [
    { complete: true, label: "Administrator access established", to: "/administrators" as const },
    { complete: Boolean(workspace?.application && environment), label: "Application and environment created", to: "/environments" as const },
    { complete: configuredCount("identityProviders") > 0, label: "User authentication configured", to: "/authentication-providers" as const },
    { complete: configuredCount("attestationPolicies") > 0, label: "Client verification configured", to: "/attestation" as const },
    { complete: configuredCount("upstreams") > 0, label: "AI connection added", to: "/upstreams" as const },
    { complete: configuredCount("features") > 0, label: "First feature published", to: "/features" as const },
    { complete: Boolean(recentRequests.data?.items.length), label: "Client request verified", to: "/requests" as const }
  ];
  const completedSteps = setupSteps.filter((step) => step.complete).length;
  const heading =
    state === "available"
      ? "The gateway is ready for control-plane work."
      : state === "loading"
        ? "Confirming the gateway operating posture."
        : "The gateway needs attention before configuration changes.";

  return (
    <>
      <section className="hero" aria-labelledby="overview-heading">
        <div className="hero__copy">
          <p className="eyebrow">Gateway overview</p>
          <h1 id="overview-heading">{heading}</h1>
          <p className="hero__lede">
            Latchway keeps upstream AI credentials behind an authenticated,
            installation-bound policy boundary. Begin with runtime health before
            changing application configuration.
          </p>
          <Link className="primary-action" to="/system-health">
            Inspect runtime checks
            <span aria-hidden="true">→</span>
          </Link>
        </div>
        <div className={`posture-card posture-card--${state}`}>
          <p className="posture-card__label">Operating posture</p>
          <p className="posture-card__value">
            {state === "available"
              ? "Ready"
              : state === "loading"
                ? "Checking"
                : state === "degraded"
                  ? "Degraded"
                  : "Unavailable"}
          </p>
          <dl className="posture-card__metrics">
            <div>
              <dt>Process</dt>
              <dd>{liveness.data?.state ?? "checking"}</dd>
            </div>
            <div>
              <dt>Dependencies</dt>
              <dd>{readiness.data?.state ?? "checking"}</dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="action-center" aria-labelledby="needs-attention-heading">
        <div className="detail-card__heading"><div><p className="eyebrow">Action center</p><h2 id="needs-attention-heading">Needs attention</h2></div>{environment ? <span className={`environment-badge environment-badge--${environment.kind}`}>{environment.kind === "production" ? "Production" : environment.kind}</span> : null}</div>
        <div className="attention-list">{!workspace?.application || !environment ? <article><span aria-hidden="true">!</span><div><strong>Create an application environment</strong><p>The console will not open task workflows without an explicit server-owned environment.</p></div><Link search={(previous) => previous} to="/setup">Start setup</Link></article> : null}{environment && !environment.active_revision_id ? <article><span aria-hidden="true">!</span><div><strong>No active configuration</strong><p>{workspace.application?.display_name} / {environment.display_name} cannot serve feature traffic yet.</p></div><Link search={(previous) => previous} to="/setup">Continue setup</Link></article> : null}{state !== "available" ? <article><span aria-hidden="true">!</span><div><strong>Gateway health needs review</strong><p>Inspect readiness before publishing configuration.</p></div><Link search={(previous) => previous} to="/system-health">Investigate</Link></article> : null}{workspace?.application && environment?.active_revision_id && state === "available" && completedSteps === setupSteps.length ? <article className="attention-list__healthy"><span aria-hidden="true">✓</span><div><strong>No immediate setup blockers</strong><p>The selected environment has active configuration and a verified request.</p></div><Link search={(previous) => previous} to="/requests">Inspect requests</Link></article> : null}</div>
      </section>

      <section className="setup-checklist" aria-labelledby="setup-checklist-heading">
        <div><p className="eyebrow">First-run setup</p><h2 id="setup-checklist-heading">Set up {workspace?.application?.display_name ?? "your application"}{environment ? ` / ${environment.display_name}` : ""}</h2><p>{completedSteps} of {setupSteps.length} complete. Each step uses the canonical Admin API and remains resumable.</p></div><ol>{setupSteps.map((step) => <li className={step.complete ? "setup-checklist__complete" : ""} key={step.label}><span aria-hidden="true">{step.complete ? "✓" : "○"}</span><Link search={(previous) => previous} to={step.to}>{step.label}</Link></li>)}</ol>
      </section>
    </>
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

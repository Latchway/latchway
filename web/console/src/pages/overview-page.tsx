import { Link } from "@tanstack/react-router";

import { overallHealthState, useSystemHealth } from "../api/health";
import { useConsoleSession } from "../api/session";
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
  const state = overallHealthState(liveness.data, readiness.data);
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

      <section className="principles-grid" aria-label="Latchway operating model">
        <article className="principle-card">
          <span className="principle-card__index">01</span>
          <h2>Feature-first routing</h2>
          <p>Client-visible features map policy and models without exposing upstreams.</p>
        </article>
        <article className="principle-card">
          <span className="principle-card__index">02</span>
          <h2>Immutable revisions</h2>
          <p>Validated configuration revisions activate atomically and remain reversible.</p>
        </article>
        <article className="principle-card">
          <span className="principle-card__index">03</span>
          <h2>Evidence before traffic</h2>
          <p>Identity, attestation, DPoP, and limits are evaluated before proxy dispatch.</p>
        </article>
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

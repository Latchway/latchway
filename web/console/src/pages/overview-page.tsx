import { Link } from "@tanstack/react-router";

import { overallHealthState, useSystemHealth } from "../api/health";
import { useConsoleSession } from "../api/session";

function FirstRunOverview() {
  const { liveness, readiness } = useSystemHealth();
  const processOnline = liveness.data?.state === "available";
  const runtimeReady = readiness.data?.state === "available";

  return (
    <>
      <section className="hero hero--setup" aria-labelledby="setup-heading">
        <div className="hero__copy">
          <p className="eyebrow">Secure bootstrap</p>
          <h1 id="setup-heading">Create the trust boundary before traffic arrives.</h1>
          <p className="hero__lede">
            This installation has no administrative owner yet. Verify the runtime,
            consume the one-time bootstrap token, then configure applications through
            the canonical Admin API.
          </p>
          <Link className="primary-action" to="/system-health">
            Review system health
            <span aria-hidden="true">→</span>
          </Link>
        </div>
        <div className="setup-sequence" aria-label="Initial setup sequence">
          <div className={`setup-step ${processOnline ? "setup-step--complete" : ""}`}>
            <span className="setup-step__number">01</span>
            <span>
              <strong>Verify process</strong>
              <span>{processOnline ? "Liveness confirmed" : "Waiting for liveness"}</span>
            </span>
          </div>
          <div className={`setup-step ${runtimeReady ? "setup-step--complete" : ""}`}>
            <span className="setup-step__number">02</span>
            <span>
              <strong>Verify dependencies</strong>
              <span>{runtimeReady ? "Readiness confirmed" : "Review readiness checks"}</span>
            </span>
          </div>
          <div className="setup-step setup-step--current">
            <span className="setup-step__number">03</span>
            <span>
              <strong>Create first owner</strong>
              <span>Requires the one-time bootstrap token</span>
            </span>
          </div>
        </div>
      </section>

      <section className="principles-grid" aria-label="Bootstrap safeguards">
        <article className="principle-card">
          <span className="principle-card__index">A</span>
          <h2>Single use by design</h2>
          <p>The bootstrap path closes permanently after the first owner is created.</p>
        </article>
        <article className="principle-card">
          <span className="principle-card__index">B</span>
          <h2>Same control plane</h2>
          <p>The console and CLI will use the same audited administrative API.</p>
        </article>
        <article className="principle-card">
          <span className="principle-card__index">C</span>
          <h2>No provider keys here</h2>
          <p>Credentials are created as write-only secrets and are never returned.</p>
        </article>
      </section>
    </>
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

  if (session.data?.mode === "setup-required") {
    return <FirstRunOverview />;
  }

  return <OperatingOverview />;
}

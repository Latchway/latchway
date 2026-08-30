import { EndpointCard } from "../components/endpoint-card";
import { overallHealthState, useSystemHealth } from "../api/health";
import { SystemStatusPanel } from "../components/system-status-panel";

export function SystemHealthPage() {
  const { liveness, readiness } = useSystemHealth();
  const overallState = overallHealthState(liveness.data, readiness.data);
  const isRefreshing = liveness.isFetching || readiness.isFetching;

  async function refresh(): Promise<void> {
    await Promise.all([liveness.refetch(), readiness.refetch()]);
  }

  return (
    <div className="health-page">
      <section className="page-heading" aria-labelledby="health-heading">
        <div>
          <p className="eyebrow">Operations</p>
          <h1 id="health-heading">System health</h1>
          <p>
            Live status from the gateway’s canonical process and dependency probes.
            Results refresh every fifteen seconds while this page is visible.
          </p>
        </div>
        <button
          className="secondary-action"
          disabled={isRefreshing}
          onClick={() => void refresh()}
          type="button"
        >
          <span className="refresh-icon" aria-hidden="true">
            ↻
          </span>
          {isRefreshing ? "Refreshing…" : "Refresh checks"}
        </button>
      </section>

      <div className={`health-summary health-summary--${overallState}`} role="status">
        <span className="health-summary__indicator" aria-hidden="true" />
        <span>
          <strong>
            {overallState === "available"
              ? "Gateway ready"
              : overallState === "loading"
                ? "Checking gateway"
                : overallState === "degraded"
                  ? "Gateway not fully ready"
                  : "Gateway unavailable"}
          </strong>
          <span>
            {overallState === "available"
              ? "The process and required dependencies are responding."
              : "Use the endpoint details below to identify the failing boundary."}
          </span>
        </span>
      </div>

      <div className="endpoint-grid">
        <EndpointCard
          description="Confirms that the Latchway process is alive and able to serve HTTP requests."
          query={liveness}
          title="Process liveness"
        />
        <EndpointCard
          description="Confirms database, schema, active configuration, key material, and required workers."
          query={readiness}
          title="Traffic readiness"
        />
      </div>

      <SystemStatusPanel />

      <aside className="health-note" aria-labelledby="health-note-heading">
        <p className="health-note__index" aria-hidden="true">
          i
        </p>
        <div>
          <h2 id="health-note-heading">What readiness protects</h2>
          <p>
            A live process can still be unsafe for client traffic. Readiness remains
            closed until PostgreSQL, schema compatibility, active configuration, and
            required signing or encryption keys are available.
          </p>
        </div>
      </aside>
    </div>
  );
}

import type { UseQueryResult } from "@tanstack/react-query";

import type { HealthResult, HealthState } from "../api/health";

interface EndpointCardProps {
  description: string;
  query: UseQueryResult<HealthResult, Error>;
  title: string;
}

const stateLabels: Record<HealthState, string> = {
  available: "Available",
  degraded: "Degraded",
  unavailable: "Unavailable"
};

function displayTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(value));
}

export function EndpointCard({ description, query, title }: EndpointCardProps) {
  const result = query.data;
  const state: HealthState | "loading" = result?.state ?? "loading";
  const label = state === "loading" ? "Checking" : stateLabels[state];

  return (
    <article className="endpoint-card" aria-busy={query.isPending || query.isFetching}>
      <div className="endpoint-card__heading">
        <div>
          <p className="endpoint-card__eyebrow">{result?.endpoint ?? "Endpoint"}</p>
          <h2>{title}</h2>
        </div>
        <span className={`state-badge state-badge--${state}`}>
          <span className="state-badge__dot" aria-hidden="true" />
          {label}
        </span>
      </div>

      <p className="endpoint-card__description">{description}</p>

      {query.isError ? (
        <div className="endpoint-message endpoint-message--error" role="status">
          <strong>Could not reach this endpoint.</strong>
          <span>Check the server process and same-origin routing, then try again.</span>
        </div>
      ) : result ? (
        <>
          <div className="endpoint-message" role="status">
            <strong>{result.summary}</strong>
            <span>
              HTTP {result.statusCode} · {result.latencyMs} ms · observed at{" "}
              {displayTime(result.observedAt)}
            </span>
          </div>

          {result.checks.length > 0 ? (
            <ul className="check-list" aria-label={`${title} checks`}>
              {result.checks.map((check) => (
                <li className="check-list__item" key={check.name}>
                  <span
                    className={`check-list__indicator check-list__indicator--${check.state}`}
                    aria-hidden="true"
                  />
                  <span className="check-list__copy">
                    <strong>{check.name.replaceAll("_", " ")}</strong>
                    {check.detail ? <span>{check.detail}</span> : null}
                  </span>
                  <span className="visually-hidden">{stateLabels[check.state]}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : (
        <div className="endpoint-message" role="status">
          <strong>Contacting the gateway…</strong>
          <span>The result will update automatically.</span>
        </div>
      )}
    </article>
  );
}

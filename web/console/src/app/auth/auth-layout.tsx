import type { ReactNode } from "react";

import { overallHealthState, useSystemHealth } from "../../api/health";
import { Logo } from "../../ui";

function BrandArt() {
  return (
    <svg aria-hidden="true" className="lw-auth__art" viewBox="0 0 520 300">
      <rect className="is-tint" height="300" rx="24" width="520" />
      <rect className="is-ink" height="44" rx="12" width="184" x="40" y="48" />
      <rect className="is-pill-b" height="12" rx="6" width="96" x="60" y="64" />
      <rect className="is-accent" height="44" rx="12" width="184" x="40" y="128" />
      <rect className="is-pill-a" height="12" rx="6" width="120" x="60" y="144" />
      <rect className="is-ink" height="44" rx="12" width="184" x="40" y="208" />
      <rect className="is-pill-b" height="12" rx="6" width="72" x="60" y="224" />
      <rect className="is-accent" height="8" rx="4" width="72" x="240" y="146" />
      <rect className="is-accent" height="156" rx="20" width="160" x="320" y="72" />
      <rect className="is-pill-a" height="12" rx="6" width="96" x="344" y="100" />
      <rect className="is-pill-a" height="12" rx="6" width="64" x="344" y="124" />
      <rect className="is-prod" height="28" rx="14" width="112" x="344" y="176" />
      <rect className="is-pill-c" height="8" rx="4" width="48" x="260" y="70" />
      <rect className="is-pill-c" height="8" rx="4" width="48" x="260" y="230" />
    </svg>
  );
}

/** What the browser can see about this server before sign-in: its host and the public health endpoints. */
function ServerFacts() {
  const { liveness, readiness } = useSystemHealth();
  const state = overallHealthState(liveness.data, readiness.data);
  const version = liveness.data?.version ?? readiness.data?.version;
  const status = state === "available" ? "Reachable and ready" : state === "degraded" ? "Reachable, not ready" : state === "unavailable" ? "Not reachable" : "Checking…";
  return (
    <section aria-label="This server" className="lw-auth__facts">
      <strong>This server</strong>
      <dl>
        <div><dt>Host</dt><dd>{window.location.host}</dd></div>
        <div><dt>Version</dt><dd>{version ?? (state === "unavailable" ? "Unknown" : "Not reported before sign-in")}</dd></div>
        <div><dt>Status</dt><dd>{state === "loading" ? null : <span aria-hidden="true" className={state === "available" ? "lw-auth__dot" : "lw-auth__dot is-down"} />}{status}</dd></div>
      </dl>
    </section>
  );
}

export function AuthLayout({ children, description, title }: { children: ReactNode; description?: ReactNode; title: string }) {
  return (
    <div className="lw-auth">
      <div className="lw-auth__panel">
        <main className="lw-auth__main" id="main-content">
          <div className="lw-auth__head">
            <Logo />
            <h1>{title}</h1>
            {description ? <p>{description}</p> : null}
          </div>
          <div className="lw-auth__body">{children}</div>
        </main>
        <p className="lw-auth__foot">Latchway console · Your session cookie stays on this server.</p>
      </div>
      <aside aria-label="About this server" className="lw-auth__brand">
        <BrandArt />
        <ServerFacts />
      </aside>
    </div>
  );
}

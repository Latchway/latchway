import { useQueryClient } from "@tanstack/react-query";
import { Link, Outlet } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";

import { logoutAdministrator, problemFromError } from "../api/auth";
import { overallHealthState, useSystemHealth } from "../api/health";
import { consoleSessionQueryOptions, useConsoleSession, type ConsoleMode } from "../api/session";

type ConsoleRoute = "/" | "/setup" | "/configuration" | "/users" | "/installations" | "/requests" | "/usage" | "/route-simulator" | "/self-tests" | "/audit" | "/system-health";

interface NavigationLinkProps {
  children: ReactNode;
  description: string;
  to: ConsoleRoute;
}

function NavigationLink({ children, description, to }: NavigationLinkProps) {
  return (
    <Link
      activeOptions={{ exact: to === "/" }}
      activeProps={{ "aria-current": "page", className: "nav-link nav-link--active" }}
      className="nav-link"
      to={to}
    >
      <span className="nav-link__marker" aria-hidden="true" />
      <span>
        <span className="nav-link__label">{children}</span>
        <span className="nav-link__description">{description}</span>
      </span>
    </Link>
  );
}

function modeLabel(mode: ConsoleMode, userLabel: string | undefined): string {
  if (mode === "configured") {
    return userLabel ?? "Console ready";
  }
  if (mode === "signed-out") {
    return "Signed out";
  }
  return "Discovering console";
}

export function AppShell() {
  const queryClient = useQueryClient();
  const session = useConsoleSession();
  const [logoutError, setLogoutError] = useState<string>();
  const [loggingOut, setLoggingOut] = useState(false);
  const { liveness, readiness } = useSystemHealth();
  const mode = session.data?.mode ?? "unknown";
  const needsAccess = mode !== "configured";
  const overallState = overallHealthState(liveness.data, readiness.data);
  const healthLabel =
    overallState === "available"
      ? "All systems ready"
      : overallState === "degraded"
        ? "Attention required"
        : overallState === "unavailable"
          ? "System unavailable"
          : "Checking system";

  async function logout(): Promise<void> {
    setLoggingOut(true);
    setLogoutError(undefined);
    try {
      await logoutAdministrator();
      queryClient.setQueryData(consoleSessionQueryOptions.queryKey, { mode: "signed-out" });
      await queryClient.invalidateQueries({ exact: true, queryKey: consoleSessionQueryOptions.queryKey });
    } catch (error) {
      setLogoutError(problemFromError(error).detail);
    } finally {
      setLoggingOut(false);
    }
  }

  return (
    <div className="console-frame">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      <aside className="sidebar">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">
            L
          </span>
          <span>
            <span className="brand-name">Latchway</span>
            <span className="brand-product">Admin console</span>
          </span>
        </div>

        <div className="environment-card" aria-label="Deployment context">
          <span className="environment-card__label">Control plane</span>
          <strong>Self-hosted gateway</strong>
          <span className="environment-card__meta">Same-origin administration</span>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <p className="nav-group-label">{needsAccess ? "Access" : "Workspace"}</p>
          <NavigationLink
            description={
              mode === "signed-out"
                ? "Sign in or create the first owner"
                : mode === "unknown"
                  ? "Confirm the administrator session"
                  : "Gateway operating posture"
            }
            to="/"
          >
            {needsAccess ? "Console access" : "Overview"}
          </NavigationLink>

          {!needsAccess ? <>
            <NavigationLink description="Guided native first run" to="/setup">Setup wizard</NavigationLink>
            <NavigationLink description="Validate, diff, and activate" to="/configuration">Configuration</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Identity</p>
            <NavigationLink description="Pseudonymous identities" to="/users">Users</NavigationLink>
            <NavigationLink description="Trust and revocation" to="/installations">Installations</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Observability</p>
            <NavigationLink description="Metadata and attempts" to="/requests">Requests</NavigationLink>
            <NavigationLink description="Tokens and cost" to="/usage">Usage</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Operations</p>
            <NavigationLink description="Exact production resolver" to="/route-simulator">Route simulator</NavigationLink>
            <NavigationLink description="Bounded diagnostics" to="/self-tests">Self-tests</NavigationLink>
            <NavigationLink description="Redacted change history" to="/audit">Audit log</NavigationLink>
          </> : null}

          <p className="nav-group-label nav-group-label--spaced">System</p>
          <NavigationLink description="Liveness and readiness" to="/system-health">
            System health
          </NavigationLink>
        </nav>

        <div className="sidebar-footer">
          <p className="sidebar-footer__eyebrow">Console state</p>
          <p className="sidebar-footer__value">
            <span
              className={`status-dot status-dot--${mode === "signed-out" ? "warm" : "cool"}`}
              aria-hidden="true"
            />
            {modeLabel(mode, session.data?.userLabel)}
          </p>
          <p className="sidebar-footer__hint">
            Configuration changes will use the canonical Admin API.
          </p>
        </div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <div className="topbar__identity" aria-hidden="true">
            <span className="mobile-brand-mark">L</span>
            <span>Latchway</span>
          </div>
          <div className="topbar__actions"><Link
            className={`health-pill health-pill--${overallState}`}
            to="/system-health"
            aria-label={`${healthLabel}. Open system health.`}
          >
            <span className="health-pill__indicator" aria-hidden="true" />
            <span>{healthLabel}</span>
          </Link>{mode === "configured" ? <button className="topbar__logout" disabled={loggingOut} onClick={() => void logout()} type="button">{loggingOut ? "Signing out…" : "Sign out"}</button> : null}</div>
          {logoutError ? <span className="topbar__error" role="alert">{logoutError}</span> : null}
        </header>

        <main className="main-content" id="main-content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}

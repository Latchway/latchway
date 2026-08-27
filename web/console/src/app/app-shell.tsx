import { Link, Outlet } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { overallHealthState, useSystemHealth } from "../api/health";
import { useConsoleSession, type ConsoleMode } from "../api/session";

type ConsoleRoute = "/" | "/system-health";

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
  const session = useConsoleSession();
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

          <p className="nav-group-label nav-group-label--spaced">Operations</p>
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
          <Link
            className={`health-pill health-pill--${overallState}`}
            to="/system-health"
            aria-label={`${healthLabel}. Open system health.`}
          >
            <span className="health-pill__indicator" aria-hidden="true" />
            <span>{healthLabel}</span>
          </Link>
        </header>

        <main className="main-content" id="main-content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}

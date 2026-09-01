import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet } from "@tanstack/react-router";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  dispatchAdminRefresh,
  openAdminEventStream,
  startAdminEventFallback,
  type AdminEventStreamConnection
} from "../api/admin-events";
import { adminRequest, SystemStatusSchema } from "../api/admin";
import { logoutAdministrator, problemFromError } from "../api/auth";
import { overallHealthState, useSystemHealth } from "../api/health";
import { consoleSessionQueryOptions, useConsoleSession, type ConsoleMode } from "../api/session";
import { latestConfigurationRevisionQueryOptions } from "../api/workspace";
import { WorkspaceProvider } from "./workspace-context";
import { useWorkspace } from "./workspace-context-value";

type ConsoleRoute =
  | "/"
  | "/applications"
  | "/environments"
  | "/setup"
  | "/administrators"
  | "/api-tokens"
  | "/authentication-providers"
  | "/attestation"
  | "/users"
  | "/installation-families"
  | "/installations"
  | "/component-definitions"
  | "/features"
  | "/routes"
  | "/upstreams"
  | "/models-pricing"
  | "/secrets"
  | "/configuration"
  | "/access-policies"
  | "/limit-plans"
  | "/user-overrides"
  | "/abuse-controls"
  | "/requests"
  | "/usage"
  | "/cost"
  | "/latency"
  | "/errors"
  | "/attestation-failures"
  | "/configuration-revisions"
  | "/route-simulator"
  | "/self-tests"
  | "/audit"
  | "/system-health"
  | "/settings";

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
      search={(previous) => previous}
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

const commands: Array<{ description: string; label: string; to: ConsoleRoute }> = [
  { description: "Review operational posture and setup progress", label: "Overview", to: "/" },
  { description: "Create or review a client-visible AI capability", label: "Features", to: "/features" },
  { description: "Inspect request outcomes and upstream attempts", label: "Requests", to: "/requests" },
  { description: "Find an application user and effective controls", label: "Users", to: "/users" },
  { description: "Connect a server-owned upstream", label: "AI connections", to: "/upstreams" },
  { description: "Continue the guided first-run workflow", label: "Setup wizard", to: "/setup" },
  { description: "Exercise the exact server policy resolver", label: "Route simulator", to: "/route-simulator" },
  { description: "Run bounded installation diagnostics", label: "Self-tests", to: "/self-tests" },
  { description: "Inspect gateway dependencies", label: "System health", to: "/system-health" },
  { description: "Review compatibility, privacy, imports, and sessions", label: "Settings", to: "/settings" }
];

function CommandPalette({ close }: { close: () => void }) {
  const [query, setQuery] = useState("");
  const dialog = useRef<HTMLElement>(null);
  const results = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return normalized
      ? commands.filter((command) => `${command.label} ${command.description}`.toLowerCase().includes(normalized))
      : commands;
  }, [query]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(dialog.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      ) ?? []).filter((element) => !element.hasAttribute("hidden"));
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [close]);

  return <div className="command-backdrop" onMouseDown={(event) => { if (event.currentTarget === event.target) close(); }}>
    <section aria-labelledby="command-heading" aria-modal="true" className="command-palette" ref={dialog} role="dialog">
      <div className="command-palette__heading"><div><p className="eyebrow">Search or jump</p><h2 id="command-heading">Go to an operator task</h2></div><button aria-label="Close command palette" className="small-action" onClick={close} type="button">Esc</button></div>
      <label className="command-search"><span className="sr-only">Search pages and tasks</span><input autoFocus onChange={(event) => setQuery(event.target.value)} placeholder="Feature, request, setup, health…" value={query} /></label>
      <div className="command-results" role="list">{results.length ? results.map((command) => <Link className="command-result" key={command.to} onClick={close} search={(previous) => previous} to={command.to}><strong>{command.label}</strong><span>{command.description}</span></Link>) : <p>No matching task.</p>}</div>
      <p className="command-palette__hint">Dangerous actions open their review page; they never execute from search.</p>
    </section>
  </div>;
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

function AppShellContent() {
  const queryClient = useQueryClient();
  const session = useConsoleSession();
  const workspace = useWorkspace();
  const [commandOpen, setCommandOpen] = useState(false);
  const commandReturnFocus = useRef<HTMLElement | null>(null);
  const [logoutError, setLogoutError] = useState<string>();
  const [loggingOut, setLoggingOut] = useState(false);
  const { liveness, readiness } = useSystemHealth();
  const mode = session.data?.mode ?? "unknown";
  const latestRevision = useQuery({
    ...latestConfigurationRevisionQueryOptions(workspace.environment?.id ?? ""),
    enabled: mode === "configured" && Boolean(workspace.environment?.id)
  });
  const newestRevision = latestRevision.data?.items[0];
  const newestIsDraft = newestRevision && ["draft", "valid", "invalid"].includes(newestRevision.state);
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

  const showCommand = useCallback(() => {
    if (document.activeElement instanceof HTMLElement) commandReturnFocus.current = document.activeElement;
    setCommandOpen(true);
  }, []);

  const closeCommand = useCallback(() => {
    setCommandOpen(false);
  }, []);

  useEffect(() => {
    function openCommand(event: KeyboardEvent): void {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        showCommand();
      }
    }
    window.addEventListener("keydown", openCommand);
    return () => window.removeEventListener("keydown", openCommand);
  }, [showCommand]);

  useEffect(() => {
    if (commandOpen || !commandReturnFocus.current) return;
    const target = commandReturnFocus.current;
    commandReturnFocus.current = null;
    target.focus();
  }, [commandOpen]);

  useEffect(() => {
    if (mode !== "configured") return;
    const controller = new AbortController();
    let connection: AdminEventStreamConnection | undefined;
    let disposed = false;
    void adminRequest("/admin/v1/system", SystemStatusSchema, { signal: controller.signal })
      .then(({ data }) => {
        if (disposed) return;
        const onTopics = dispatchAdminRefresh;
        connection = data.server_capabilities.includes("admin_event_stream")
          ? openAdminEventStream({ environmentID: workspace.environment?.id, onTopics })
          : startAdminEventFallback(onTopics);
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      controller.abort();
      connection?.close();
    };
  }, [mode, workspace.environment?.id]);

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
          <span className="environment-card__label">Current scope</span>
          <strong>{workspace.application?.display_name ?? "Select an application"}</strong>
          <span className="environment-card__meta">{workspace.environment ? `${workspace.environment.display_name} · ${workspace.environment.kind}` : "No environment selected"}</span>
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
            <NavigationLink description="Client-visible capabilities" to="/features">Features</NavigationLink>
            <NavigationLink description="Metadata and attempts" to="/requests">Requests</NavigationLink>
            <NavigationLink description="Pseudonymous identities and controls" to="/users">Users</NavigationLink>
            <NavigationLink description="Trusted token accounting" to="/usage">Usage</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Configure</p>
            <NavigationLink description="Provider and gateway destinations" to="/upstreams"><span>Upstreams</span><span className="nav-link__operator-term"> · AI connections</span></NavigationLink>
            <NavigationLink description="Authentication, app verification, and components" to="/attestation"><span>Attestation</span><span className="nav-link__operator-term"> · Client access</span></NavigationLink>
            <NavigationLink description="Application deployment scopes" to="/environments">Environments</NavigationLink>
            <NavigationLink description="Guided first-run checklist" to="/setup">Setup wizard</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Investigate</p>
            <NavigationLink description="Nano-USD and provenance" to="/cost">Cost</NavigationLink>
            <NavigationLink description="Request and first-token timing" to="/latency">Latency</NavigationLink>
            <NavigationLink description="Failure and denial rates" to="/errors">Errors</NavigationLink>
            <NavigationLink description="Rejected platform proofs" to="/attestation-failures">Attestation failures</NavigationLink>
            <NavigationLink description="Component trust and revocation" to="/installation-families">Installation families</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Changes &amp; operations</p>
            <NavigationLink description="History and safe rollback" to="/configuration-revisions">Configuration revisions</NavigationLink>
            <NavigationLink description="Exact production resolver" to="/route-simulator">Route simulator</NavigationLink>
            <NavigationLink description="Bounded diagnostics" to="/self-tests">Self-tests</NavigationLink>
            <NavigationLink description="Redacted change history" to="/audit">Audit log</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Advanced configuration</p>
            <NavigationLink description="Tenant application resources" to="/applications">Applications</NavigationLink>
            <NavigationLink description="Issuer and claim trust" to="/authentication-providers">Authentication providers</NavigationLink>
            <NavigationLink description="Allowed roots, children, and feature grants" to="/component-definitions">Component definitions</NavigationLink>
            <NavigationLink description="Ordered conditional resolution" to="/routes">Routes</NavigationLink>
            <NavigationLink description="Physical models and rates" to="/models-pricing">Models &amp; pricing</NavigationLink>
            <NavigationLink description="Write-only credentials" to="/secrets">Secrets</NavigationLink>
            <NavigationLink description="Validate, diff, and activate" to="/configuration">Full configuration</NavigationLink>
            <NavigationLink description="Per-feature authorization" to="/access-policies">Access policies</NavigationLink>
            <NavigationLink description="Durable quota policies" to="/limit-plans">Limit plans</NavigationLink>
            <NavigationLink description="Per-user plan selection" to="/user-overrides">User overrides</NavigationLink>
            <NavigationLink description="Composed protective controls" to="/abuse-controls">Abuse controls</NavigationLink>
            <NavigationLink description="Legacy root installation records" to="/installations">Installations</NavigationLink>

            <p className="nav-group-label nav-group-label--spaced">Team &amp; access</p>
            <NavigationLink description="Accounts and roles" to="/administrators">Administrators</NavigationLink>
            <NavigationLink description="Scoped automation credentials" to="/api-tokens">API tokens</NavigationLink>
          </> : null}

          <p className="nav-group-label nav-group-label--spaced">System</p>
          <NavigationLink description="Liveness and readiness" to="/system-health">
            System health
          </NavigationLink>
          {!needsAccess ? <NavigationLink description="Compatibility, privacy, transfer, and sessions" to="/settings">Settings</NavigationLink> : null}
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
          <div className="topbar__identity">
            <span className="mobile-brand-mark">L</span>
            {mode === "configured" ? <div className="workspace-switchers">
              <label><span className="sr-only">Current application</span><select aria-label="Current application" disabled={!workspace.applications.length} onChange={(event) => workspace.selectApplication(event.target.value)} value={workspace.application?.slug ?? ""}><option value="">Application…</option>{workspace.applications.map((application) => <option key={application.id} value={application.slug}>{application.display_name}</option>)}</select></label>
              <span aria-hidden="true">/</span>
              <label><span className="sr-only">Current environment</span><select aria-label="Current environment" className={`environment-select environment-select--${workspace.environment?.kind ?? "unknown"}`} disabled={!workspace.environments.length} onChange={(event) => workspace.selectEnvironment(event.target.value)} value={workspace.environment?.slug ?? ""}><option value="">Environment…</option>{workspace.environments.map((environment) => <option key={environment.id} value={environment.slug}>{environment.display_name} · {environment.kind}</option>)}</select></label>
              {workspace.environment ? <span className={`environment-badge environment-badge--${workspace.environment.kind}`}>{workspace.environment.kind === "production" ? "Production" : workspace.environment.kind}</span> : null}
            </div> : <span>Latchway</span>}
          </div>
          <div className="topbar__actions">{mode === "configured" ? <button aria-label="Search or jump" className="command-trigger" onClick={showCommand} type="button"><span>Search or jump…</span><kbd>{typeof navigator !== "undefined" && navigator.platform.includes("Mac") ? "⌘K" : "Ctrl K"}</kbd></button> : null}<Link
            className={`health-pill health-pill--${overallState}`}
            search={(previous) => previous}
            to="/system-health"
            aria-label={`${healthLabel}. Open system health.`}
          >
            <span className="health-pill__indicator" aria-hidden="true" />
            <span>{healthLabel}</span>
          </Link>{mode === "configured" ? <><Link className={`draft-indicator ${newestIsDraft ? "draft-indicator--pending" : ""}`} search={(previous) => previous} title={newestIsDraft ? `Newest server revision ${newestRevision.id} is ${newestRevision.state}.` : "Open configuration history."} to="/configuration-revisions">{newestIsDraft ? `Draft ${newestRevision.state}` : workspace.environment?.active_revision_id ? "Active configuration" : "Setup required"}</Link><span className="admin-identity">{session.data?.userLabel ?? "Administrator"}</span><button className="topbar__logout" disabled={loggingOut} onClick={() => void logout()} type="button">{loggingOut ? "Signing out…" : "Sign out"}</button></> : null}</div>
          {logoutError ? <span className="topbar__error" role="alert">{logoutError}</span> : null}
        </header>

        <main className="main-content" id="main-content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
      {commandOpen ? <CommandPalette close={closeCommand} /> : null}
    </div>
  );
}

export function AppShell() {
  return <WorkspaceProvider><AppShellContent /></WorkspaceProvider>;
}

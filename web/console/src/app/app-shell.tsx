import { useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useLocation } from "@tanstack/react-router";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  dispatchAdminRefresh,
  openAdminEventStream,
  startAdminEventFallback,
  type AdminEventStreamConnection
} from "../api/admin-events";
import { logoutAdministrator, problemFromError } from "../api/auth";
import { overallHealthState, useSystemHealth } from "../api/health";
import { consoleSessionQueryOptions, useConsoleSession, type ConsoleMode } from "../api/session";
import { buttonClass, cx, EnvironmentBadge, Icon, Logo, Menu, type StatusItem, StatusRail, useFocusTrap } from "../ui";
import { useConsoleCompatibility } from "./console-compatibility-context";
import { ConsoleCompatibilityProvider } from "./console-compatibility";
import {
  areaForPath,
  type Command,
  commands,
  environmentNavigation,
  isOrganizationPath,
  type NavArea,
  type NavGroup,
  organizationNavigation,
  scopeSearch
} from "./navigation";
import { effectiveTheme, setTheme, type Theme } from "./theme";
import { DraftActions } from "../pages/build/draft-actions";
import { draftSummary } from "../pages/build/draft-summary";
import { useEnvironmentDraft } from "../pages/build/environment-draft";
import { WorkspaceProvider } from "./workspace-context";
import { useWorkspace } from "./workspace-context-value";

function CommandPalette({ close }: { close: () => void }) {
  const [query, setQuery] = useState("");
  const dialog = useRef<HTMLElement>(null);
  useFocusTrap(dialog, close);
  const results = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return normalized
      ? commands.filter((command) => `${command.section ?? ""} ${command.label} ${command.description}`.toLowerCase().includes(normalized))
      : commands;
  }, [query]);

  return <div className="lw-overlay lw-overlay--top" onMouseDown={(event) => { if (event.currentTarget === event.target) close(); }}>
    <section aria-labelledby="command-heading" aria-modal="true" className="lw-palette" ref={dialog} role="dialog">
      <h2 className="lw-sr" id="command-heading">Go to an operator task</h2>
      <div className="lw-palette__input">
        <Icon name="search" />
        <button aria-label="Close command palette" className="lw-kbd lw-palette__close" onClick={close} type="button">Esc</button>
        <label className="lw-sr" htmlFor="command-query">Search pages and tasks</label>
        <input autoComplete="off" data-autofocus id="command-query" onChange={(event) => setQuery(event.target.value)} placeholder="Feature, request, setup, health…" value={query} />
      </div>
      <div className="lw-palette__list">
        {results.length ? results.map((command: Command) => (
          <Link className="lw-menu__item" key={command.to} onClick={close} search={scopeSearch} to={command.to}>
            <span className="lw-menu__item-label">{command.section ? <span className="lw-palette__section">{command.section} › </span> : null}{command.label}</span>
            <span className="lw-menu__item-hint">{command.description}</span>
          </Link>
        )) : <p className="lw-palette__empty">No matching page.</p>}
      </div>
      <p className="lw-palette__foot">Search only navigates. Dangerous actions open their review page; they never execute from here.</p>
    </section>
  </div>;
}

function SideLink({ area, pathname }: { area: NavArea; pathname: string }) {
  const active = area.to === pathname || Boolean(area.tabs?.some((tab) => tab.to === pathname));
  return (
    <Link aria-current={active ? "page" : undefined} className="lw-side-item" search={scopeSearch} to={area.to}>
      <Icon name={area.icon} />
      <span className="lw-side-item__label">{area.label}</span>
    </Link>
  );
}

function SideGroup({ group, pathname }: { group: NavGroup; pathname: string }) {
  const [open, setOpen] = useState(true);
  const containsActive = group.areas.some((area) => area.to === pathname || area.tabs?.some((tab) => tab.to === pathname));
  const expanded = !group.collapsible || open || containsActive;
  return (
    <div className="lw-side-section">
      {group.title ? group.collapsible ? (
        <button aria-expanded={expanded} className="lw-side-section__head" onClick={() => setOpen(!open)} type="button">
          <Icon className="lw-side-section__chevron" name="chevronRight" />
          <span className="lw-side-section__title">{group.title}</span>
        </button>
      ) : (
        <div className="lw-side-section__head"><span className="lw-side-section__title">{group.title}</span></div>
      ) : null}
      {expanded ? group.areas.map((area) => <SideLink area={area} key={area.to} pathname={pathname} />) : null}
    </div>
  );
}

function SectionTabs({ area, pathname }: { area: NavArea; pathname: string }) {
  if (!area.tabs) return null;
  return (
    <nav aria-label={`${area.label} pages`} className="lw-section-nav">
      <div className="lw-tabs">
        {area.tabs.map((tab) => (
          <Link aria-current={tab.to === pathname ? "page" : undefined} className="lw-tab" key={tab.to} search={scopeSearch} title={tab.description} to={tab.to}>{tab.label}</Link>
        ))}
      </div>
    </nav>
  );
}

function modeLabel(mode: ConsoleMode, userLabel: string | undefined): string {
  if (mode === "configured") return userLabel ?? "Console ready";
  if (mode === "signed-out") return "Signed out";
  return "Discovering console";
}

function initials(label: string): string {
  const name = label.split("@")[0] ?? label;
  return name.split(/[\s._-]+/).filter(Boolean).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "A";
}

function AppShellContent() {
  const queryClient = useQueryClient();
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const workspace = useWorkspace();
  const { pathname } = useLocation();
  const [commandOpen, setCommandOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  // The phone drawer belongs to the page it was opened on, so it closes whenever a navigation lands.
  const [navOpenOn, setNavOpenOn] = useState<string | null>(null);
  const [theme, setThemeState] = useState<Theme>(() => effectiveTheme());
  const accountButton = useRef<HTMLButtonElement>(null);
  const [logoutError, setLogoutError] = useState<string>();
  const [loggingOut, setLoggingOut] = useState(false);
  const { liveness, readiness } = useSystemHealth();
  const mode = session.data?.mode ?? "unknown";
  const configured = mode === "configured";
  const sharedDraft = useEnvironmentDraft();
  const draft = configured ? draftSummary(sharedDraft) : undefined;
  const overallState = overallHealthState(liveness.data, readiness.data);
  const healthLabel =
    overallState === "available"
      ? "All systems ready"
      : overallState === "degraded"
        ? "Attention required"
        : overallState === "unavailable"
          ? "System unavailable"
          : "Checking system";
  const userLabel = session.data?.userLabel ?? "Administrator";
  const area = configured ? areaForPath(pathname) : undefined;
  const scopeDimmed = isOrganizationPath(pathname);
  const navOpen = navOpenOn === pathname;
  const setNavOpen = useCallback((open: boolean) => setNavOpenOn(open ? pathname : null), [pathname]);

  const showCommand = useCallback(() => setCommandOpen(true), []);
  const closeCommand = useCallback(() => setCommandOpen(false), []);
  const closeAccount = useCallback(() => {
    setAccountOpen(false);
    accountButton.current?.focus();
  }, []);

  useEffect(() => {
    if (!configured) return;
    function openCommand(event: KeyboardEvent): void {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        showCommand();
      }
    }
    window.addEventListener("keydown", openCommand);
    return () => window.removeEventListener("keydown", openCommand);
  }, [configured, showCommand]);

  useEffect(() => {
    if (!accountOpen) return;
    function onPointerDown(event: MouseEvent): void {
      if (event.target instanceof Node && !accountButton.current?.parentElement?.contains(event.target)) setAccountOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [accountOpen]);

  useEffect(() => {
    if (!navOpen) return;
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape") setNavOpen(false);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navOpen, setNavOpen]);

  useEffect(() => {
    if (!configured || !consoleCompatibility.status) return;
    const connection: AdminEventStreamConnection = consoleCompatibility.status.server_capabilities.includes("admin_event_stream")
      ? openAdminEventStream({ environmentID: workspace.environment?.id, onTopics: dispatchAdminRefresh })
      : startAdminEventFallback(dispatchAdminRefresh);
    return () => {
      connection?.close();
    };
  }, [configured, consoleCompatibility.status, workspace.environment?.id]);

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

  function toggleTheme(): void {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    setThemeState(next);
  }

  const statusItems: StatusItem[] = [];
  if (configured && !consoleCompatibility.mutationAllowed) {
    const reasons = consoleCompatibility.compatibility?.reasons ?? [];
    statusItems.push({
      chip: "Read-only safe mode",
      icon: "lock",
      id: "safe-mode",
      text: <>
        Administrative reads and redaction-safe export remain available. Mutations stay disabled until the Console verifies the server contract, protocol, required capabilities, and mutation readiness.
        {reasons.length ? <ul className="lw-status__reasons">{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : consoleCompatibility.error ? " Compatibility status could not be loaded." : " Compatibility status is being verified."}
      </>,
      title: "Read-only safe mode.",
      tone: "danger"
    });
  }
  if (configured && workspace.environment && draft) {
    statusItems.push({
      actions: <DraftActions draft={sharedDraft} />,
      chip: draft.chip,
      icon: "changes",
      id: "draft",
      text: draft.text,
      title: draft.title,
      tone: "draft"
    });
  } else if (configured && workspace.environment && !sharedDraft.isPending && !workspace.environment.active_revision_id && !sharedDraft.active) {
    statusItems.push({
      actions: <Link className={buttonClass({ size: "sm" })} search={scopeSearch} to="/setup">Continue setup</Link>,
      chip: "Setup required",
      icon: "rocket",
      id: "setup",
      text: `${workspace.environment.display_name} has no active configuration yet.`,
      title: "Setup required.",
      tone: "warning"
    });
  }

  const productionScope = configured && !scopeDimmed && workspace.environment?.kind === "production";

  return (
    <div className="lw-root lw-console" data-nav-open={navOpen ? "" : undefined}>
      <a className="skip-link" href="#main-content">Skip to main content</a>

      <header className={cx("lw-header lw-console__header", productionScope && "lw-header--production")}>
        <div className="lw-header__logo">
          {configured ? (
            <button aria-controls="console-navigation" aria-expanded={navOpen} aria-label={navOpen ? "Close navigation" : "Open navigation"} className="lw-console__nav-toggle" onClick={() => setNavOpen(!navOpen)} type="button">
              <Icon name={navOpen ? "x" : "menu"} size={20} />
            </button>
          ) : null}
          <Link aria-label="Latchway home" className="lw-console__home" search={scopeSearch} to="/"><Logo /></Link>
        </div>
        <div className="lw-header__main">
          {configured ? <>
            <span className="lw-crumb lw-crumb--strong lw-crumb--hide-sm" title="Organization">{workspace.organization?.display_name ?? "Organization"}</span>
            <span aria-hidden="true" className="lw-slash lw-crumb--hide-sm" />
            <span className={cx("lw-crumb-select", scopeDimmed && "lw-crumb-btn--dim")} title={scopeDimmed ? "Not used on this page" : undefined}>
              <select aria-label="Current application" disabled={!workspace.applications.length} onChange={(event) => workspace.selectApplication(event.target.value)} value={workspace.application?.slug ?? ""}>
                <option value="">Application…</option>
                {workspace.applications.map((application) => <option key={application.id} value={application.slug}>{application.display_name}</option>)}
              </select>
              <Icon name="chevronDown" />
            </span>
            <span aria-hidden="true" className="lw-slash" />
            <span className={cx("lw-crumb-select", scopeDimmed && "lw-crumb-btn--dim")} title={scopeDimmed ? "Not used on this page" : undefined}>
              <select aria-label="Current environment" disabled={!workspace.environments.length} onChange={(event) => workspace.selectEnvironment(event.target.value)} value={workspace.environment?.slug ?? ""}>
                <option value="">Environment…</option>
                {workspace.environments.map((environment) => <option key={environment.id} value={environment.slug}>{environment.display_name}</option>)}
              </select>
              <Icon name="chevronDown" />
            </span>
            {workspace.environment ? <EnvironmentBadge className={cx("lw-console__env", scopeDimmed && "lw-crumb-btn--dim")} kind={workspace.environment.kind} /> : null}
          </> : <span className="lw-crumb lw-crumb--strong">Latchway</span>}
        </div>
        <div className="lw-header__right">
          {configured ? (
            <button aria-label="Search or jump" className="lw-header__search" onClick={showCommand} type="button">
              <Icon name="search" />
              <span>Search</span>
              <kbd className="lw-kbd">{typeof navigator !== "undefined" && navigator.platform.includes("Mac") ? "⌘K" : "Ctrl K"}</kbd>
            </button>
          ) : null}
          <Link aria-label={`${healthLabel}. Open system health.`} className={cx("lw-health", overallState !== "available" && `lw-health--${overallState}`)} search={scopeSearch} to="/system-health">
            <span aria-hidden="true" className="lw-badge__dot" />
            <span className="lw-health__text">{healthLabel}</span>
          </Link>
          <button aria-label={theme === "dark" ? "Use light theme" : "Use dark theme"} className="lw-btn lw-btn--ghost lw-btn--icon" onClick={toggleTheme} title={theme === "dark" ? "Use light theme" : "Use dark theme"} type="button">
            <Icon name="sun" />
          </button>
          {configured ? (
            <span className="lw-console__account">
              <button aria-expanded={accountOpen} aria-haspopup="menu" aria-label={`Your account: ${userLabel}`} className="lw-avatar lw-avatar--button" onClick={() => setAccountOpen(!accountOpen)} ref={accountButton} title={userLabel} type="button">
                {initials(userLabel)}
              </button>
              {accountOpen ? (
                <div className="lw-console__popover">
                  <Menu
                    entries={[
                      { heading: modeLabel(mode, session.data?.userLabel), kind: "heading" },
                      { kind: "separator" },
                      { destructive: true, icon: "external", label: loggingOut ? "Signing out…" : "Sign out", onSelect: () => void logout() }
                    ]}
                    label="Account"
                    onClose={closeAccount}
                  />
                </div>
              ) : null}
            </span>
          ) : null}
        </div>
      </header>
      {logoutError ? <p className="lw-console__error" role="alert">{logoutError}</p> : null}

      <div className="lw-console__row">
        {navOpen ? <div aria-hidden="true" className="lw-console__scrim" onClick={() => setNavOpen(false)} /> : null}
        <nav aria-label="Primary navigation" className="lw-sidebar lw-console__sidebar" id="console-navigation">
          {configured ? <>
            <div className="lw-side-scope">
              <span className="lw-side-scope__label">Environment</span>
              <span className="lw-side-scope__sub">{workspace.application && workspace.environment ? `${workspace.application.display_name} · ${workspace.environment.display_name}` : "No environment selected"}</span>
            </div>
            {environmentNavigation.map((group, index) => <SideGroup group={group} key={group.title ?? index} pathname={pathname} />)}
            <hr className="lw-side-divider" />
            <div className="lw-side-scope">
              <span className="lw-side-scope__label">Organization</span>
              <span className="lw-side-scope__sub">{workspace.organization?.display_name ?? "Organization"}</span>
            </div>
            {organizationNavigation.map((group, index) => <SideGroup group={group} key={group.title ?? index} pathname={pathname} />)}
          </> : <>
            <SideLink area={{ description: "Sign in or create the first owner", icon: "lock", label: "Console access", to: "/" }} pathname={pathname} />
            <SideLink area={{ description: "Liveness and readiness", icon: "health", label: "System Health", to: "/system-health" }} pathname={pathname} />
          </>}
          <p className="lw-side-foot">Changes use the canonical Admin API.</p>
        </nav>

        <main className="lw-console__main" id="main-content" tabIndex={-1}>
          <StatusRail items={statusItems} label="Console state" />
          {area ? <SectionTabs area={area} pathname={pathname} /> : null}
          <div className="main-content"><Outlet /></div>
        </main>
      </div>
      {commandOpen ? <CommandPalette close={closeCommand} /> : null}
    </div>
  );
}

export function AppShell(): ReactNode {
  return <WorkspaceProvider><ConsoleCompatibilityProvider><AppShellContent /></ConsoleCompatibilityProvider></WorkspaceProvider>;
}


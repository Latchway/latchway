import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { type ReactNode, useEffect, useMemo } from "react";

import {
  applicationsQueryOptions,
  environmentsQueryOptions,
  organizationsQueryOptions
} from "../api/workspace";
import { useConsoleSession } from "../api/session";
import {
  WorkspaceContext,
  type WorkspaceContextValue,
  type WorkspaceSearch,
  useOptionalWorkspace
} from "./workspace-context-value";

function selectedBySlug<T extends { slug: string }>(items: T[], requested: string | undefined): T | undefined {
  if (requested) return items.find((item) => item.slug === requested);
  return items[0];
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const session = useConsoleSession();
  const navigate = useNavigate();
  const location = useLocation();
  const search = location.search as WorkspaceSearch;
  const configured = session.data?.mode === "configured";
  const organizationID = configured ? session.data?.session?.organization_id ?? "" : "";
  const organizationsQuery = useQuery({
    ...organizationsQueryOptions(),
    enabled: configured
  });
  const organizations = organizationsQuery.data?.items ?? [];
  const organization = organizations.find((item) => item.id === organizationID);
  const applicationsQuery = useQuery({
    ...applicationsQueryOptions(organizationID),
    enabled: configured && Boolean(organizationID)
  });
  const applications = useMemo(() => applicationsQuery.data?.items ?? [], [applicationsQuery.data?.items]);
  const application = selectedBySlug(applications, search.application);
  const environmentsQuery = useQuery({
    ...environmentsQueryOptions(application?.id ?? ""),
    enabled: configured && Boolean(application?.id)
  });
  const environments = useMemo(() => environmentsQuery.data?.items ?? [], [environmentsQuery.data?.items]);
  const environment = selectedBySlug(environments, search.environment);
  const invalidApplication = Boolean(search.application && applicationsQuery.isSuccess && !application);
  const invalidEnvironment = Boolean(search.environment && environmentsQuery.isSuccess && !environment);

  useEffect(() => {
    if (!configured || invalidApplication || invalidEnvironment || !application || !environment) return;
    const organizationSlug = organization?.slug;
    if (
      search.application === application.slug &&
      search.environment === environment.slug &&
      (!organizationSlug || search.organization === organizationSlug)
    ) return;
    void navigate({
      replace: true,
      search: (previous) => ({
        ...previous,
        application: application.slug,
        environment: environment.slug,
        ...(organizationSlug ? { organization: organizationSlug } : {})
      }),
      to: location.pathname
    });
  }, [application, configured, environment, invalidApplication, invalidEnvironment, location.pathname, navigate, organization?.slug, search.application, search.environment, search.organization]);

  const value = useMemo<WorkspaceContextValue>(() => ({
    application,
    applications,
    environment,
    environments,
    invalidApplication,
    invalidEnvironment,
    isLoading: configured && (organizationsQuery.isPending || applicationsQuery.isPending || (Boolean(application) && environmentsQuery.isPending)),
    organization,
    search,
    selectApplication: (slug) => {
      const nextApplication = applications.find((item) => item.slug === slug);
      if (!nextApplication) return;
      void navigate({
        search: (previous) => ({ ...previous, application: slug, environment: undefined }),
        to: location.pathname
      });
    },
    selectEnvironment: (slug) => {
      if (!environments.some((item) => item.slug === slug)) return;
      void navigate({
        search: (previous) => ({ ...previous, environment: slug }),
        to: location.pathname
      });
    },
    updateSearch: (patch) => {
      void navigate({
        replace: true,
        search: (previous) => ({ ...previous, ...patch }),
        to: location.pathname
      });
    }
  }), [application, applications, applicationsQuery.isPending, configured, environment, environments, environmentsQuery.isPending, invalidApplication, invalidEnvironment, location.pathname, navigate, organization, organizationsQuery.isPending, search]);

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function EnvironmentRequired({ children }: { children: ReactNode }) {
  const workspace = useOptionalWorkspace();
  if (!workspace) return children;
  if (workspace.isLoading) {
    return <section className="empty-state" role="status"><h1>Loading application environment…</h1><p>The console is resolving the server-owned workspace context.</p></section>;
  }
  if (workspace.invalidApplication || workspace.invalidEnvironment) {
    return <section className="empty-state" role="alert"><h1>The URL names an unavailable environment.</h1><p>Select an application and environment in the top bar. The console will not fall back silently from an invalid URL.</p></section>;
  }
  if (!workspace.application || !workspace.environment) {
    return <section className="empty-state"><h1>Create an application environment first.</h1><p>Task pages remain disabled until the Admin API returns an explicit environment.</p></section>;
  }
  return children;
}

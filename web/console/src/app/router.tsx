import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  redirect
} from "@tanstack/react-router";

import { AppShell } from "./app-shell";
import { NotFoundPage } from "../pages/not-found-page";
import { OverviewPage } from "../pages/overview-page";
import { SystemHealthPage } from "../pages/system-health-page";
import { SettingsPage } from "../pages/settings-page";
import { AdministratorsPage } from "../pages/administrators-page";
import { APITokensPage } from "../pages/api-tokens-page";
import {
  AuditPageView,
  RouteSimulatorPage,
  SelfTestsPage,
} from "../pages/control-plane-pages";
import { RequestsPage } from "../pages/requests/requests-page";
import { InstallationFamiliesPage } from "../pages/users/installations-page";
import { InstallationsPage } from "../pages/users/older-installs-page";
import { UsersPage } from "../pages/users/users-page";
import {
  CostAnalyticsPage,
  PerformanceAnalyticsPage,
  ReliabilityAnalyticsPage,
  UsageAnalyticsPage
} from "../pages/analytics/analytics-page";
import {
  ConfigurationEditorPage,
  SetupWizardPage
} from "../pages/configuration-pages";
import {
  AbuseControlsConfigurationPage,
  AccessPoliciesConfigurationPage,
  AttestationConfigurationPage,
  AuthenticationProvidersPage,
  ComponentDefinitionsConfigurationPage,
  FeaturesConfigurationPage,
  LimitPlansConfigurationPage,
  ModelsPricingConfigurationPage,
  RoutesConfigurationPage,
  UpstreamsConfigurationPage
} from "../pages/configuration-area-pages";
import {
  ApplicationsPage,
  ConfigurationRevisionsPage,
  EnvironmentsPage,
  SecretsPage,
  UserOverridesPage
} from "../pages/resource-management-pages";
import {
  AnalyticsRouteSearchSchema,
  parseAnalyticsRouteSearch,
  parseConfigurationRouteSearch,
  parseAuditRouteSearch,
  parseFeatureRouteSearch,
  parseInstallationFamilyRouteSearch,
  parseInstallationRouteSearch,
  parseRequestRouteSearch,
  parseRouteSimulatorRouteSearch,
  parseSelfTestRouteSearch,
  parseUserRouteSearch
} from "./route-search";

const rootRoute = createRootRoute({
  component: AppShell,
  notFoundComponent: NotFoundPage
});

const indexRoute = createRoute({
  component: OverviewPage,
  getParentRoute: () => rootRoute,
  path: "/"
});

const systemHealthRoute = createRoute({
  component: SystemHealthPage,
  getParentRoute: () => rootRoute,
  path: "/system-health"
});
const settingsRoute = createRoute({ component: SettingsPage, getParentRoute: () => rootRoute, path: "/settings" });

const setupRoute = createRoute({ component: SetupWizardPage, getParentRoute: () => rootRoute, path: "/setup" });
const configurationRoute = createRoute({ component: ConfigurationEditorPage, getParentRoute: () => rootRoute, path: "/configuration", validateSearch: parseConfigurationRouteSearch });
const applicationsRoute = createRoute({ component: ApplicationsPage, getParentRoute: () => rootRoute, path: "/applications" });
const environmentsRoute = createRoute({ component: EnvironmentsPage, getParentRoute: () => rootRoute, path: "/environments" });
const administratorsRoute = createRoute({ component: AdministratorsPage, getParentRoute: () => rootRoute, path: "/administrators" });
const apiTokensRoute = createRoute({ component: APITokensPage, getParentRoute: () => rootRoute, path: "/api-tokens" });
const authenticationProvidersRoute = createRoute({ component: AuthenticationProvidersPage, getParentRoute: () => rootRoute, path: "/authentication-providers", validateSearch: parseConfigurationRouteSearch });
const attestationRoute = createRoute({ component: AttestationConfigurationPage, getParentRoute: () => rootRoute, path: "/attestation" });
const usersRoute = createRoute({ component: UsersPage, getParentRoute: () => rootRoute, path: "/users", validateSearch: parseUserRouteSearch });
const installationsRoute = createRoute({ component: InstallationsPage, getParentRoute: () => rootRoute, path: "/installations", validateSearch: parseInstallationRouteSearch });
const installationFamiliesRoute = createRoute({ component: InstallationFamiliesPage, getParentRoute: () => rootRoute, path: "/installation-families", validateSearch: parseInstallationFamilyRouteSearch });
const componentDefinitionsRoute = createRoute({ component: ComponentDefinitionsConfigurationPage, getParentRoute: () => rootRoute, path: "/component-definitions", validateSearch: parseConfigurationRouteSearch });
const featuresRoute = createRoute({ component: FeaturesConfigurationPage, getParentRoute: () => rootRoute, path: "/features", validateSearch: parseFeatureRouteSearch });
const routesRoute = createRoute({ component: RoutesConfigurationPage, getParentRoute: () => rootRoute, path: "/routes", validateSearch: parseConfigurationRouteSearch });
const upstreamsRoute = createRoute({ component: UpstreamsConfigurationPage, getParentRoute: () => rootRoute, path: "/upstreams" });
const modelsPricingRoute = createRoute({ component: ModelsPricingConfigurationPage, getParentRoute: () => rootRoute, path: "/models-pricing", validateSearch: parseConfigurationRouteSearch });
const secretsRoute = createRoute({ component: SecretsPage, getParentRoute: () => rootRoute, path: "/secrets" });
const accessPoliciesRoute = createRoute({ component: AccessPoliciesConfigurationPage, getParentRoute: () => rootRoute, path: "/access-policies", validateSearch: parseConfigurationRouteSearch });
const limitPlansRoute = createRoute({ component: LimitPlansConfigurationPage, getParentRoute: () => rootRoute, path: "/limit-plans" });
const userOverridesRoute = createRoute({ component: UserOverridesPage, getParentRoute: () => rootRoute, path: "/user-overrides" });
const abuseControlsRoute = createRoute({ component: AbuseControlsConfigurationPage, getParentRoute: () => rootRoute, path: "/abuse-controls", validateSearch: parseConfigurationRouteSearch });
const requestsRoute = createRoute({
  component: RequestsPage,
  getParentRoute: () => rootRoute,
  path: "/requests",
  validateSearch: parseRequestRouteSearch
});
const usageRoute = createRoute({ component: UsageAnalyticsPage, getParentRoute: () => rootRoute, path: "/analytics/usage", validateSearch: parseAnalyticsRouteSearch });
const costRoute = createRoute({ component: CostAnalyticsPage, getParentRoute: () => rootRoute, path: "/analytics/cost", validateSearch: parseAnalyticsRouteSearch });
const performanceRoute = createRoute({ component: PerformanceAnalyticsPage, getParentRoute: () => rootRoute, path: "/analytics/performance", validateSearch: parseAnalyticsRouteSearch });
const reliabilityRoute = createRoute({ component: ReliabilityAnalyticsPage, getParentRoute: () => rootRoute, path: "/analytics/reliability", validateSearch: parseAnalyticsRouteSearch });

/**
 * The five pre-redesign analytics pages became tabs of one Analytics page. Old links keep working: the workspace
 * selection carries over, and a period carries over only when it was a whole-day range the new page can show.
 */
function legacyAnalyticsRoute(path: string, to: "/analytics/usage" | "/analytics/cost" | "/analytics/performance" | "/analytics/reliability") {
  return createRoute({
    beforeLoad: ({ search }) => {
      const previous = search as Record<string, unknown>;
      const carried = parseAnalyticsRouteSearch({
        application: previous.application,
        environment: previous.environment,
        organization: previous.organization
      });
      const withPeriod = AnalyticsRouteSearchSchema.safeParse({ ...carried, end: previous.end, start: previous.start });
      throw redirect({ replace: true, search: withPeriod.success ? withPeriod.data : carried, to });
    },
    getParentRoute: () => rootRoute,
    path
  });
}

const legacyAnalyticsRoutes = [
  legacyAnalyticsRoute("/usage", "/analytics/usage"),
  legacyAnalyticsRoute("/cost", "/analytics/cost"),
  legacyAnalyticsRoute("/latency", "/analytics/performance"),
  legacyAnalyticsRoute("/errors", "/analytics/reliability"),
  legacyAnalyticsRoute("/attestation-failures", "/analytics/reliability")
];
const configurationRevisionsRoute = createRoute({ component: ConfigurationRevisionsPage, getParentRoute: () => rootRoute, path: "/configuration-revisions" });
const routeSimulatorRoute = createRoute({ component: RouteSimulatorPage, getParentRoute: () => rootRoute, path: "/route-simulator", validateSearch: parseRouteSimulatorRouteSearch });
const selfTestsRoute = createRoute({ component: SelfTestsPage, getParentRoute: () => rootRoute, path: "/self-tests", validateSearch: parseSelfTestRouteSearch });
const auditRoute = createRoute({
  component: AuditPageView,
  getParentRoute: () => rootRoute,
  path: "/audit",
  validateSearch: parseAuditRouteSearch
});

const routeTree = rootRoute.addChildren([
  indexRoute, applicationsRoute, environmentsRoute, setupRoute, administratorsRoute, apiTokensRoute,
  authenticationProvidersRoute, attestationRoute, usersRoute, installationFamiliesRoute, installationsRoute,
  componentDefinitionsRoute,
  featuresRoute, routesRoute, upstreamsRoute, modelsPricingRoute, secretsRoute, configurationRoute,
  accessPoliciesRoute, limitPlansRoute, userOverridesRoute, abuseControlsRoute,
  requestsRoute, usageRoute, costRoute, performanceRoute, reliabilityRoute, ...legacyAnalyticsRoutes,
  configurationRevisionsRoute, routeSimulatorRoute, selfTestsRoute, auditRoute,
  systemHealthRoute, settingsRoute
]);

interface CreateAppRouterOptions {
  history?: ReturnType<typeof createMemoryHistory>;
}

export function createAppRouter(options: CreateAppRouterOptions = {}) {
  return createRouter({
    defaultPreload: "intent",
    defaultPreloadStaleTime: 0,
    routeTree,
    ...(options.history ? { history: options.history } : {})
  });
}

export type AppRouter = ReturnType<typeof createAppRouter>;

declare module "@tanstack/react-router" {
  interface Register {
    router: AppRouter;
  }
}

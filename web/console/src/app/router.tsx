import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter
} from "@tanstack/react-router";

import { AppShell } from "./app-shell";
import { NotFoundPage } from "../pages/not-found-page";
import { OverviewPage } from "../pages/overview-page";
import { SystemHealthPage } from "../pages/system-health-page";
import { SettingsPage } from "../pages/settings-page";
import { AdministratorsPage } from "../pages/administrators-page";
import { APITokensPage } from "../pages/api-tokens-page";
import { InstallationFamiliesPage } from "../pages/installation-families-page";
import {
  AttestationFailuresPage,
  AuditPageView,
  CostPage,
  ErrorsPage,
  InstallationsPage,
  LatencyPage,
  RequestsPage,
  RouteSimulatorPage,
  SelfTestsPage,
  UsagePage,
  UsersPage
} from "../pages/control-plane-pages";
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
const usageRoute = createRoute({ component: UsagePage, getParentRoute: () => rootRoute, path: "/usage", validateSearch: parseAnalyticsRouteSearch });
const costRoute = createRoute({ component: CostPage, getParentRoute: () => rootRoute, path: "/cost", validateSearch: parseAnalyticsRouteSearch });
const latencyRoute = createRoute({ component: LatencyPage, getParentRoute: () => rootRoute, path: "/latency", validateSearch: parseAnalyticsRouteSearch });
const errorsRoute = createRoute({ component: ErrorsPage, getParentRoute: () => rootRoute, path: "/errors", validateSearch: parseAnalyticsRouteSearch });
const attestationFailuresRoute = createRoute({ component: AttestationFailuresPage, getParentRoute: () => rootRoute, path: "/attestation-failures", validateSearch: parseAnalyticsRouteSearch });
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
  requestsRoute, usageRoute, costRoute, latencyRoute, errorsRoute, attestationFailuresRoute,
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

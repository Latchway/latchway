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
import { AdministratorsPage } from "../pages/administrators-page";
import { APITokensPage } from "../pages/api-tokens-page";
import {
  AuditPageView,
  InstallationsPage,
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

const setupRoute = createRoute({ component: SetupWizardPage, getParentRoute: () => rootRoute, path: "/setup" });
const configurationRoute = createRoute({ component: ConfigurationEditorPage, getParentRoute: () => rootRoute, path: "/configuration" });
const applicationsRoute = createRoute({ component: ApplicationsPage, getParentRoute: () => rootRoute, path: "/applications" });
const environmentsRoute = createRoute({ component: EnvironmentsPage, getParentRoute: () => rootRoute, path: "/environments" });
const administratorsRoute = createRoute({ component: AdministratorsPage, getParentRoute: () => rootRoute, path: "/administrators" });
const apiTokensRoute = createRoute({ component: APITokensPage, getParentRoute: () => rootRoute, path: "/api-tokens" });
const authenticationProvidersRoute = createRoute({ component: AuthenticationProvidersPage, getParentRoute: () => rootRoute, path: "/authentication-providers" });
const attestationRoute = createRoute({ component: AttestationConfigurationPage, getParentRoute: () => rootRoute, path: "/attestation" });
const usersRoute = createRoute({ component: UsersPage, getParentRoute: () => rootRoute, path: "/users" });
const installationsRoute = createRoute({ component: InstallationsPage, getParentRoute: () => rootRoute, path: "/installations" });
const featuresRoute = createRoute({ component: FeaturesConfigurationPage, getParentRoute: () => rootRoute, path: "/features" });
const routesRoute = createRoute({ component: RoutesConfigurationPage, getParentRoute: () => rootRoute, path: "/routes" });
const upstreamsRoute = createRoute({ component: UpstreamsConfigurationPage, getParentRoute: () => rootRoute, path: "/upstreams" });
const modelsPricingRoute = createRoute({ component: ModelsPricingConfigurationPage, getParentRoute: () => rootRoute, path: "/models-pricing" });
const secretsRoute = createRoute({ component: SecretsPage, getParentRoute: () => rootRoute, path: "/secrets" });
const accessPoliciesRoute = createRoute({ component: AccessPoliciesConfigurationPage, getParentRoute: () => rootRoute, path: "/access-policies" });
const limitPlansRoute = createRoute({ component: LimitPlansConfigurationPage, getParentRoute: () => rootRoute, path: "/limit-plans" });
const userOverridesRoute = createRoute({ component: UserOverridesPage, getParentRoute: () => rootRoute, path: "/user-overrides" });
const abuseControlsRoute = createRoute({ component: AbuseControlsConfigurationPage, getParentRoute: () => rootRoute, path: "/abuse-controls" });
const requestsRoute = createRoute({ component: RequestsPage, getParentRoute: () => rootRoute, path: "/requests" });
const usageRoute = createRoute({ component: UsagePage, getParentRoute: () => rootRoute, path: "/usage" });
const costRoute = createRoute({ component: UsagePage, getParentRoute: () => rootRoute, path: "/cost" });
const latencyRoute = createRoute({ component: UsagePage, getParentRoute: () => rootRoute, path: "/latency" });
const errorsRoute = createRoute({ component: UsagePage, getParentRoute: () => rootRoute, path: "/errors" });
const attestationFailuresRoute = createRoute({ component: UsagePage, getParentRoute: () => rootRoute, path: "/attestation-failures" });
const configurationRevisionsRoute = createRoute({ component: ConfigurationRevisionsPage, getParentRoute: () => rootRoute, path: "/configuration-revisions" });
const routeSimulatorRoute = createRoute({ component: RouteSimulatorPage, getParentRoute: () => rootRoute, path: "/route-simulator" });
const selfTestsRoute = createRoute({ component: SelfTestsPage, getParentRoute: () => rootRoute, path: "/self-tests" });
const auditRoute = createRoute({ component: AuditPageView, getParentRoute: () => rootRoute, path: "/audit" });

const routeTree = rootRoute.addChildren([
  indexRoute, applicationsRoute, environmentsRoute, setupRoute, administratorsRoute, apiTokensRoute,
  authenticationProvidersRoute, attestationRoute, usersRoute, installationsRoute,
  featuresRoute, routesRoute, upstreamsRoute, modelsPricingRoute, secretsRoute, configurationRoute,
  accessPoliciesRoute, limitPlansRoute, userOverridesRoute, abuseControlsRoute,
  requestsRoute, usageRoute, costRoute, latencyRoute, errorsRoute, attestationFailuresRoute,
  configurationRevisionsRoute, routeSimulatorRoute, selfTestsRoute, auditRoute,
  systemHealthRoute
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

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
import { SystemHealthPage } from "../pages/operate/system-health-page";
import { SelfTestsPage } from "../pages/operate/self-tests-page";
import { ApplicationsSettingsPage, GeneralSettingsPage } from "../pages/settings/settings-pages";
import { AuditLogPage } from "../pages/audit/audit-page";
import { SecretsPage } from "../pages/build/secrets-page";
import { MembersPage, RolesPage, SessionsPage, TokensPage } from "../pages/team/team-pages";
import { ComparePage, DraftChangesPage, JsonEditorPage, RevisionHistoryPage } from "../pages/changes/changes-pages";
import { LimitPlansPage, OverridesPage, PlanByFeaturePage, ProtectionsPage } from "../pages/policies/policies-pages";
import { SimulatorPage } from "../pages/simulator/simulator-page";
import { RequestsPage } from "../pages/requests/requests-page";
import { SessionsPolicyPage } from "../pages/build/client-trust-pages";
import { InstallationFamiliesPage } from "../pages/users/installations-page";
import { InstallationsPage } from "../pages/users/older-installs-page";
import { UsersPage } from "../pages/users/users-page";
import {
  CostAnalyticsPage,
  PerformanceAnalyticsPage,
  ReliabilityAnalyticsPage,
  UsageAnalyticsPage
} from "../pages/analytics/analytics-page";
import { SetupWizardPage } from "../pages/configuration-pages";
import {
  AttestationConfigurationPage,
  AuthenticationProvidersPage,
  ComponentDefinitionsConfigurationPage,
  FeaturesConfigurationPage,
  ModelsPricingConfigurationPage,
  RoutesConfigurationPage,
  UpstreamsConfigurationPage
} from "../pages/configuration-area-pages";
import {
  AnalyticsRouteSearchSchema,
  parseAnalyticsRouteSearch,
  parseConfigurationRouteSearch,
  parseAuditRouteSearch,
  parseCompareRouteSearch,
  parseFeatureRouteSearch,
  parseInstallationFamilyRouteSearch,
  parseInstallationRouteSearch,
  parseLimitPlanRouteSearch,
  parseOverrideRouteSearch,
  parsePlanByFeatureRouteSearch,
  parseRequestRouteSearch,
  parseRevisionRouteSearch,
  parseRouteSimulatorRouteSearch,
  parseSelfTestRouteSearch,
  parseTeamRouteSearch,
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
const settingsRoute = createRoute({ component: GeneralSettingsPage, getParentRoute: () => rootRoute, path: "/settings" });

const setupRoute = createRoute({ component: SetupWizardPage, getParentRoute: () => rootRoute, path: "/setup" });
const configurationRoute = createRoute({ component: JsonEditorPage, getParentRoute: () => rootRoute, path: "/configuration", validateSearch: parseConfigurationRouteSearch });
const applicationsRoute = createRoute({ component: ApplicationsSettingsPage, getParentRoute: () => rootRoute, path: "/applications" });
/** Environments are managed inside each application's card under Settings → Applications. */
const environmentsRoute = createRoute({
  beforeLoad: ({ search }) => {
    const previous = search as Record<string, unknown>;
    throw redirect({ replace: true, search: parseFeatureRouteSearch({ application: previous.application, environment: previous.environment, organization: previous.organization }), to: "/applications" });
  },
  getParentRoute: () => rootRoute,
  path: "/environments"
});
const administratorsRoute = createRoute({ component: MembersPage, getParentRoute: () => rootRoute, path: "/administrators", validateSearch: parseTeamRouteSearch });
const adminSessionsRoute = createRoute({ component: SessionsPage, getParentRoute: () => rootRoute, path: "/admin-sessions" });
const rolesRoute = createRoute({ component: RolesPage, getParentRoute: () => rootRoute, path: "/roles" });
const apiTokensRoute = createRoute({ component: TokensPage, getParentRoute: () => rootRoute, path: "/api-tokens" });
const authenticationProvidersRoute = createRoute({ component: AuthenticationProvidersPage, getParentRoute: () => rootRoute, path: "/authentication-providers", validateSearch: parseConfigurationRouteSearch });
const attestationRoute = createRoute({ component: AttestationConfigurationPage, getParentRoute: () => rootRoute, path: "/attestation" });
const usersRoute = createRoute({ component: UsersPage, getParentRoute: () => rootRoute, path: "/users", validateSearch: parseUserRouteSearch });
const installationsRoute = createRoute({ component: InstallationsPage, getParentRoute: () => rootRoute, path: "/installations", validateSearch: parseInstallationRouteSearch });
const installationFamiliesRoute = createRoute({ component: InstallationFamiliesPage, getParentRoute: () => rootRoute, path: "/installation-families", validateSearch: parseInstallationFamilyRouteSearch });
const clientSessionsRoute = createRoute({ component: SessionsPolicyPage, getParentRoute: () => rootRoute, path: "/client-sessions" });
const componentDefinitionsRoute = createRoute({ component: ComponentDefinitionsConfigurationPage, getParentRoute: () => rootRoute, path: "/component-definitions", validateSearch: parseConfigurationRouteSearch });
const featuresRoute = createRoute({ component: FeaturesConfigurationPage, getParentRoute: () => rootRoute, path: "/features", validateSearch: parseFeatureRouteSearch });
const routesRoute = createRoute({ component: RoutesConfigurationPage, getParentRoute: () => rootRoute, path: "/routes", validateSearch: parseConfigurationRouteSearch });
const upstreamsRoute = createRoute({ component: UpstreamsConfigurationPage, getParentRoute: () => rootRoute, path: "/upstreams" });
const modelsPricingRoute = createRoute({ component: ModelsPricingConfigurationPage, getParentRoute: () => rootRoute, path: "/models-pricing", validateSearch: parseConfigurationRouteSearch });
const secretsRoute = createRoute({ component: SecretsPage, getParentRoute: () => rootRoute, path: "/secrets" });
const limitPlansRoute = createRoute({ component: LimitPlansPage, getParentRoute: () => rootRoute, path: "/limit-plans", validateSearch: parseLimitPlanRouteSearch });
const planByFeatureRoute = createRoute({ component: PlanByFeaturePage, getParentRoute: () => rootRoute, path: "/plan-by-feature", validateSearch: parsePlanByFeatureRouteSearch });
const userOverridesRoute = createRoute({ component: OverridesPage, getParentRoute: () => rootRoute, path: "/user-overrides", validateSearch: parseOverrideRouteSearch });
const protectionsRoute = createRoute({ component: ProtectionsPage, getParentRoute: () => rootRoute, path: "/protections" });
/** Access is edited on each feature's Access & limits tab; protective limits moved to Protections. */
function legacyScopeRoute(path: string, to: "/features" | "/protections") {
  return createRoute({
    beforeLoad: ({ search }) => {
      const previous = search as Record<string, unknown>;
      throw redirect({ replace: true, search: parseFeatureRouteSearch({ application: previous.application, environment: previous.environment, organization: previous.organization }), to });
    },
    getParentRoute: () => rootRoute,
    path
  });
}
const legacyPolicyRoutes = [legacyScopeRoute("/access-policies", "/features"), legacyScopeRoute("/abuse-controls", "/protections")];
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
const changesRoute = createRoute({ component: DraftChangesPage, getParentRoute: () => rootRoute, path: "/changes" });
const configurationRevisionsRoute = createRoute({ component: RevisionHistoryPage, getParentRoute: () => rootRoute, path: "/configuration-revisions", validateSearch: parseRevisionRouteSearch });
const configurationCompareRoute = createRoute({ component: ComparePage, getParentRoute: () => rootRoute, path: "/configuration-compare", validateSearch: parseCompareRouteSearch });
const routeSimulatorRoute = createRoute({ component: SimulatorPage, getParentRoute: () => rootRoute, path: "/route-simulator", validateSearch: parseRouteSimulatorRouteSearch });
const selfTestsRoute = createRoute({ component: SelfTestsPage, getParentRoute: () => rootRoute, path: "/self-tests", validateSearch: parseSelfTestRouteSearch });
const auditRoute = createRoute({
  component: AuditLogPage,
  getParentRoute: () => rootRoute,
  path: "/audit",
  validateSearch: parseAuditRouteSearch
});

const routeTree = rootRoute.addChildren([
  indexRoute, applicationsRoute, environmentsRoute, setupRoute, administratorsRoute, apiTokensRoute, adminSessionsRoute, rolesRoute,
  authenticationProvidersRoute, attestationRoute, usersRoute, installationFamiliesRoute, installationsRoute,
  componentDefinitionsRoute, clientSessionsRoute,
  featuresRoute, routesRoute, upstreamsRoute, modelsPricingRoute, secretsRoute, configurationRoute,
  limitPlansRoute, planByFeatureRoute, userOverridesRoute, protectionsRoute, ...legacyPolicyRoutes,
  requestsRoute, usageRoute, costRoute, performanceRoute, reliabilityRoute, ...legacyAnalyticsRoutes,
  changesRoute, configurationRevisionsRoute, configurationCompareRoute, routeSimulatorRoute, selfTestsRoute, auditRoute,
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

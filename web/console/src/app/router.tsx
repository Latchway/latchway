import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  redirect
} from "@tanstack/react-router";

import { AppShell } from "./app-shell";
import { NotFoundPage } from "../pages/not-found-page";
import { OverviewPage } from "../pages/overview-page";
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

// Pages load on first visit so the sign-in screen and shell stay small.
const SystemHealthPage = lazyRouteComponent(() => import("../pages/operate/system-health-page"), "SystemHealthPage");
const SelfTestsPage = lazyRouteComponent(() => import("../pages/operate/self-tests-page"), "SelfTestsPage");
const ApplicationsSettingsPage = lazyRouteComponent(() => import("../pages/settings/settings-pages"), "ApplicationsSettingsPage");
const GeneralSettingsPage = lazyRouteComponent(() => import("../pages/settings/settings-pages"), "GeneralSettingsPage");
const AuditLogPage = lazyRouteComponent(() => import("../pages/audit/audit-page"), "AuditLogPage");
const SecretsPage = lazyRouteComponent(() => import("../pages/build/secrets-page"), "SecretsPage");
const MembersPage = lazyRouteComponent(() => import("../pages/team/team-pages"), "MembersPage");
const RolesPage = lazyRouteComponent(() => import("../pages/team/team-pages"), "RolesPage");
const SessionsPage = lazyRouteComponent(() => import("../pages/team/team-pages"), "SessionsPage");
const TokensPage = lazyRouteComponent(() => import("../pages/team/team-pages"), "TokensPage");
const ComparePage = lazyRouteComponent(() => import("../pages/changes/changes-pages"), "ComparePage");
const DraftChangesPage = lazyRouteComponent(() => import("../pages/changes/changes-pages"), "DraftChangesPage");
const JsonEditorPage = lazyRouteComponent(() => import("../pages/changes/changes-pages"), "JsonEditorPage");
const RevisionHistoryPage = lazyRouteComponent(() => import("../pages/changes/changes-pages"), "RevisionHistoryPage");
const LimitPlansPage = lazyRouteComponent(() => import("../pages/policies/policies-pages"), "LimitPlansPage");
const OverridesPage = lazyRouteComponent(() => import("../pages/policies/policies-pages"), "OverridesPage");
const PlanByFeaturePage = lazyRouteComponent(() => import("../pages/policies/policies-pages"), "PlanByFeaturePage");
const ProtectionsPage = lazyRouteComponent(() => import("../pages/policies/policies-pages"), "ProtectionsPage");
const SimulatorPage = lazyRouteComponent(() => import("../pages/simulator/simulator-page"), "SimulatorPage");
const RequestsPage = lazyRouteComponent(() => import("../pages/requests/requests-page"), "RequestsPage");
const SessionsPolicyPage = lazyRouteComponent(() => import("../pages/build/client-trust-pages"), "SessionsPolicyPage");
const InstallationFamiliesPage = lazyRouteComponent(() => import("../pages/users/installations-page"), "InstallationFamiliesPage");
const InstallationsPage = lazyRouteComponent(() => import("../pages/users/older-installs-page"), "InstallationsPage");
const UsersPage = lazyRouteComponent(() => import("../pages/users/users-page"), "UsersPage");
const CostAnalyticsPage = lazyRouteComponent(() => import("../pages/analytics/analytics-page"), "CostAnalyticsPage");
const PerformanceAnalyticsPage = lazyRouteComponent(() => import("../pages/analytics/analytics-page"), "PerformanceAnalyticsPage");
const ReliabilityAnalyticsPage = lazyRouteComponent(() => import("../pages/analytics/analytics-page"), "ReliabilityAnalyticsPage");
const UsageAnalyticsPage = lazyRouteComponent(() => import("../pages/analytics/analytics-page"), "UsageAnalyticsPage");
const SetupWizardPage = lazyRouteComponent(() => import("../pages/configuration-pages"), "SetupWizardPage");
const AttestationConfigurationPage = lazyRouteComponent(() => import("../pages/configuration-area-pages"), "AttestationConfigurationPage");
const AuthenticationProvidersPage = lazyRouteComponent(() => import("../pages/configuration-area-pages"), "AuthenticationProvidersPage");
const ComponentDefinitionsConfigurationPage = lazyRouteComponent(() => import("../pages/configuration-area-pages"), "ComponentDefinitionsConfigurationPage");
const FeaturesConfigurationPage = lazyRouteComponent(() => import("../pages/configuration-area-pages"), "FeaturesConfigurationPage");
const ModelsPricingConfigurationPage = lazyRouteComponent(() => import("../pages/configuration-area-pages"), "ModelsPricingConfigurationPage");
const RoutesConfigurationPage = lazyRouteComponent(() => import("../pages/configuration-area-pages"), "RoutesConfigurationPage");
const UpstreamsConfigurationPage = lazyRouteComponent(() => import("../pages/configuration-area-pages"), "UpstreamsConfigurationPage");

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

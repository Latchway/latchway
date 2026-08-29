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
const administratorsRoute = createRoute({ component: AdministratorsPage, getParentRoute: () => rootRoute, path: "/administrators" });
const apiTokensRoute = createRoute({ component: APITokensPage, getParentRoute: () => rootRoute, path: "/api-tokens" });
const usersRoute = createRoute({ component: UsersPage, getParentRoute: () => rootRoute, path: "/users" });
const installationsRoute = createRoute({ component: InstallationsPage, getParentRoute: () => rootRoute, path: "/installations" });
const requestsRoute = createRoute({ component: RequestsPage, getParentRoute: () => rootRoute, path: "/requests" });
const usageRoute = createRoute({ component: UsagePage, getParentRoute: () => rootRoute, path: "/usage" });
const routeSimulatorRoute = createRoute({ component: RouteSimulatorPage, getParentRoute: () => rootRoute, path: "/route-simulator" });
const selfTestsRoute = createRoute({ component: SelfTestsPage, getParentRoute: () => rootRoute, path: "/self-tests" });
const auditRoute = createRoute({ component: AuditPageView, getParentRoute: () => rootRoute, path: "/audit" });

const routeTree = rootRoute.addChildren([
  indexRoute, setupRoute, configurationRoute, administratorsRoute, apiTokensRoute, usersRoute, installationsRoute,
  requestsRoute, usageRoute, routeSimulatorRoute, selfTestsRoute, auditRoute,
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

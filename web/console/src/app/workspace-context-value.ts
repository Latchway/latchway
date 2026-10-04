import { createContext, useContext } from "react";

import type {
  ApplicationResource,
  EnvironmentResource,
  OrganizationResource
} from "../api/resources";
import type {
  AnalyticsRouteSearch,
  AuditRouteSearch,
  CompareRouteSearch,
  ConfigurationRouteSearch,
  FeatureRouteSearch,
  InstallationFamilyRouteSearch,
  InstallationRouteSearch,
  LimitPlanRouteSearch,
  OverrideRouteSearch,
  PlanByFeatureRouteSearch,
  RequestRouteSearch,
  RevisionRouteSearch,
  RouteSimulatorRouteSearch,
  SelfTestRouteSearch,
  UserRouteSearch
} from "./route-search";

export interface WorkspaceSearch extends
  Partial<AnalyticsRouteSearch>,
  Partial<AuditRouteSearch>,
  Partial<CompareRouteSearch>,
  Partial<ConfigurationRouteSearch>,
  Partial<FeatureRouteSearch>,
  Partial<InstallationFamilyRouteSearch>,
  Partial<InstallationRouteSearch>,
  Partial<LimitPlanRouteSearch>,
  Partial<OverrideRouteSearch>,
  Partial<PlanByFeatureRouteSearch>,
  Partial<RequestRouteSearch>,
  Partial<RevisionRouteSearch>,
  Partial<RouteSimulatorRouteSearch>,
  Partial<SelfTestRouteSearch>,
  Partial<UserRouteSearch> {
  application?: string;
  environment?: string;
  organization?: string;
}

export interface WorkspaceContextValue {
  application?: ApplicationResource;
  applications: ApplicationResource[];
  environment?: EnvironmentResource;
  environments: EnvironmentResource[];
  invalidApplication: boolean;
  invalidEnvironment: boolean;
  isLoading: boolean;
  organization?: OrganizationResource;
  search: WorkspaceSearch;
  selectApplication: (slug: string) => void;
  selectEnvironment: (slug: string) => void;
  updateSearch: (patch: Partial<WorkspaceSearch>, options?: { replace?: boolean }) => void;
}

export const WorkspaceContext = createContext<WorkspaceContextValue | undefined>(undefined);

export function useOptionalWorkspace(): WorkspaceContextValue | undefined {
  return useContext(WorkspaceContext);
}

export function useWorkspace(): WorkspaceContextValue {
  const workspace = useOptionalWorkspace();
  if (!workspace) throw new Error("Workspace context is unavailable.");
  return workspace;
}

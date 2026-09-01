import { createContext, useContext } from "react";

import type {
  ApplicationResource,
  EnvironmentResource,
  OrganizationResource
} from "../api/resources";
import type {
  AnalyticsRouteSearch,
  AuditRouteSearch,
  ConfigurationRouteSearch,
  FeatureRouteSearch,
  InstallationFamilyRouteSearch,
  InstallationRouteSearch,
  RequestRouteSearch,
  RouteSimulatorRouteSearch,
  SelfTestRouteSearch,
  UserRouteSearch
} from "./route-search";

export interface WorkspaceSearch extends
  Partial<AnalyticsRouteSearch>,
  Partial<AuditRouteSearch>,
  Partial<ConfigurationRouteSearch>,
  Partial<FeatureRouteSearch>,
  Partial<InstallationFamilyRouteSearch>,
  Partial<InstallationRouteSearch>,
  Partial<RequestRouteSearch>,
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

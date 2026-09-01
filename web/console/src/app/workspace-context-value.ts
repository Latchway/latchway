import { createContext, useContext } from "react";

import type {
  ApplicationResource,
  EnvironmentResource,
  OrganizationResource
} from "../api/resources";
import type { AuditRouteSearch, RequestRouteSearch } from "./route-search";

export interface WorkspaceSearch extends Partial<AuditRouteSearch>, Partial<RequestRouteSearch> {
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
  updateSearch: (patch: Partial<WorkspaceSearch>) => void;
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

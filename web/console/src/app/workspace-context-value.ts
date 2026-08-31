import { createContext, useContext } from "react";

import type {
  ApplicationResource,
  EnvironmentResource,
  OrganizationResource
} from "../api/resources";

export interface WorkspaceSearch {
  application?: string;
  environment?: string;
  organization?: string;
  [key: string]: unknown;
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
  updateSearch: (patch: Record<string, string | undefined>) => void;
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

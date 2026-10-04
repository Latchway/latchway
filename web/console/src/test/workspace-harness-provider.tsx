import { type ReactNode, useState } from "react";
import { vi } from "vitest";

import { WorkspaceContext, type WorkspaceContextValue, type WorkspaceSearch } from "../app/workspace-context-value";
import { ids, instant } from "./workspace-fixtures";

export interface HarnessOptions {
  applicationStatus?: "active" | "disabled";
  environmentStatus?: "active" | "disabled";
  initial?: WorkspaceSearch;
  searchLog?: WorkspaceSearch[];
}

function workspaceValue(search: WorkspaceSearch, updateSearch: WorkspaceContextValue["updateSearch"], options: HarnessOptions): WorkspaceContextValue {
  const organization = { created_at: instant, display_name: "Example", id: ids.organization, slug: "example" };
  const application = { created_at: instant, display_name: "Mobile", id: ids.application, organization_id: organization.id, slug: "mobile", status: options.applicationStatus ?? "active" };
  const production = { active_revision_id: ids.activeRevision, application_id: application.id, created_at: instant, display_name: "Production", id: ids.environment, kind: "production" as const, slug: "production", status: options.environmentStatus ?? "active" };
  const staging = { application_id: application.id, created_at: instant, display_name: "Staging", id: ids.stagingEnvironment, kind: "staging" as const, slug: "staging", status: "active" as const };
  return { application, applications: [application], environment: production, environments: [production, staging], invalidApplication: false, invalidEnvironment: false, isLoading: false, organization, search, selectApplication: vi.fn(), selectEnvironment: vi.fn(), updateSearch };
}

/** A workspace whose URL updates apply immediately, for page tests. */
export function WorkspaceHarness({ children, options }: { children: ReactNode; options: HarnessOptions }) {
  const [search, setSearch] = useState<WorkspaceSearch>(options.initial ?? {});
  const updateSearch: WorkspaceContextValue["updateSearch"] = (patch) => {
    options.searchLog?.push(patch as WorkspaceSearch);
    setSearch((current) => ({ ...current, ...patch }));
  };
  return <WorkspaceContext.Provider value={workspaceValue(search, updateSearch, options)}>{children}</WorkspaceContext.Provider>;
}


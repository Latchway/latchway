import { queryOptions } from "@tanstack/react-query";

import { adminRequest, queryPath } from "./admin";
import {
  ApplicationResourcePageSchema,
  ConfigurationRevisionResourcePageSchema,
  EnvironmentResourceListSchema,
  OrganizationResourcePageSchema
} from "./resources";

export function organizationsQueryOptions() {
  return queryOptions({
    queryFn: async () =>
      (await adminRequest(queryPath("/admin/v1/organizations", { page_size: "200" }), OrganizationResourcePageSchema)).data,
    queryKey: ["organizations", "workspace-switcher"] as const,
    staleTime: 30_000
  });
}

export function applicationsQueryOptions(organizationID: string) {
  return queryOptions({
    enabled: Boolean(organizationID),
    queryFn: async () =>
      (await adminRequest(queryPath("/admin/v1/applications", {
        organization_id: organizationID,
        page_size: "200"
      }), ApplicationResourcePageSchema)).data,
    queryKey: ["organization", organizationID, "applications", "workspace-switcher"] as const,
    staleTime: 30_000
  });
}

export function environmentsQueryOptions(applicationID: string) {
  return queryOptions({
    enabled: Boolean(applicationID),
    queryFn: async () =>
      (await adminRequest(`/admin/v1/applications/${applicationID}/environments`, EnvironmentResourceListSchema)).data,
    queryKey: ["application", applicationID, "environments", "workspace-switcher"] as const,
    staleTime: 30_000
  });
}

export function latestConfigurationRevisionQueryOptions(environmentID: string) {
  return queryOptions({
    enabled: Boolean(environmentID),
    queryFn: async () =>
      (await adminRequest(queryPath(`/admin/v1/environments/${environmentID}/config-revisions`, {
        page_size: "1"
      }), ConfigurationRevisionResourcePageSchema)).data,
    queryKey: ["environment", environmentID, "configuration-revisions", "latest"] as const,
    retry: false,
    staleTime: 15_000
  });
}

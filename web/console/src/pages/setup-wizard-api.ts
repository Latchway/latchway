import {
  adminRequest,
  ApplicationSchema,
  ConfigurationPlanSchema,
  EnvironmentSchema,
  queryPath,
  RevisionSchema,
  ValidationSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation
} from "../api/admin";
import { problemFromError } from "../api/auth";
import {
  ApplicationResourcePageSchema,
  ConfigurationRevisionResourcePageSchema,
  EnvironmentResourceListSchema
} from "../api/resources";
import { canonicalConfigurationJSON } from "./setup-wizard-state";

export async function createValidateActivate(input: {
  document: unknown;
  environmentID: string;
  activate: boolean;
}): Promise<{ revision: ConfigurationRevision; report: ConfigurationValidation; plan?: ConfigurationPlan }> {
  const latestPage = (await adminRequest(
    queryPath(`/admin/v1/environments/${input.environmentID}/config-revisions`, { page_size: "1" }),
    ConfigurationRevisionResourcePageSchema
  )).data;
  const latest = latestPage.items[0];
  const reusable = latest && canonicalConfigurationJSON(latest.document) === canonicalConfigurationJSON(input.document)
    && latest.state !== "superseded";
  if (reusable && latest.state === "active") {
    if (!latest.validation) throw new Error("The active configuration omitted its validation report.");
    return { revision: latest, report: latest.validation };
  }

  const candidate = reusable
    ? (await adminRequest(`/admin/v1/config-revisions/${latest.id}`, RevisionSchema)).data
    : (await adminRequest(`/admin/v1/environments/${input.environmentID}/config-revisions`, RevisionSchema, {
      method: "POST", body: { document: input.document, description: "Admin console resumable full-document apply" }
    })).data;
  const report = (await adminRequest(`/admin/v1/config-revisions/${candidate.id}/validate`, ValidationSchema, { method: "POST" })).data;
  let plan: ConfigurationPlan | undefined;
  if (report.valid) {
    try { plan = (await adminRequest(`/admin/v1/config-revisions/${candidate.id}/plan`, ConfigurationPlanSchema, { method: "POST" })).data; }
    catch (error) { if (problemFromError(error).code !== "resource_not_found") throw error; }
  }
  if (!report.valid || !input.activate) return { revision: candidate, report, ...(plan ? { plan } : {}) };
  const current = await adminRequest(`/admin/v1/config-revisions/${candidate.id}`, RevisionSchema);
  if (!current.etag) throw new Error("The Admin API omitted the activation ETag.");
  const activated = await adminRequest(`/admin/v1/config-revisions/${candidate.id}/activate`, RevisionSchema, { method: "POST", etag: current.etag });
  return { revision: activated.data, report, ...(plan ? { plan } : {}) };
}

export async function findApplication(organizationID: string, slug: string) {
  let cursor: string | undefined;
  for (let page = 0; page < 100; page += 1) {
    const response = (await adminRequest(queryPath("/admin/v1/applications", {
      organization_id: organizationID,
      page_size: "200",
      ...(cursor ? { cursor } : {})
    }), ApplicationResourcePageSchema)).data;
    const match = response.items.find((application) => application.slug === slug);
    if (match) return match;
    if (!response.page.has_more) return undefined;
    if (!response.page.next_cursor || response.page.next_cursor === cursor) throw new Error("application_list_cursor_invalid");
    cursor = response.page.next_cursor;
  }
  throw new Error("application_list_too_large");
}

export async function findOrCreateApplication(input: { displayName: string; organizationID: string; slug: string }) {
  const existing = await findApplication(input.organizationID, input.slug);
  if (existing) {
    if (existing.display_name !== input.displayName) throw new Error("application_slug_in_use");
    return existing;
  }
  try {
    return (await adminRequest("/admin/v1/applications", ApplicationSchema, { method: "POST", body: {
      organization_id: input.organizationID, slug: input.slug, display_name: input.displayName
    } })).data;
  } catch (error) {
    if (problemFromError(error).code !== "conflict") throw error;
    const reconciled = await findApplication(input.organizationID, input.slug);
    if (!reconciled || reconciled.display_name !== input.displayName) throw error;
    return reconciled;
  }
}

export async function findOrCreateEnvironment(input: { applicationID: string; displayName: string; kind: "development" | "staging" | "production"; slug: string }) {
  const find = async () => (await adminRequest(
    `/admin/v1/applications/${input.applicationID}/environments`, EnvironmentResourceListSchema
  )).data.items.find((environment) => environment.slug === input.slug);
  const existing = await find();
  if (existing) {
    if (existing.display_name !== input.displayName || existing.kind !== input.kind) throw new Error("environment_slug_in_use");
    return existing;
  }
  try {
    return (await adminRequest(`/admin/v1/applications/${input.applicationID}/environments`, EnvironmentSchema, {
      method: "POST", body: { slug: input.slug, display_name: input.displayName, kind: input.kind }
    })).data;
  } catch (error) {
    if (problemFromError(error).code !== "conflict") throw error;
    const reconciled = await find();
    if (!reconciled || reconciled.display_name !== input.displayName || reconciled.kind !== input.kind) throw error;
    return reconciled;
  }
}

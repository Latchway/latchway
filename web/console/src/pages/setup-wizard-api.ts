import {
  adminRequest,
  ConfigurationPlanSchema,
  queryPath,
  RevisionSchema,
  ValidationSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation
} from "../api/admin";
import { problemFromError } from "../api/auth";
import {
  ApplicationResourceSchema,
  ApplicationResourcePageSchema,
  ConfigurationRevisionResourcePageSchema,
  EnvironmentResourceSchema,
  EnvironmentResourceListSchema,
  type ApplicationResource,
  type EnvironmentResource
} from "../api/resources";
import { canonicalConfigurationJSON } from "./setup-wizard-state";

function requireApplicationParent(application: ApplicationResource, organizationID: string): void {
  if (application.organization_id !== organizationID) throw new Error("application_context_mismatch");
}

function requireExactApplication(
  application: ApplicationResource,
  input: { displayName: string; organizationID: string; slug: string }
): void {
  if (
    application.organization_id !== input.organizationID
    || application.slug !== input.slug
    || application.display_name !== input.displayName
  ) throw new Error("application_context_mismatch");
}

function requireEnvironmentParent(environment: EnvironmentResource, applicationID: string): void {
  if (environment.application_id !== applicationID) throw new Error("environment_context_mismatch");
}

function requireExactEnvironment(
  environment: EnvironmentResource,
  input: { applicationID: string; displayName: string; kind: "development" | "staging" | "production"; slug: string }
): void {
  if (
    environment.application_id !== input.applicationID
    || environment.slug !== input.slug
    || environment.display_name !== input.displayName
    || environment.kind !== input.kind
  ) throw new Error("environment_context_mismatch");
}

function requireRevisionBinding(
  revision: ConfigurationRevision,
  input: { canonicalDocument?: string; environmentID: string; revisionID?: string }
): void {
  if (
    !/^rev_[A-Za-z0-9_-]{16,128}$/.test(revision.id)
    || revision.environment_id !== input.environmentID
    || (input.revisionID !== undefined && revision.id !== input.revisionID)
    || (input.canonicalDocument !== undefined && canonicalConfigurationJSON(revision.document) !== input.canonicalDocument)
  ) throw new Error("configuration_revision_context_mismatch");
}

export async function createValidateActivate(input: {
  document: unknown;
  environmentID: string;
  activate: boolean;
}): Promise<{ revision: ConfigurationRevision; report: ConfigurationValidation; plan?: ConfigurationPlan }> {
  const canonicalDocument = canonicalConfigurationJSON(input.document);
  const latestPage = (await adminRequest(
    queryPath(`/admin/v1/environments/${input.environmentID}/config-revisions`, { page_size: "1" }),
    ConfigurationRevisionResourcePageSchema
  )).data;
  for (const revision of latestPage.items) {
    requireRevisionBinding(revision, { environmentID: input.environmentID });
  }
  const latest = latestPage.items[0];
  const reusable = latest && canonicalConfigurationJSON(latest.document) === canonicalDocument
    && latest.state !== "superseded";
  if (reusable && latest.state === "active") {
    if (!latest.validation?.valid) throw new Error("The active configuration omitted its valid validation report.");
    return { revision: latest, report: latest.validation };
  }

  const candidateResponse = reusable
    ? (await adminRequest(`/admin/v1/config-revisions/${latest.id}`, RevisionSchema)).data
    : (await adminRequest(`/admin/v1/environments/${input.environmentID}/config-revisions`, RevisionSchema, {
      method: "POST", body: { document: input.document, description: "Admin console resumable full-document apply" }
    })).data;
  requireRevisionBinding(candidateResponse, {
    canonicalDocument,
    environmentID: input.environmentID,
    ...(reusable ? { revisionID: latest.id } : {})
  });
  const candidate = candidateResponse;
  const report = (await adminRequest(`/admin/v1/config-revisions/${candidate.id}/validate`, ValidationSchema, { method: "POST" })).data;
  let plan: ConfigurationPlan | undefined;
  if (report.valid) {
    try { plan = (await adminRequest(`/admin/v1/config-revisions/${candidate.id}/plan`, ConfigurationPlanSchema, { method: "POST" })).data; }
    catch (error) { if (problemFromError(error).code !== "resource_not_found") throw error; }
    if (plan && plan.to_revision_id !== candidate.id) throw new Error("configuration_plan_context_mismatch");
  }
  if (!report.valid || !input.activate) return { revision: candidate, report, ...(plan ? { plan } : {}) };
  const current = await adminRequest(`/admin/v1/config-revisions/${candidate.id}`, RevisionSchema);
  requireRevisionBinding(current.data, { canonicalDocument, environmentID: input.environmentID, revisionID: candidate.id });
  if (current.data.state !== "valid") throw new Error("configuration_revision_not_activatable");
  if (!current.etag) throw new Error("The Admin API omitted the activation ETag.");
  const activated = await adminRequest(`/admin/v1/config-revisions/${candidate.id}/activate`, RevisionSchema, { method: "POST", etag: current.etag });
  requireRevisionBinding(activated.data, { canonicalDocument, environmentID: input.environmentID, revisionID: candidate.id });
  if (activated.data.state !== "active") throw new Error("configuration_activation_context_mismatch");
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
    for (const application of response.items) requireApplicationParent(application, organizationID);
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
    requireExactApplication(existing, input);
    return existing;
  }
  try {
    const created = (await adminRequest("/admin/v1/applications", ApplicationResourceSchema, { method: "POST", body: {
      organization_id: input.organizationID, slug: input.slug, display_name: input.displayName
    } })).data;
    requireExactApplication(created, input);
    return created;
  } catch (error) {
    if (problemFromError(error).code !== "conflict") throw error;
    const reconciled = await findApplication(input.organizationID, input.slug);
    if (!reconciled || reconciled.display_name !== input.displayName) throw error;
    requireExactApplication(reconciled, input);
    return reconciled;
  }
}

export async function findOrCreateEnvironment(input: { applicationID: string; displayName: string; kind: "development" | "staging" | "production"; slug: string }) {
  const find = async () => {
    const environments = (await adminRequest(
      `/admin/v1/applications/${input.applicationID}/environments`, EnvironmentResourceListSchema
    )).data.items;
    for (const environment of environments) requireEnvironmentParent(environment, input.applicationID);
    return environments.find((environment) => environment.slug === input.slug);
  };
  const existing = await find();
  if (existing) {
    if (existing.display_name !== input.displayName || existing.kind !== input.kind) throw new Error("environment_slug_in_use");
    requireExactEnvironment(existing, input);
    return existing;
  }
  try {
    const created = (await adminRequest(`/admin/v1/applications/${input.applicationID}/environments`, EnvironmentResourceSchema, {
      method: "POST", body: { slug: input.slug, display_name: input.displayName, kind: input.kind }
    })).data;
    requireExactEnvironment(created, input);
    return created;
  } catch (error) {
    if (problemFromError(error).code !== "conflict") throw error;
    const reconciled = await find();
    if (!reconciled || reconciled.display_name !== input.displayName || reconciled.kind !== input.kind) throw error;
    requireExactEnvironment(reconciled, input);
    return reconciled;
  }
}

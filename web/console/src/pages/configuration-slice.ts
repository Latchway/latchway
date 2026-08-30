import {
  adminRequest,
  ConfigurationPlanSchema,
  RevisionSchema,
  ValidationSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation
} from "../api/admin";

export type JSONRecord = Record<string, unknown>;

export interface AreaResource {
  key: string;
  label: string;
  value: JSONRecord;
}

interface BaseCollectionDefinition {
  canonicalPath: string;
  deletable: boolean;
  description: string;
  key: string;
  label: string;
  template: JSONRecord;
}

interface SpecArrayCollectionDefinition extends BaseCollectionDefinition {
  kind: "spec-array";
  property: string;
}

interface FeatureRoutesCollectionDefinition extends BaseCollectionDefinition {
  kind: "feature-routes";
}

interface FeatureFieldsCollectionDefinition extends BaseCollectionDefinition {
  fields: string[];
  kind: "feature-fields";
}

export type AreaCollectionDefinition =
  | SpecArrayCollectionDefinition
  | FeatureRoutesCollectionDefinition
  | FeatureFieldsCollectionDefinition;

export interface ConfigurationAreaDefinition {
  collections: AreaCollectionDefinition[];
  description: string;
  title: string;
}

const identifierPattern = /^[a-z][a-z0-9_-]{0,62}$/;

function specArray(key: string, label: string, description: string, template: JSONRecord): SpecArrayCollectionDefinition {
  return { canonicalPath: `/spec/${key}`, deletable: true, description, key, kind: "spec-array", label, property: key, template };
}

function featureFields(key: string, label: string, description: string, fields: string[], template: JSONRecord): FeatureFieldsCollectionDefinition {
  return { canonicalPath: fields.map((field) => `/spec/features/*/${field}`).join(", "), deletable: false, description, fields, key, kind: "feature-fields", label, template };
}

const featureRoutes: FeatureRoutesCollectionDefinition = {
  canonicalPath: "/spec/features/*/routes",
  deletable: true,
  description: "Each resource is one route under an exact parent feature. Editing it cannot change that feature's access, limit-plan, or attestation selection.",
  key: "feature-routes",
  kind: "feature-routes",
  label: "Feature routes",
  template: { feature_id: "assistant", route: { fallbackOn: [], id: "new_route", model: "assistant_default", priority: 10, weight: 1, when: "true" } }
};

export const configurationAreas = {
  access: {
    collections: [featureFields("feature-access", "Feature access", "Edit only the access expression on an existing feature.", ["access"], { feature_id: "assistant", access: { expression: "principal.authenticated" } })],
    description: "Edit per-feature authorization without replacing routes, limits, attestation selection, or unrelated configuration.",
    title: "Access policies"
  },
  abuse: {
    collections: [featureFields("feature-abuse", "Feature protection composition", "Edit the access, attestation-policy, and limit-plan composition together while preserving routes and every other feature field.", ["access", "attestationPolicy", "limitPlan"], { feature_id: "assistant", access: { expression: "principal.authenticated" }, attestationPolicy: "native", limitPlan: { expression: "'free'" } })],
    description: "Abuse protection is the explicit composition of access, attestation, and limits; no hidden browser policy is introduced.",
    title: "Abuse controls"
  },
  attestation: {
    collections: [specArray("attestationPolicies", "Attestation policies", "Edit one platform-proof policy while preserving identity, features, upstreams, and limits.", { id: "new_attestation_policy", platforms: { react_native_ios: { appAttest: { allowedBundleVersions: ["1.0.0"], allowedValidationCategories: [1], appIdPrefix: "TEAMID", bundleId: "com.example.app", environment: "production" }, minimumTrustLevel: "app_verified", mode: "required", provider: "app_attest" } } })],
    description: "Edit bounded native, React Native, web, or Node proof policy resources. Server validation remains authoritative for provider/platform combinations.",
    title: "Attestation"
  },
  components: {
    collections: [specArray("componentDefinitions", "Component definitions", "Edit one configured root or delegated client component, including exact platform identifiers, trust establishment, parent constraints, and feature grants.", { id: "new_component", platform: "ios", kind: "main_app", identifiers: { bundleIdentifiers: ["com.example.app"] }, familyRole: "root", attestation: { strategy: "direct", provider: "app_attest" }, allowedFeatures: ["assistant"] })],
    description: "Define the only roots and delegated children that may join an Installation Family. The server validates platform identifiers, trust strategy, delegation ancestry, lifetime, and feature scope.",
    title: "Component definitions"
  },
  features: {
    collections: [specArray("features", "Features", "Edit a complete client-visible feature resource.", { access: { expression: "principal.authenticated" }, attestationPolicy: "native", id: "new_feature", limitPlan: { expression: "'free'" }, protocol: "openai_responses", routes: [{ id: "primary", model: "assistant_default", priority: 10, when: "true" }] })],
    description: "Edit complete feature resources without replacing identity providers, upstreams, model catalogs, or global limit plans.",
    title: "Features"
  },
  identity: {
    collections: [specArray("identityProviders", "Identity providers", "Edit one trusted issuer and its normalized-claim mapping.", { id: "new_identity_provider", projectId: "replace-me", type: "firebase" })],
    description: "Edit trusted issuer resources while preserving every non-identity configuration slice.",
    title: "Authentication providers"
  },
  limits: {
    collections: [
      specArray("limitPlans", "Limit plans", "Edit one global durable quota plan.", { id: "new_limit_plan", limits: [{ algorithm: "calendar", hard: true, maximum: 100, metric: "logical_requests", scope: ["user", "feature"], timezone: "UTC", window: "1d" }] }),
      featureFields("feature-limit-plan", "Feature plan selection", "Edit only the limit-plan expression selected by an existing feature.", ["limitPlan"], { feature_id: "assistant", limitPlan: { expression: "'free'" } })
    ],
    description: "Edit durable plan resources and feature plan selection without replacing routes, access, identity, or provider configuration.",
    title: "Limit plans"
  },
  modelsPricing: {
    collections: [
      specArray("models", "Models", "Edit logical-to-physical model mappings.", { capabilities: ["openai_responses"], id: "new_model", upstream: "primary", upstreamModel: "replace-me" }),
      specArray("inputAccountingProfiles", "Input accounting profiles", "Edit conservative exact-model input accounting profiles.", { id: "new_input_profile", maximumContextTokens: 128000, maximumFramingTokensPerMessage: 4, maximumFramingTokensPerRequest: 8, method: "utf8_byte_bpe_declared_framing_v1", physicalModel: "replace-me", protocol: "openai_responses" }),
      specArray("pricingCatalogs", "Pricing catalogs", "Edit immutable operator-reviewed price catalogs.", { currency: "USD", entries: [{ inputNanoUsdPerMillion: 0, model: "assistant_default", outputNanoUsdPerMillion: 0, requestNanoUsd: 0 }], id: "new_pricing_catalog" })
    ],
    description: "Edit model mappings, exact input accounting, and pricing as separate canonical resource collections.",
    title: "Models & pricing"
  },
  routes: {
    collections: [featureRoutes],
    description: "Edit ordered route resources under an exact feature while preserving feature access, attestation, limits, and all unrelated configuration.",
    title: "Routes"
  },
  upstreams: {
    collections: [specArray("upstreams", "Upstreams", "Edit one bounded provider destination and its server-held credential reference.", { authentication: { type: "none" }, baseUrl: "https://api.example.test/v1", id: "new_upstream", type: "openai_compatible" })],
    description: "Edit provider destinations without exposing secret plaintext or replacing model, feature, identity, or governance slices.",
    title: "Upstreams"
  }
} satisfies Record<string, ConfigurationAreaDefinition>;

function plainObject(value: unknown): value is JSONRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function configSpec(document: JSONRecord): JSONRecord {
  if (!plainObject(document.spec)) throw new Error("The active configuration has no object-valued spec.");
  return document.spec;
}

function featureResources(document: JSONRecord): JSONRecord[] {
  const features = configSpec(document).features;
  if (!Array.isArray(features) || features.some((feature) => !plainObject(feature) || !identifierPattern.test(String(feature.id ?? "")))) {
    throw new Error("The active configuration has an invalid feature collection.");
  }
  return features as JSONRecord[];
}

function exactKeys(value: JSONRecord, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && expected.slice().sort().every((key, index) => actual[index] === key);
}

function requireIdentifier(value: unknown, label: string): string {
  const identifier = String(value ?? "");
  if (!identifierPattern.test(identifier)) throw new Error(`${label} must be a canonical identifier.`);
  return identifier;
}

export function cloneConfigurationDocument(document: JSONRecord): JSONRecord {
  const copied = clone(document);
  configSpec(copied);
  return copied;
}

export function listAreaResources(document: JSONRecord, collection: AreaCollectionDefinition): AreaResource[] {
  if (collection.kind === "spec-array") {
    const values = configSpec(document)[collection.property];
    if (values === undefined) return [];
    if (!Array.isArray(values) || values.some((value) => !plainObject(value))) throw new Error(`${collection.label} is not a resource array.`);
    return values.map((value) => {
      const id = requireIdentifier(value.id, `${collection.label} resource ID`);
      return { key: id, label: id, value: clone(value) };
    });
  }
  if (collection.kind === "feature-routes") {
    return featureResources(document).flatMap((feature) => {
      const featureID = requireIdentifier(feature.id, "Feature ID");
      if (!Array.isArray(feature.routes) || feature.routes.some((route) => !plainObject(route))) throw new Error(`Feature ${featureID} has an invalid route collection.`);
      return (feature.routes as JSONRecord[]).map((route) => {
        const routeID = requireIdentifier(route.id, "Route ID");
        return { key: `${featureID}/${routeID}`, label: `${featureID} / ${routeID}`, value: { feature_id: featureID, route: clone(route) } };
      });
    });
  }
  return featureResources(document).map((feature) => {
    const featureID = requireIdentifier(feature.id, "Feature ID");
    const value: JSONRecord = { feature_id: featureID };
    for (const field of collection.fields) value[field] = clone(feature[field]);
    return { key: featureID, label: featureID, value };
  });
}

export function upsertAreaResource(document: JSONRecord, collection: AreaCollectionDefinition, previousKey: string | undefined, candidate: unknown): { document: JSONRecord; key: string } {
  if (!plainObject(candidate)) throw new Error("The resource editor must contain exactly one JSON object.");
  const next = cloneConfigurationDocument(document);
  const spec = configSpec(next);
  if (collection.kind === "spec-array") {
    const id = requireIdentifier(candidate.id, `${collection.label} resource ID`);
    if (previousKey && previousKey !== id) throw new Error("An existing resource ID cannot be changed in place.");
    const values = spec[collection.property] ?? [];
    if (!Array.isArray(values) || values.some((value) => !plainObject(value))) throw new Error(`${collection.label} is not a resource array.`);
    const index = (values as JSONRecord[]).findIndex((value) => value.id === id);
    if (!previousKey && index !== -1) throw new Error(`Resource ${id} already exists.`);
    const copied = clone(candidate);
    spec[collection.property] = index === -1 ? [...values, copied] : values.map((value, valueIndex) => valueIndex === index ? copied : value);
    return { document: next, key: id };
  }
  if (collection.kind === "feature-routes") {
    if (!exactKeys(candidate, ["feature_id", "route"]) || !plainObject(candidate.route)) throw new Error("A route resource requires exactly feature_id and route objects.");
    const featureID = requireIdentifier(candidate.feature_id, "Parent feature ID");
    const routeID = requireIdentifier(candidate.route.id, "Route ID");
    const key = `${featureID}/${routeID}`;
    if (previousKey && previousKey !== key) throw new Error("An existing route or parent feature ID cannot be changed in place.");
    const features = featureResources(next); const feature = features.find((item) => item.id === featureID);
    if (!feature) throw new Error(`Parent feature ${featureID} does not exist.`);
    if (!Array.isArray(feature.routes) || feature.routes.some((route) => !plainObject(route))) throw new Error(`Feature ${featureID} has an invalid route collection.`);
    const index = (feature.routes as JSONRecord[]).findIndex((route) => route.id === routeID);
    if (!previousKey && index !== -1) throw new Error(`Route ${key} already exists.`);
    feature.routes = index === -1 ? [...feature.routes, clone(candidate.route)] : feature.routes.map((route, routeIndex) => routeIndex === index ? clone(candidate.route) : route);
    return { document: next, key };
  }
  const expected = ["feature_id", ...collection.fields];
  if (!exactKeys(candidate, expected)) throw new Error(`This editor accepts exactly ${expected.join(", ")}.`);
  const featureID = requireIdentifier(candidate.feature_id, "Feature ID");
  if (previousKey && previousKey !== featureID) throw new Error("An existing feature ID cannot be changed in place.");
  const feature = featureResources(next).find((item) => item.id === featureID);
  if (!feature) throw new Error(`Feature ${featureID} does not exist.`);
  for (const field of collection.fields) feature[field] = clone(candidate[field]);
  return { document: next, key: featureID };
}

export function deleteAreaResource(document: JSONRecord, collection: AreaCollectionDefinition, key: string): JSONRecord {
  if (!collection.deletable) throw new Error("This required nested resource can be replaced but not removed in this editor.");
  const next = cloneConfigurationDocument(document); const spec = configSpec(next);
  if (collection.kind === "spec-array") {
    const values = spec[collection.property];
    if (!Array.isArray(values)) throw new Error(`${collection.label} is not a resource array.`);
    const filtered = values.filter((value) => plainObject(value) && value.id !== key);
    if (filtered.length === values.length) throw new Error(`Resource ${key} is no longer present.`);
    spec[collection.property] = filtered;
    return next;
  }
  if (collection.kind === "feature-routes") {
    const split = key.indexOf("/");
    if (split < 1) throw new Error("The route key is invalid.");
    const featureID = key.slice(0, split); const routeID = key.slice(split + 1);
    const feature = featureResources(next).find((item) => item.id === featureID);
    if (!feature || !Array.isArray(feature.routes)) throw new Error(`Route ${key} is no longer present.`);
    const filtered = feature.routes.filter((route) => plainObject(route) && route.id !== routeID);
    if (filtered.length === feature.routes.length) throw new Error(`Route ${key} is no longer present.`);
    feature.routes = filtered;
    return next;
  }
  throw new Error("This nested resource cannot be deleted.");
}

export function validStrongETag(value: string | undefined): value is string {
  return Boolean(value && value.length >= 3 && value.length <= 256 && value.startsWith('"') && value.endsWith('"') && !value.startsWith("W/") && !value.includes("\n") && !value.includes("\r") && !value.includes(","));
}

export async function applyConfigurationSliceChange(input: {
  activate: boolean;
  description: string;
  document: JSONRecord;
  environmentID: string;
  sourceRevisionID: string;
}): Promise<{ etag: string; revision: ConfigurationRevision; report: ConfigurationValidation; plan?: ConfigurationPlan }> {
  const draft = await adminRequest(`/admin/v1/environments/${input.environmentID}/config-revisions`, RevisionSchema, {
    body: { base_revision_id: input.sourceRevisionID, description: input.description },
    method: "POST"
  });
  if (!validStrongETag(draft.etag)) throw new Error("The Admin API omitted the strong ETag required to edit the cloned draft.");
  const replaced = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}`, RevisionSchema, {
    body: input.document,
    etag: draft.etag,
    method: "PATCH"
  });
  if (!validStrongETag(replaced.etag)) throw new Error("The Admin API omitted the current strong ETag after replacing the cloned draft.");
  const report = (await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/validate`, ValidationSchema, { method: "POST" })).data;
  let plan: ConfigurationPlan | undefined;
  if (report.valid) {
    plan = (await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/plan`, ConfigurationPlanSchema, { method: "POST" })).data;
  }
  if (!report.valid || !input.activate) return { etag: replaced.etag, revision: replaced.data, report, ...(plan ? { plan } : {}) };
  const activated = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/activate`, RevisionSchema, {
    etag: replaced.etag,
    method: "POST"
  });
  if (!validStrongETag(activated.etag)) throw new Error("The Admin API omitted the strong ETag for the activated revision.");
  return { etag: activated.etag, revision: activated.data, report, ...(plan ? { plan } : {}) };
}

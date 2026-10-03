import { configurationAreas, type JSONRecord, upsertAreaResource } from "../configuration-slice";
import { object, orderedRoutes, specCollection } from "./feature-model";

export const featuresCollection = configurationAreas.features.collections[0]!;

/** Plain words for each condition that moves a request to the next route. */
export const RETRY_CONDITION_LABEL: Readonly<Record<string, string>> = {
  connect_error: "Can't connect",
  first_byte_timeout: "No first byte in time",
  status_408: "Request timeout (408)",
  status_429: "Rate limited (429)",
  status_500: "Server error (500)",
  status_502: "Bad gateway (502)",
  status_503: "Unavailable (503)",
  status_504: "Gateway timeout (504)",
  timeout_before_headers: "No response headers in time"
};

export const RETRY_CONDITIONS = Object.keys(RETRY_CONDITION_LABEL);

export const STICKY_LABEL: Readonly<Record<string, string>> = { installation: "Per install", none: "Mix freely", user: "Per user" };

export function featureOf(document: JSONRecord | undefined, featureID: string): JSONRecord | undefined {
  return document ? specCollection(document, "features").find((feature) => feature.id === featureID) : undefined;
}

/** The AI connection a logical model belongs to. */
export function connectionOfModel(document: JSONRecord | undefined, modelID: unknown): string | undefined {
  if (!document) return undefined;
  const model = specCollection(document, "models").find((candidate) => candidate.id === modelID);
  return model ? String(model.upstream ?? "") || undefined : undefined;
}

/** Models usable by a protocol: those that declare it, or declare no capabilities at all. */
export function modelsForProtocol(document: JSONRecord | undefined, protocol: unknown): JSONRecord[] {
  if (!document) return [];
  return specCollection(document, "models").filter((model) => !Array.isArray(model.capabilities) || model.capabilities.includes(protocol));
}

/** Replaces one feature in the document, keeping every other resource. */
export function replaceFeature(document: JSONRecord, featureID: string, change: (feature: JSONRecord) => JSONRecord): JSONRecord {
  const current = featureOf(document, featureID);
  if (!current) throw new Error(`Feature ${featureID} isn't in the draft any more.`);
  return upsertAreaResource(document, featuresCollection, featureID, change(JSON.parse(JSON.stringify(current)) as JSONRecord)).document;
}

/** Routes that share a priority split traffic by weight; their order is a tie, so they can't be moved apart by swapping. */
export function hasSplits(feature: JSONRecord): boolean {
  const priorities = orderedRoutes(feature).map((route) => Number(route.priority ?? 0));
  return new Set(priorities).size !== priorities.length;
}

/** Swaps a route's priority with its neighbour's, leaving every other route untouched. */
export function moveRoute(feature: JSONRecord, routeID: string, direction: -1 | 1): JSONRecord {
  const routes = orderedRoutes(feature);
  const index = routes.findIndex((route) => route.id === routeID);
  const neighbour = routes[index + direction];
  const current = routes[index];
  if (!current || !neighbour) return feature;
  if (current.priority === neighbour.priority) throw new Error("These routes share a priority to split traffic, so their order can't be swapped. Edit their priorities instead.");
  const swapped = routes.map((route) => (route.id === current.id ? { ...route, priority: neighbour.priority } : route.id === neighbour.id ? { ...route, priority: current.priority } : route));
  return { ...feature, routes: swapped };
}

export function upsertRoute(feature: JSONRecord, previousID: string | undefined, route: JSONRecord): JSONRecord {
  const routes = orderedRoutes(feature);
  const id = String(route.id ?? "");
  if (!/^[a-z][a-z0-9_-]{0,62}$/.test(id)) throw new Error("A route ID starts with a letter and uses lowercase letters, digits, - or _.");
  if (previousID && previousID !== id) throw new Error("A route ID can't be changed; add a new route instead.");
  if (!previousID && routes.some((candidate) => candidate.id === id)) throw new Error(`This feature already has a route named ${id}.`);
  const last = Math.max(0, ...routes.map((candidate) => Number(candidate.priority ?? 0)));
  const next = previousID ? routes.map((candidate) => (candidate.id === id ? route : candidate)) : [...routes, { ...route, priority: route.priority ?? last + 10 }];
  return { ...feature, routes: next };
}

export function removeRoute(feature: JSONRecord, routeID: string): JSONRecord {
  const routes = orderedRoutes(feature);
  if (routes.length <= 1) throw new Error("A feature keeps at least one route.");
  return { ...feature, routes: routes.filter((route) => route.id !== routeID) };
}

/** "Always" for a route that matches everything, otherwise the CEL rule itself. */
export function whenText(route: JSONRecord): string {
  const when = String(route.when ?? "true").trim();
  return when === "true" ? "Always" : when;
}

export function fallbackText(route: JSONRecord): string {
  const conditions = Array.isArray(route.fallbackOn) ? route.fallbackOn.map(String) : [];
  return conditions.length ? conditions.map((condition) => RETRY_CONDITION_LABEL[condition] ?? condition).join(", ") : "Never";
}

export interface RouteRow {
  connection?: string;
  feature: string;
  model: string;
  order: number;
  route: JSONRecord;
}

/** One row per feature × route, in evaluation order, for the Routing page. */
export function routeRows(document: JSONRecord | undefined): RouteRow[] {
  if (!document) return [];
  return specCollection(document, "features").flatMap((feature) => orderedRoutes(feature).map((route, index) => ({
    connection: connectionOfModel(document, route.model),
    feature: String(feature.id),
    model: String(route.model ?? ""),
    order: index,
    route
  })));
}

export function isRecord(value: unknown): value is JSONRecord {
  return object(value);
}

import type { ConsoleRoute } from "../../app/navigation";
import { cloneConfigurationDocument, type JSONRecord } from "../configuration-slice";
import { limitText } from "../policies/limit-model";

/**
 * A configuration change is computed per resource, as the difference between two documents (normally the working
 * draft and the live revision). Equal resources produce no entry, so an edit that ends up equal to live disappears.
 */
export type DiffGroup = "features" | "routing" | "limits" | "connections" | "trust" | "other";

export const GROUP_LABEL: Readonly<Record<DiffGroup, string>> = {
  connections: "AI Connections",
  features: "Features",
  limits: "Limits",
  other: "Other settings",
  routing: "Routing",
  trust: "Client Trust"
};

export const GROUP_ORDER: readonly DiffGroup[] = ["features", "routing", "limits", "connections", "trust", "other"];

interface CollectionInfo {
  group: DiffGroup;
  label: string;
}

/** The spec arrays keyed by `id`, in the order the review lists them. */
export const COLLECTIONS: Readonly<Record<string, CollectionInfo>> = {
  features: { group: "features", label: "Feature" },
  limitPlans: { group: "limits", label: "Limit plan" },
  upstreams: { group: "connections", label: "AI connection" },
  models: { group: "connections", label: "Model" },
  pricingCatalogs: { group: "connections", label: "Pricing catalog" },
  inputAccountingProfiles: { group: "connections", label: "Input accounting" },
  identityProviders: { group: "trust", label: "Sign-in provider" },
  attestationPolicies: { group: "trust", label: "App verification" },
  componentDefinitions: { group: "trust", label: "Component" }
};

const SINGLETONS: Readonly<Record<string, CollectionInfo>> = {
  privacy: { group: "other", label: "Privacy settings" },
  session: { group: "trust", label: "Session settings" }
};

export type DiffState = "new" | "edited" | "removing";

export interface FieldChange {
  after?: unknown;
  before?: unknown;
  /** For lists of plain values: what was added and removed. */
  list?: { added: string[]; removed: string[] };
  path: string;
}

export interface DiffEntry {
  /** The spec key, e.g. `features`, or `features.routes` for a feature's routing. */
  collection: string;
  fields: FieldChange[];
  group: DiffGroup;
  id: string;
  /** Stable key, e.g. `features/assistant` or `routing/assistant`. */
  key: string;
  label: string;
  state: DiffState;
  summary: string;
}

function isRecord(value: unknown): value is JSONRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function spec(document: JSONRecord | undefined): JSONRecord {
  return document && isRecord(document.spec) ? document.spec : {};
}

function items(document: JSONRecord | undefined, key: string): JSONRecord[] {
  const value = spec(document)[key];
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function plain(value: unknown): value is string | number | boolean {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

/** Field-level differences, with readable paths ("routes › primary › model") and list changes as + / −. */
export function fieldChanges(before: unknown, after: unknown, path: string[] = []): FieldChange[] {
  if (same(before, after)) return [];
  const label = path.join(" › ") || "value";
  if (Array.isArray(before) && Array.isArray(after)) {
    if ([...before, ...after].every(plain)) {
      const left = before.map(String);
      const right = after.map(String);
      const added = right.filter((value) => !left.includes(value));
      const removed = left.filter((value) => !right.includes(value));
      if (!added.length && !removed.length) return [{ after, before, path: `${label} (order)` }];
      return [{ list: { added, removed }, path: label }];
    }
    if ([...before, ...after].every((item) => isRecord(item) && typeof item.id === "string")) {
      const ids = [...new Set([...before, ...after].map((item) => String((item as JSONRecord).id)))];
      return ids.flatMap((id) => fieldChanges(before.find((item) => (item as JSONRecord).id === id), after.find((item) => (item as JSONRecord).id === id), [...path, id]));
    }
    if ([...before, ...after].every(isRecord)) {
      // Unkeyed records (such as a plan's limits) are compared by position, numbered from 1.
      return Array.from({ length: Math.max(before.length, after.length) }, (_, index) => fieldChanges(before[index], after[index], [...path, String(index + 1)])).flat();
    }
    return [{ after, before, path: label }];
  }
  if (isRecord(before) && isRecord(after)) {
    return [...new Set([...Object.keys(before), ...Object.keys(after)])].sort().flatMap((key) => fieldChanges(before[key], after[key], [...path, key]));
  }
  return [{ after, before, path: label }];
}

function short(value: unknown): string {
  if (value === undefined) return "—";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > 60 ? `${text.slice(0, 57)}…` : text;
}

/** One line for an entry: the first changes, e.g. "baseUrl: https://a → https://b · models: + fast". */
export function summarize(state: DiffState, label: string, fields: readonly FieldChange[]): string {
  if (state === "new") return `New ${label.toLowerCase()}`;
  if (state === "removing") return `Removed in the draft`;
  const parts = fields.slice(0, 2).map((field) => field.list
    ? `${field.path}: ${[...field.list.added.map((value) => `+ ${value}`), ...field.list.removed.map((value) => `− ${value}`)].join(", ")}`
    : `${field.path}: ${short(field.before)} → ${short(field.after)}`);
  return `${parts.join(" · ")}${fields.length > 2 ? ` · ${fields.length - 2} more` : ""}`;
}

/** A plan's limits read as sentences in the diff ("limits › 2: — → Each installation can use 1,000 requests per day"). */
function describeLimits(fields: FieldChange[]): FieldChange[] {
  const sentence = (value: unknown) => (isRecord(value) && typeof value.metric === "string" ? limitText(value) : value);
  return fields.map((field) => (/^limits › \d+$/.test(field.path) ? { ...field, after: sentence(field.after), before: sentence(field.before) } : field));
}

function entry(collection: string, info: CollectionInfo, id: string, before: unknown, after: unknown, key = `${collection}/${id}`): DiffEntry | undefined {
  if (same(before, after)) return undefined;
  const state: DiffState = before === undefined ? "new" : after === undefined ? "removing" : "edited";
  const changes = state === "edited" ? fieldChanges(before, after) : [];
  const fields = collection === "limitPlans" ? describeLimits(changes) : changes;
  return { collection, fields, group: info.group, id, key, label: info.label, state, summary: summarize(state, info.label, fields) };
}

/** Every resource that differs between `base` (normally live) and `target` (normally the draft). */
export function configurationDiff(base: JSONRecord | undefined, target: JSONRecord | undefined): DiffEntry[] {
  const entries: DiffEntry[] = [];
  for (const [collection, info] of Object.entries(COLLECTIONS)) {
    const left = items(base, collection);
    const right = items(target, collection);
    const ids = [...new Set([...left, ...right].map((item) => String(item.id)))];
    for (const id of ids) {
      const before = left.find((item) => item.id === id);
      const after = right.find((item) => item.id === id);
      if (collection === "features") {
        // A feature's routing and its other settings are reviewed and discarded separately.
        const settings = (value: JSONRecord | undefined) => (value ? Object.fromEntries(Object.entries(value).filter(([key]) => key !== "routes")) : undefined);
        const settingsEntry = entry(collection, info, id, settings(before), settings(after));
        if (settingsEntry) entries.push(settingsEntry);
        if (before && after) {
          const routing = entry("features.routes", { group: "routing", label: "Routing" }, id, before.routes, after.routes, `routing/${id}`);
          if (routing) entries.push(routing);
        }
        continue;
      }
      const changed = entry(collection, info, id, before, after);
      if (changed) entries.push(changed);
    }
  }
  for (const [key, info] of Object.entries(SINGLETONS)) {
    const changed = entry(key, info, key, spec(base)[key], spec(target)[key]);
    if (changed) entries.push(changed);
  }
  const known = new Set([...Object.keys(COLLECTIONS), ...Object.keys(SINGLETONS)]);
  for (const key of [...new Set([...Object.keys(spec(base)), ...Object.keys(spec(target))])].filter((candidate) => !known.has(candidate)).sort()) {
    const changed = entry(key, { group: "other", label: key }, key, spec(base)[key], spec(target)[key]);
    if (changed) entries.push(changed);
  }
  if (!same(base?.metadata, target?.metadata) && base && target) {
    const changed = entry("metadata", { group: "other", label: "Metadata" }, "metadata", base.metadata, target.metadata);
    if (changed) entries.push(changed);
  }
  return entries;
}

/** Puts one entry back to its value in `base`: removes a new resource, restores an edited or removed one. */
export function discardEntry(target: JSONRecord, base: JSONRecord, change: DiffEntry): JSONRecord {
  const next = cloneConfigurationDocument(target);
  const nextSpec = next.spec as JSONRecord;
  if (change.collection === "metadata") {
    next.metadata = structuredClone(base.metadata);
    return next;
  }
  if (change.collection === "features.routes") {
    const live = items(base, "features").find((item) => item.id === change.id);
    nextSpec.features = items(next, "features").map((item) => (item.id === change.id && live ? { ...item, routes: structuredClone(live.routes) } : item));
    return next;
  }
  if (!(change.collection in COLLECTIONS)) {
    const live = spec(base)[change.collection];
    if (live === undefined) delete nextSpec[change.collection];
    else nextSpec[change.collection] = structuredClone(live);
    return next;
  }
  const live = items(base, change.collection).find((item) => item.id === change.id);
  const current = items(next, change.collection);
  if (!live) {
    nextSpec[change.collection] = current.filter((item) => item.id !== change.id);
    return next;
  }
  const restored = change.collection === "features"
    ? { ...structuredClone(live), routes: current.find((item) => item.id === change.id)?.routes ?? structuredClone(live.routes) }
    : structuredClone(live);
  nextSpec[change.collection] = current.some((item) => item.id === change.id)
    ? current.map((item) => (item.id === change.id ? restored : item))
    : [...current, restored];
  return next;
}

/** "1 feature, 2 routing changes, 1 limit plan · 8 fields": a generated summary of a set of changes. */
export function changeSetSummary(entries: readonly DiffEntry[]): string {
  if (!entries.length) return "No changes";
  const counts = new Map<string, number>();
  for (const change of entries) counts.set(change.label, (counts.get(change.label) ?? 0) + 1);
  // Lower-case the label unless it starts with an acronym ("AI connection").
  const noun = (label: string) => (/^[A-Z]{2}/.test(label) ? label : label.charAt(0).toLowerCase() + label.slice(1));
  const parts = [...counts.entries()].map(([label, count]) => `${count} ${noun(label)}${count === 1 || label.endsWith("s") ? "" : "s"}`);
  const fields = entries.reduce((total, change) => total + Math.max(1, change.fields.length), 0);
  return `${parts.join(", ")} · ${fields} field${fields === 1 ? "" : "s"}`;
}

/** Where to edit an entry's resource. */
export function editTarget(change: DiffEntry): { search?: Record<string, string>; to: ConsoleRoute } {
  switch (change.collection) {
    case "features": return { search: { feature: change.id }, to: "/features" };
    case "features.routes": return { search: { feature: change.id, tab: "routing" }, to: "/features" };
    case "limitPlans": return { search: { plan: change.id }, to: "/limit-plans" };
    case "upstreams": return { to: "/upstreams" };
    case "models":
    case "pricingCatalogs":
    case "inputAccountingProfiles": return { to: "/models-pricing" };
    case "identityProviders": return { to: "/authentication-providers" };
    case "attestationPolicies": return { to: "/attestation" };
    case "componentDefinitions": return { to: "/component-definitions" };
    case "session": return { to: "/client-sessions" };
    default: return { to: "/configuration" };
  }
}

/** Where to fix a validation issue, from its JSON path, e.g. `/spec/features/2/limitPlan`. */
export function fixTarget(path: string, document: JSONRecord | undefined): { search?: Record<string, string>; to: ConsoleRoute } {
  const match = /^[/$.]*spec[/.]([A-Za-z]+)(?:[/.[](\d+))?/.exec(path);
  if (!match?.[1]) return { to: "/configuration" };
  const collection = match[1];
  const index = match[2] === undefined ? undefined : Number(match[2]);
  const id = index === undefined ? undefined : String(items(document, collection)[index]?.id ?? "");
  if (collection === "features" && id) {
    const tab = /routes/.test(path) ? "routing" : /access|limitPlan|attestationPolicy|output/.test(path) ? "access" : undefined;
    return { search: { feature: id, ...(tab ? { tab } : {}) }, to: "/features" };
  }
  if (collection === "limitPlans" && id) return { search: { plan: id }, to: "/limit-plans" };
  if (collection in COLLECTIONS || collection in SINGLETONS) return editTarget({ collection, fields: [], group: "other", id: id ?? collection, key: "", label: "", state: "edited", summary: "" });
  return { to: "/configuration" };
}

/** Features whose behaviour a set of changes can affect: changed features and routing, and features using a changed plan. */
export function affectedFeatures(entries: readonly DiffEntry[], draft: JSONRecord | undefined): string[] {
  const features = new Set<string>();
  const plans = new Set<string>();
  for (const entry of entries) {
    if (entry.collection === "features" || entry.collection === "features.routes") features.add(entry.id);
    if (entry.collection === "limitPlans") plans.add(entry.id);
  }
  const spec = draft?.spec;
  const list = spec && typeof spec === "object" && !Array.isArray(spec) && Array.isArray((spec as JSONRecord).features) ? ((spec as JSONRecord).features as JSONRecord[]) : [];
  for (const feature of list) {
    const expression = JSON.stringify(feature.limitPlan ?? "");
    if ([...plans].some((plan) => expression.includes(`'${plan}'`))) features.add(String(feature.id));
  }
  return [...features].sort();
}

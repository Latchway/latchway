import {
  type AreaCollectionDefinition,
  type AreaResource,
  cloneConfigurationDocument,
  deleteAreaResource,
  type JSONRecord,
  listAreaResources,
  upsertAreaResource
} from "../configuration-slice";

export type ResourceState = "live" | "new" | "edited" | "removing";

export interface ResourceRow extends AreaResource {
  /** The live value, when the resource exists in the active configuration. */
  live?: JSONRecord;
  state: ResourceState;
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function safeList(document: JSONRecord | undefined, collection: AreaCollectionDefinition): AreaResource[] {
  return document ? listAreaResources(document, collection) : [];
}

/**
 * Every resource in a collection with its draft state: new (only in the draft), edited (differs from live),
 * removing (live but deleted in the draft) or live. Removed resources keep their live value so they can be shown
 * struck through and restored.
 */
export function resourceRows(active: JSONRecord | undefined, working: JSONRecord | undefined, collection: AreaCollectionDefinition): ResourceRow[] {
  const live = new Map(safeList(active, collection).map((resource) => [resource.key, resource]));
  const current = safeList(working ?? active, collection);
  const rows: ResourceRow[] = current.map((resource) => {
    const before = live.get(resource.key);
    return { ...resource, ...(before ? { live: before.value } : {}), state: !before ? "new" : same(before.value, resource.value) ? "live" : "edited" };
  });
  const present = new Set(current.map((resource) => resource.key));
  for (const [key, resource] of live) {
    if (!present.has(key)) rows.push({ ...resource, live: resource.value, state: "removing" });
  }
  return rows;
}

/** Undo for one resource: a new one is removed, an edited or removed one goes back to its live value. */
export function restoreResource(working: JSONRecord, row: ResourceRow, collection: AreaCollectionDefinition): JSONRecord {
  if (row.state === "new") return deleteAreaResource(working, collection, row.key);
  if (!row.live) return cloneConfigurationDocument(working);
  return upsertAreaResource(working, collection, row.state === "edited" ? row.key : undefined, row.live).document;
}

/** Counts of changed resources across collections, for summaries. */
export function changeCount(rows: readonly ResourceRow[]): number {
  return rows.filter((row) => row.state !== "live").length;
}

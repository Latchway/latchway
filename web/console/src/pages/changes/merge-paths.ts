import type { JSONRecord } from "../configuration-slice";

/**
 * Reads a value from a configuration document at a merge path. Path segments are JSON Pointer tokens; a segment
 * under a list of identified entries names the entry by its `id`, the way the server's diff and merge do.
 */
export function valueAtPath(document: unknown, path: string): unknown {
  if (path === "/") return document;
  let current: unknown = document;
  for (const raw of path.split("/").slice(1)) {
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(current)) {
      current = current.find((item: unknown) => item !== null && typeof item === "object" && (item as JSONRecord).id === token);
    } else if (current !== null && typeof current === "object") {
      current = Object.hasOwn(current, token) ? (current as JSONRecord)[token] : undefined;
    } else {
      return undefined;
    }
    if (current === undefined) return undefined;
  }
  return current;
}

const SECTION_LABEL: Readonly<Record<string, string>> = {
  attestationPolicies: "App checks",
  componentDefinitions: "Components",
  identityProviders: "Sign-in providers",
  upstreams: "AI connections"
};

/** "/spec/upstreams/openai" → "AI connections: openai". */
export function promotionPath(path: string): string {
  const [, , section, entry] = path.split("/");
  if (path === "/metadata") return "Environment name and labels";
  if (section && entry) return `${SECTION_LABEL[section] ?? section}: ${entry.replaceAll("~1", "/").replaceAll("~0", "~")}`;
  return section ?? path;
}

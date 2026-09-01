import {
  isScalar,
  parseAllDocuments,
  stringify,
  visit,
  type Document
} from "yaml";

import type {
  ConfigurationPlan,
  ConfigurationRevision,
  ConfigurationValidation
} from "../api/admin";
import { adminRequest, RevisionSchema } from "../api/admin";
import { createValidateActivate } from "./setup-wizard-api";
import { canonicalConfigurationJSON } from "./setup-wizard-state";

export const maximumConfigurationImportBytes = 1 << 20;

const maximumDepth = 64;
const maximumNodes = 100_000;
const prohibitedObjectKeys = new Set(["__proto__", "constructor", "prototype"]);
const credentialValueKeys = new Set([
  "accesstoken",
  "apikey",
  "apitoken",
  "authorization",
  "bearertoken",
  "ciphertext",
  "clientsecret",
  "cookie",
  "credential",
  "credentials",
  "credentialvalue",
  "evidence",
  "password",
  "privatekey",
  "proof",
  "refreshtoken",
  "secret",
  "secretmaterial",
  "secrettext",
  "secretvalue"
]);
const standardTags = new Set([
  "tag:yaml.org,2002:bool",
  "tag:yaml.org,2002:float",
  "tag:yaml.org,2002:int",
  "tag:yaml.org,2002:map",
  "tag:yaml.org,2002:null",
  "tag:yaml.org,2002:seq",
  "tag:yaml.org,2002:str"
]);
const plainTimestamp = /^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}(?::?\d{2})?)?)?$/;

export type ConfigurationValue =
  | null
  | boolean
  | number
  | string
  | ConfigurationValue[]
  | ConfigurationDocument;

export interface ConfigurationDocument {
  [key: string]: ConfigurationValue;
}

export interface ConfigurationTransferResult {
  plan?: ConfigurationPlan;
  report: ConfigurationValidation;
  revision: ConfigurationRevision;
}

export class ConfigurationTransferError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationTransferError";
  }
}

function fail(message: string): never {
  throw new ConfigurationTransferError(message);
}

function byteLength(source: string): number {
  return new TextEncoder().encode(source).byteLength;
}

function inspectSyntax(document: Document): void {
  let failure: string | undefined;
  visit(document, {
    Alias() {
      failure ??= "Aliases and anchors are not allowed in configuration imports.";
      return visit.BREAK;
    },
    Node(_key, node) {
      if ("anchor" in node && node.anchor) {
        failure ??= "Aliases and anchors are not allowed in configuration imports.";
        return visit.BREAK;
      }
      if (node.tag && !standardTags.has(node.tag)) {
        failure ??= "Custom YAML tags are not allowed in configuration imports.";
        return visit.BREAK;
      }
      if (isScalar(node) && node.type === "PLAIN" && typeof node.source === "string" && plainTimestamp.test(node.source)) {
        failure ??= "YAML timestamps are not allowed in configuration imports; quote intended strings explicitly.";
        return visit.BREAK;
      }
      return undefined;
    },
    Pair(_key, pair) {
      if (isScalar(pair.key) && pair.key.value === "<<") {
        failure ??= "YAML merge keys are not allowed in configuration imports.";
        return visit.BREAK;
      }
      return undefined;
    }
  });
  if (failure) fail(failure);
}

function normalizeValue(
  value: unknown,
  depth: number,
  state: { nodes: number },
  path: WeakSet<object>
): ConfigurationValue {
  state.nodes += 1;
  if (state.nodes > maximumNodes) fail("The configuration import contains too many values.");
  if (depth > maximumDepth) fail("The configuration import is nested too deeply.");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "bigint") {
    if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) {
      fail("Configuration integers must be within the JSON safe-integer range.");
    }
    return Number(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("Non-finite numbers are not allowed in configuration imports.");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      fail("Configuration integers must be within the JSON safe-integer range.");
    }
    return value;
  }
  if (typeof value !== "object") fail("The configuration import contains a non-JSON value.");
  if (path.has(value)) fail("Cyclic or aliased objects are not allowed in configuration imports.");
  path.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => normalizeValue(item, depth + 1, state, path));
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail("Prototype-bearing objects are not allowed in configuration imports.");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      fail("Configuration object keys must be strings.");
    }
    const normalized = Object.create(null) as ConfigurationDocument;
    for (const key of keys as string[]) {
      if (prohibitedObjectKeys.has(key)) {
        fail(`The reserved object key ${key} is not allowed in configuration imports.`);
      }
      normalized[key] = normalizeValue(
        (value as Record<string, unknown>)[key],
        depth + 1,
        state,
        path
      );
    }
    return normalized;
  } finally {
    path.delete(value);
  }
}

function normalizeDocument(value: unknown): ConfigurationDocument {
  const normalized = normalizeValue(value, 0, { nodes: 0 }, new WeakSet());
  if (normalized === null || Array.isArray(normalized) || typeof normalized !== "object") {
    fail("A configuration import must contain one top-level object.");
  }
  return normalized;
}

export function parseConfigurationDocument(source: string): ConfigurationDocument {
  if (byteLength(source) > maximumConfigurationImportBytes) {
    fail("Configuration imports cannot exceed 1 MiB.");
  }
  if (!source.trim()) fail("A configuration import must contain one document.");

  const documents = parseAllDocuments(source, {
    intAsBigInt: true,
    merge: false,
    prettyErrors: false,
    schema: "core",
    strict: true,
    stringKeys: true,
    uniqueKeys: true,
    version: "1.2"
  });
  if (documents.length !== 1) fail("A configuration import must contain exactly one document.");
  const [document] = documents;
  if (!document || document.errors.length > 0 || document.warnings.length > 0 || !document.contents) {
    fail("The configuration import is not valid duplicate-key-safe YAML 1.2 or JSON.");
  }
  inspectSyntax(document);
  let value: unknown;
  try {
    value = document.toJS({ maxAliasCount: 0 });
  } catch {
    fail("Aliases and anchors are not allowed in configuration imports.");
  }
  return normalizeDocument(value);
}

export async function readConfigurationFile(file: File): Promise<ConfigurationDocument> {
  if (file.size > maximumConfigurationImportBytes) {
    fail("Configuration imports cannot exceed 1 MiB.");
  }
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
  } catch {
    fail("Configuration imports must be valid UTF-8.");
  }
  return parseConfigurationDocument(source);
}

function normalizedKey(key: string): string {
  return key.replaceAll(/[^A-Za-z0-9]/g, "").toLowerCase();
}

function isCredentialValueKey(key: string): boolean {
  if (key.endsWith("secretref")) return false;
  return credentialValueKeys.has(key) || [
    "accesstoken",
    "apikey",
    "apitoken",
    "bearertoken",
    "clientsecret",
    "credential",
    "credentials",
    "password",
    "privatekey",
    "providersecret",
    "refreshtoken",
    "secretkey",
    "secretmaterial",
    "secretvalue"
  ].some((suffix) => key.endsWith(suffix));
}

function assertRedactionSafe(value: ConfigurationValue): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach(assertRedactionSafe);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const normalized = normalizedKey(key);
    if (isCredentialValueKey(normalized)) {
      fail("The active configuration contains a credential-shaped field that cannot be exported safely.");
    }
    assertRedactionSafe(child);
  }
}

export function redactionSafeConfigurationYAML(document: unknown): string {
  const normalized = normalizeDocument(document);
  assertRedactionSafe(normalized);
  return stringify(normalized, {
    aliasDuplicateObjects: false,
    lineWidth: 0,
    schema: "core",
    sortMapEntries: true
  });
}

export async function stageConfigurationImport(input: {
  document: ConfigurationDocument;
  environmentID: string;
}): Promise<ConfigurationTransferResult> {
  return createValidateActivate({ ...input, activate: false });
}

export async function activateConfigurationImport(input: {
  document: ConfigurationDocument;
  environmentID: string;
  staged: ConfigurationTransferResult;
}): Promise<ConfigurationTransferResult> {
  const staged = input.staged;
  if (!staged.report.valid || staged.revision.state !== "valid" ||
    staged.revision.environment_id !== input.environmentID ||
    canonicalConfigurationJSON(staged.revision.document) !== canonicalConfigurationJSON(input.document)) {
    fail("The reviewed configuration draft no longer matches this environment and import document.");
  }
  const current = await adminRequest(
    `/admin/v1/config-revisions/${staged.revision.id}`,
    RevisionSchema
  );
  if (!current.etag) fail("The Admin API omitted the reviewed draft's strong ETag.");
  if (current.data.id !== staged.revision.id || current.data.environment_id !== input.environmentID ||
    current.data.state !== "valid" ||
    canonicalConfigurationJSON(current.data.document) !== canonicalConfigurationJSON(input.document)) {
    fail("The reviewed configuration draft changed or is no longer activatable. Stage and review the import again.");
  }
  const activated = await adminRequest(
    `/admin/v1/config-revisions/${staged.revision.id}/activate`,
    RevisionSchema,
    { method: "POST", etag: current.etag }
  );
  return {
    revision: activated.data,
    report: staged.report,
    ...(staged.plan ? { plan: staged.plan } : {})
  };
}

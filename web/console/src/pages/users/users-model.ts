import type { ClientComponent, InstallationFamily, InstallationSignal, UserOperationAction } from "../../api/admin";
import type { Severity } from "../../ui";

export const DAY_MS = 86_400_000;

export const KEY_STORAGE_LABEL: Readonly<Record<ClientComponent["key_storage_claim"], string>> = {
  keychain: "Keychain",
  memory: "In memory",
  secure_enclave: "Secure Enclave",
  software: "Software",
  strongbox: "StrongBox",
  tee: "Trusted execution environment",
  unknown: "Not reported",
  webcrypto: "WebCrypto"
};

export const COMPONENT_STATUS_WORDS: Readonly<Record<ClientComponent["status"], string>> = {
  active: "Active",
  replaced: "Replaced",
  revoked: "Revoked",
  suspended: "Suspended"
};

export interface Signal {
  /** What the console suggests; undefined when nothing needs doing. */
  action?: "revoke-installation" | "revoke-component" | "reverify-component";
  componentID?: string;
  id: string;
  label: string;
  severity: Severity;
  text: string;
}

const NATIVE_PLATFORMS = new Set(["ios", "android", "react_native_ios", "react_native_android"]);
const WEAK_STORAGE = new Set(["software", "memory"]);

/** Labels for the signals the server derives for each installation. */
export const SERVER_SIGNAL: Readonly<Record<InstallationSignal, { label: string; severity: Severity }>> = {
  debug_trust: { label: "Debug trust", severity: "critical" },
  failed_sessions: { label: "Failed sessions", severity: "warning" },
  token_reuse: { label: "Token reuse", severity: "critical" },
  trust_expiring: { label: "Trust expiring", severity: "warning" },
  weak_key_storage: { label: "Weak key storage", severity: "warning" }
};

/** Badges for a list row: the server's signals when it sends them, else what the row itself shows. */
export function rowSignals(family: InstallationFamily, environmentKind: string | undefined, now: number): Array<{ id: string; label: string; severity: Severity }> {
  if (family.signals) return family.signals.map((signal) => ({ id: signal, ...SERVER_SIGNAL[signal] }));
  return familySignals(family, environmentKind, now);
}

/** Signals visible from a list row, which carries the family but not its parts. */
export function familySignals(family: InstallationFamily, environmentKind: string | undefined, now: number): Signal[] {
  const signals: Signal[] = [];
  if (family.status === "revoked") return signals;
  if (family.root_trust_source === "debug" && environmentKind !== "development") {
    signals.push({ action: "revoke-installation", id: "debug", label: "Debug trust", severity: "critical", text: "This installation verified with the debug provider outside Development. Debug trust doesn't prove a genuine app." });
  }
  if (family.root_trust_expires_at) {
    const remaining = Date.parse(family.root_trust_expires_at) - now;
    if (remaining > 0 && remaining <= 7 * DAY_MS) {
      const days = Math.max(1, Math.ceil(remaining / DAY_MS));
      signals.push({ id: "trust-expiring", label: `Trust expires in ${days} day${days === 1 ? "" : "s"}`, severity: "warning", text: "Nothing to do: the app renews its trust on its next launch." });
    }
  }
  return signals;
}

/** Signals that need the family's parts, so they appear once an installation is opened. */
export function componentSignals(component: ClientComponent): Signal[] {
  const signals: Signal[] = [];
  if (component.status === "revoked" || component.status === "replaced") return signals;
  if (component.refresh_reuse_count > 0) {
    signals.push({
      action: component.is_root ? "revoke-installation" : "revoke-component",
      componentID: component.id,
      id: `reuse-${component.id}`,
      label: `Token reuse ×${component.refresh_reuse_count}`,
      severity: "critical",
      text: `An already-rotated refresh token for ${component.definition_id} was used again, so a copy of it likely exists.`
    });
  }
  if (NATIVE_PLATFORMS.has(component.platform) && WEAK_STORAGE.has(component.key_storage_claim)) {
    signals.push({ action: "reverify-component", componentID: component.id, id: `storage-${component.id}`, label: "Weak key storage", severity: "warning", text: `${component.definition_id} keeps its key in ${KEY_STORAGE_LABEL[component.key_storage_claim].toLowerCase()} storage, where hardware-backed storage is expected on this platform.` });
  }
  if (component.session_failure_count >= 3) {
    signals.push({ componentID: component.id, id: `sessions-${component.id}`, label: `Failed sessions ×${component.session_failure_count}`, severity: "warning", text: `${component.session_failure_count} session families for ${component.definition_id} ended without a clean sign-out. Ask the user to update; re-verify if it continues.` });
  }
  return signals;
}

export function signalBadgeColor(severity: Severity): "danger" | "warning" | "accent" {
  return severity === "critical" ? "danger" : severity === "warning" ? "warning" : "accent";
}

/** Parts ordered root first, each followed by the parts it delegated to. */
export function orderedParts(components: readonly ClientComponent[]): Array<{ component: ClientComponent; depth: number }> {
  const result: Array<{ component: ClientComponent; depth: number }> = [];
  const visit = (component: ClientComponent, depth: number) => {
    result.push({ component, depth });
    for (const child of components.filter((candidate) => candidate.parent_component_id === component.id)) visit(child, depth + 1);
  };
  for (const root of components.filter((candidate) => candidate.is_root)) visit(root, 0);
  return result;
}

export type GoToRecord =
  | { id: string; kind: "user" | "family" | "component" | "request" }
  | { kind: "invalid" };

const PATTERNS: Array<[RegExp, "user" | "family" | "component" | "request"]> = [
  [/^usr_[A-Za-z0-9_-]{16,128}$/, "user"],
  [/^fam_[A-Za-z0-9_-]{16,128}$/, "family"],
  [/^cmp_[A-Za-z0-9_-]{16,128}$/, "component"],
  [/^req_[A-Za-z0-9_-]{16,128}$/, "request"]
];

/** Go to ID stands in for search: the API has none, and Latchway never stores emails or sign-in subjects. */
export function goToRecord(value: string): GoToRecord {
  const trimmed = value.trim();
  const match = PATTERNS.find(([pattern]) => pattern.test(trimmed));
  return match ? { id: trimmed, kind: match[1] } : { kind: "invalid" };
}

export const GO_TO_HELP = "Latchway never stores emails or sign-in subjects, so it can't search by them. Paste a usr_, fam_, cmp_ or req_ ID; ask the user for their Latchway ID.";

/** Claim values hidden until asked for; keys stay visible. */
export function maskClaim(value: unknown): string {
  return value === null || value === undefined ? "—" : "••••••";
}

export function claimText(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

export const ACTION_TITLE: Readonly<Record<UserOperationAction, string>> = {
  block: "Block user",
  require_app_reverification: "Require app re-verification",
  require_reauthentication: "Require sign-in",
  unblock: "Unblock user"
};

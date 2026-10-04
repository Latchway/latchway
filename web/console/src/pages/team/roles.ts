/**
 * The server's fixed, organization-wide roles (internal/adminauth/role.go). The console only displays this matrix; the
 * server decides every request.
 */
export type Role = "owner" | "admin" | "operator" | "viewer";
export type Capability = "inspect_users" | "run_self_tests" | "revoke_installations" | "activate_configuration" | "manage_secrets" | "manage_owners";

export const ROLES: readonly Role[] = ["owner", "admin", "operator", "viewer"];

export const ROLE_LABEL: Readonly<Record<Role, string>> = { admin: "Admin", operator: "Operator", owner: "Owner", viewer: "Viewer" };

export const ROLE_SUMMARY: Readonly<Record<Role, string>> = {
  admin: "Changes and publishes configuration and manages secrets.",
  operator: "Runs self-tests, blocks users and revokes installs.",
  owner: "Everything, including the team, owners and console sessions.",
  viewer: "Reads users, requests, usage and the audit log."
};

export const CAPABILITIES: ReadonlyArray<{ id: Capability; label: string; pages: string; roles: readonly Role[] }> = [
  { id: "inspect_users", label: "View users, requests, usage and audit", pages: "Requests, Analytics, Users & Installs, Audit Log", roles: ["owner", "admin", "operator", "viewer"] },
  { id: "run_self_tests", label: "Run self-tests", pages: "Self-tests, connection tests", roles: ["owner", "admin", "operator"] },
  { id: "revoke_installations", label: "Block users and revoke installs", pages: "Users & Installs actions", roles: ["owner", "admin", "operator"] },
  { id: "activate_configuration", label: "Change and publish configuration", pages: "Build, Policies & Limits, Changes", roles: ["owner", "admin"] },
  { id: "manage_secrets", label: "Manage secrets and provider keys", pages: "AI Connections › Secrets", roles: ["owner", "admin"] },
  { id: "manage_owners", label: "Manage the team, owners and console sessions", pages: "Team & Access", roles: ["owner"] }
];

export function capabilitiesOf(role: Role): Capability[] {
  return CAPABILITIES.filter((capability) => capability.roles.includes(role)).map((capability) => capability.id);
}

export function capabilityLabel(id: string): string {
  return CAPABILITIES.find((capability) => capability.id === id)?.label ?? id.replaceAll("_", " ");
}

/** What moving from one role to another adds and removes. */
export function roleChange(from: Role, to: Role): { gains: Capability[]; loses: Capability[] } {
  const before = capabilitiesOf(from);
  const after = capabilitiesOf(to);
  return { gains: after.filter((capability) => !before.includes(capability)), loses: before.filter((capability) => !after.includes(capability)) };
}

/** The lowest role that has a capability, for "Needs the Admin role" hints. */
export function lowestRoleWith(capability: string): Role {
  const roles = CAPABILITIES.find((candidate) => candidate.id === capability)?.roles ?? ["owner"];
  return [...ROLES].reverse().find((role) => roles.includes(role)) ?? "owner";
}

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/** A 20-character password from the browser's CSPRNG, without look-alike characters. */
export function generatePassword(length = 20): string {
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => ALPHABET[value % ALPHABET.length]).join("");
}

/** Days until an instant, rounded up; negative when past. */
export function daysUntil(instant: string | undefined, now: number): number | undefined {
  if (!instant) return undefined;
  return Math.ceil((Date.parse(instant) - now) / 86_400_000);
}

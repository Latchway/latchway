import { queryOptions } from "@tanstack/react-query";

import { adminRequest, SystemStatusSchema, type SystemStatus } from "./admin";

export const consoleCompatibilityPollInterval = 15_000;
export const consoleCompatibilityBackgroundExpiry = 30_000;

export interface ConsoleCompatibilityQueryIdentity {
  administratorID: string;
  generation: number;
  organizationID: string;
}

export function consoleCompatibilityQueryOptions(identity: ConsoleCompatibilityQueryIdentity) {
  return queryOptions({
    queryKey: ["console-compatibility", identity] as const,
    queryFn: async ({ signal }) => (await adminRequest("/admin/v1/system", SystemStatusSchema, { signal })).data,
    refetchInterval: consoleCompatibilityPollInterval,
    refetchIntervalInBackground: false,
    // Re-entry is handled by the provider so an expired mutation grant is
    // synchronously closed before this request can begin.
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: consoleCompatibilityBackgroundExpiry
  });
}

export const consoleContractVersion = "1.0.0";
export const consoleProtocolVersion = 2;
export const requiredConsoleServerCapabilities = [
  "app_attest",
  "play_integrity",
  "firebase_app_check",
  "turnstile",
  "component_delegation",
  "cost_limits",
  "openai_responses",
  "openai_chat",
  "openai_embeddings",
  "anthropic_messages",
  "opaque_http",
  "configuration_import_export",
  "admin_session_management"
] as const;
export const optionalConsoleServerCapabilities = ["admin_event_stream"] as const;

export interface ConsoleCompatibility {
  contractCompatible: boolean;
  missingCapabilities: string[];
  protocolCompatible: boolean;
  readOnlySafeMode: boolean;
  reasons: string[];
}

export function evaluateConsoleCompatibility(status: SystemStatus): ConsoleCompatibility {
  const missingCapabilities = requiredConsoleServerCapabilities.filter(
    (capability) => !status.server_capabilities.includes(capability)
  );
  const contractCompatible = status.contract_version === consoleContractVersion;
  const protocolCompatible = status.protocol_versions.includes(consoleProtocolVersion);
  const reasons: string[] = [];
  if (!contractCompatible) reasons.push(`Contract ${consoleContractVersion} is required.`);
  if (!protocolCompatible) reasons.push(`Protocol ${consoleProtocolVersion} is required.`);
  if (missingCapabilities.length > 0) reasons.push(`Missing server capabilities: ${missingCapabilities.join(", ")}.`);
  if (!status.mutation_ready) reasons.push("The administrative database and schema are not ready for mutations.");
  return {
    contractCompatible,
    missingCapabilities,
    protocolCompatible,
    readOnlySafeMode: reasons.length > 0,
    reasons
  };
}

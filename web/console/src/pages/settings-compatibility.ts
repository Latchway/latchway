import type { DoctorReport, SystemStatus } from "../api/admin";

export const consoleContractVersion = "1.0.0";
export const consoleProtocolVersion = 2;
export const requiredSettingsServerCapabilities = [
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
export const optionalSettingsServerCapabilities = ["admin_event_stream"] as const;

export interface SettingsCompatibility {
  contractCompatible: boolean;
  missingCapabilities: string[];
  protocolCompatible: boolean;
  readOnlySafeMode: boolean;
  reasons: string[];
}

export function evaluateSettingsCompatibility(
  status: SystemStatus,
  doctor?: DoctorReport
): SettingsCompatibility {
  const missingCapabilities = requiredSettingsServerCapabilities.filter(
    (capability) => !status.server_capabilities.includes(capability)
  );
  const contractCompatible = status.contract_version === consoleContractVersion
    && (!doctor || doctor.facts.runtime.contract_version === consoleContractVersion);
  const protocolCompatible = status.protocol_versions.includes(consoleProtocolVersion)
    && (!doctor || doctor.facts.runtime.protocol_versions.includes(consoleProtocolVersion));
  const reasons: string[] = [];
  if (!contractCompatible) reasons.push(`Contract ${consoleContractVersion} is required.`);
  if (!protocolCompatible) reasons.push(`Protocol ${consoleProtocolVersion} is required.`);
  if (missingCapabilities.length > 0) reasons.push(`Missing server capabilities: ${missingCapabilities.join(", ")}.`);
  if (!status.ready) reasons.push("The server is not ready for mutations.");
  return {
    contractCompatible,
    missingCapabilities,
    protocolCompatible,
    readOnlySafeMode: reasons.length > 0,
    reasons
  };
}

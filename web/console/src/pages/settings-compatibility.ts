import type { DoctorReport, SystemStatus } from "../api/admin";
import {
  consoleContractVersion,
  consoleProtocolVersion,
  evaluateConsoleCompatibility,
  optionalConsoleServerCapabilities,
  requiredConsoleServerCapabilities,
  type ConsoleCompatibility
} from "../api/console-compatibility";

export { consoleContractVersion, consoleProtocolVersion };
export const requiredSettingsServerCapabilities = requiredConsoleServerCapabilities;
export const optionalSettingsServerCapabilities = optionalConsoleServerCapabilities;
export type SettingsCompatibility = ConsoleCompatibility;

// Kept as the Settings-facing adapter because the doctor report provides an
// independent display-time consistency check. The application-wide mutation
// gate intentionally depends only on the canonical /admin/v1/system contract.
export function evaluateSettingsCompatibility(
  status: SystemStatus,
  doctor?: DoctorReport
): SettingsCompatibility {
  const result = evaluateConsoleCompatibility(status);
  const reasons = [...result.reasons];
  const contractCompatible = result.contractCompatible
    && (!doctor || doctor.facts.runtime.contract_version === consoleContractVersion);
  const protocolCompatible = result.protocolCompatible
    && (!doctor || doctor.facts.runtime.protocol_versions.includes(consoleProtocolVersion));
  if (result.contractCompatible && !contractCompatible) reasons.push(`Doctor contract ${consoleContractVersion} is required.`);
  if (result.protocolCompatible && !protocolCompatible) reasons.push(`Doctor protocol ${consoleProtocolVersion} is required.`);
  return {
    ...result,
    contractCompatible,
    protocolCompatible,
    readOnlySafeMode: reasons.length > 0,
    reasons
  };
}

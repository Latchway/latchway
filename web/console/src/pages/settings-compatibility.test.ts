import { describe, expect, it } from "vitest";

import { evaluateSettingsCompatibility, requiredSettingsServerCapabilities } from "./settings-compatibility";

const systemStatus = {
  contract_version: "1.0.0",
  database_schema_version: "27",
  mutation_ready: true,
  protocol_versions: [1, 2],
  ready: true,
  role: "all" as const,
  server_capabilities: [...requiredSettingsServerCapabilities, "admin_event_stream"],
  server_version: "1.0.0"
};

describe("Settings compatibility", () => {
  it("enters read-only safe mode for protocol, capability, contract, or mutation-readiness gaps", () => {
    const result = evaluateSettingsCompatibility({
      ...systemStatus,
      contract_version: "0.9.0",
      mutation_ready: false,
      protocol_versions: [1],
      ready: false,
      server_capabilities: systemStatus.server_capabilities.filter((item) => item !== "opaque_http")
    });

    expect(result.readOnlySafeMode).toBe(true);
    expect(result.protocolCompatible).toBe(false);
    expect(result.contractCompatible).toBe(false);
    expect(result.missingCapabilities).toEqual(["opaque_http"]);
    expect(result.reasons).toHaveLength(4);
  });

  it("reports traffic readiness without deadlocking administrative remediation", () => {
    expect(evaluateSettingsCompatibility({
      ...systemStatus,
      mutation_ready: true,
      ready: false
    }).readOnlySafeMode).toBe(false);

    const unsafe = evaluateSettingsCompatibility({
      ...systemStatus,
      mutation_ready: false,
      ready: true
    });
    expect(unsafe.readOnlySafeMode).toBe(true);
    expect(unsafe.reasons).toContain("The administrative database and schema are not ready for mutations.");
  });
});

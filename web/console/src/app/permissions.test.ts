import { describe, expect, it } from "vitest";

import type { AdminSession } from "../api/auth";
import { capabilitiesAnywhere, capabilitiesIn } from "./permissions";

const viewer: AdminSession = {
  administrator: { email: "viewer@example.test", enabled: true, id: "adm_0123456789abcdef" },
  application_roles: [{ application_id: "app_0123456789abcdef", role: "admin" }],
  capabilities: ["inspect_users"],
  expires_at: null,
  memberships: [{ organization_id: "org_0123456789abcdef", role: "viewer" }],
  organization_id: "org_0123456789abcdef"
};

describe("permissions", () => {
  it("raises capabilities only in the application with a role", () => {
    expect(capabilitiesIn(viewer, "app_0123456789abcdef")).toEqual(expect.arrayContaining(["activate_configuration", "manage_secrets", "revoke_installations", "run_self_tests", "inspect_users"]));
    expect(capabilitiesIn(viewer, "app_1123456789abcdef")).toEqual(["inspect_users"]);
    expect(capabilitiesIn(viewer, undefined)).toEqual(["inspect_users"]);
    expect(capabilitiesIn(viewer, "app_0123456789abcdef")).not.toContain("manage_owners");
  });

  it("collects what tokens may carry and shows a previewed role without application roles", () => {
    expect(capabilitiesAnywhere(viewer)).toContain("activate_configuration");
    expect(capabilitiesIn(viewer, "app_0123456789abcdef", "viewer")).toEqual(["inspect_users"]);
    expect(capabilitiesIn({ ...viewer, capabilities: ["manage_owners", "inspect_users"] }, undefined, "operator")).toEqual(["inspect_users", "run_self_tests", "revoke_installations"]);
    expect(capabilitiesIn(undefined, "app_0123456789abcdef")).toEqual([]);
  });
});

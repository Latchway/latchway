import { createContext, useContext } from "react";

import type { AdminSession } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { capabilitiesOf, type Role } from "../pages/team/roles";
import { useOptionalWorkspace } from "./workspace-context-value";

/** A role an owner can preview the console as. */
export type PreviewRole = Exclude<Role, "owner">;

export interface RolePreviewState {
  role?: PreviewRole;
  set: (role: PreviewRole | undefined) => void;
}

/**
 * While an owner previews another role the console shows what that role would see and turns changes off. It's a view
 * only: the server checks every request against the owner's own role.
 */
export const RolePreviewContext = createContext<RolePreviewState>({ set: () => undefined });

export function useRolePreview(): RolePreviewState {
  return useContext(RolePreviewContext);
}

/**
 * The capabilities to show for one application: the organization role's, plus what an application role adds there.
 * Application roles only raise; the server applies the same rule to every request.
 */
export function capabilitiesIn(session: AdminSession | undefined, applicationID: string | undefined, preview?: PreviewRole): readonly string[] {
  if (!session) return [];
  if (preview) return capabilitiesOf(preview);
  const raised = applicationID ? session.application_roles?.find((grant) => grant.application_id === applicationID)?.role : undefined;
  return raised ? [...new Set([...session.capabilities, ...capabilitiesOf(raised)])] : session.capabilities;
}

/** Capabilities held anywhere: the organization's and every application role's, as API tokens may carry. */
export function capabilitiesAnywhere(session: AdminSession | undefined, preview?: PreviewRole): readonly string[] {
  if (!session) return [];
  if (preview) return capabilitiesOf(preview);
  return [...new Set([...session.capabilities, ...(session.application_roles ?? []).flatMap((grant) => capabilitiesOf(grant.role))])];
}

/** Capabilities for the application in view, honoring a role preview. */
export function useCapabilities(): { can: (capability: string) => boolean; capabilities: readonly string[]; previewRole?: PreviewRole } {
  const session = useConsoleSession().data?.session;
  const workspace = useOptionalWorkspace();
  const preview = useRolePreview();
  const capabilities = capabilitiesIn(session, workspace?.application?.id, preview.role);
  return { can: (capability) => capabilities.includes(capability), capabilities, previewRole: preview.role };
}

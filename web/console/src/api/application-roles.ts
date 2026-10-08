import { queryOptions } from "@tanstack/react-query";
import { z } from "zod";

import { adminRequest } from "./admin";

const ApplicationRoleGrantSchema = z
  .object({
    admin_user_id: z.string().regex(/^adm_[A-Za-z0-9_-]{16,128}$/),
    application_id: z.string().regex(/^app_[A-Za-z0-9_-]{16,128}$/),
    created_at: z.iso.datetime({ offset: true }),
    granted_by: z.string().max(200),
    role: z.enum(["admin", "operator"]),
    updated_at: z.iso.datetime({ offset: true })
  })
  .strict();

const ApplicationRoleListSchema = z.object({ items: z.array(ApplicationRoleGrantSchema).max(2000) }).strict();

export type ApplicationRoleGrant = z.infer<typeof ApplicationRoleGrantSchema>;

export const applicationRolesQueryOptions = queryOptions({
  queryFn: async ({ signal }) => (await adminRequest("/admin/v1/application-roles", ApplicationRoleListSchema, { signal })).data.items,
  queryKey: ["team", "application-roles"] as const,
  staleTime: 15_000
});

/** Raises a member's role in one application; it never lowers the organization role. */
export async function setApplicationRole(adminUserID: string, applicationID: string, role: ApplicationRoleGrant["role"]): Promise<ApplicationRoleGrant> {
  return (await adminRequest(`/admin/v1/administrators/${adminUserID}/application-roles/${applicationID}`, ApplicationRoleGrantSchema, { body: { role }, method: "PUT" })).data;
}

export async function removeApplicationRole(adminUserID: string, applicationID: string): Promise<void> {
  await adminRequest(`/admin/v1/administrators/${adminUserID}/application-roles/${applicationID}`, z.undefined(), { method: "DELETE" });
}

import { queryOptions } from "@tanstack/react-query";
import { z } from "zod";

import { adminRequest } from "./admin";

const Instant = z.iso.datetime({ offset: true });
const Role = z.enum(["owner", "admin", "operator", "viewer"]);

export const InvitationSchema = z
  .object({
    accepted_at: Instant.optional(),
    created_at: Instant,
    display_name: z.string().min(1).max(200).optional(),
    email: z.string().min(3).max(320),
    email_sent_at: Instant.optional(),
    email_status: z.enum(["not_requested", "sent", "failed"]),
    expires_at: Instant,
    id: z.string().regex(/^ain_[A-Za-z0-9_-]{16,128}$/),
    invited_by: z.string().max(200),
    revoked_at: Instant.optional(),
    role: Role,
    status: z.enum(["pending", "accepted", "revoked", "expired"])
  })
  .strict();

export const InvitationListSchema = z.object({ email_delivery: z.boolean(), items: z.array(InvitationSchema).max(200) }).strict();

const InvitationLinkSchema = z.object({ invitation: InvitationSchema, url: z.string().min(1).max(2200) }).strict();

const ClaimedInvitationSchema = z.object({ organization_id: z.string().regex(/^org_[A-Za-z0-9_-]{16,128}$/), role: Role }).strict();

export type Invitation = z.infer<typeof InvitationSchema>;
export type InvitationLink = z.infer<typeof InvitationLinkSchema>;

export function invitationsQueryOptions(organizationID: string) {
  return queryOptions({
    queryFn: async ({ signal }) => (await adminRequest(`/admin/v1/organizations/${organizationID}/invitations`, InvitationListSchema, { signal })).data,
    queryKey: ["team", "invitations", organizationID] as const,
    staleTime: 15_000
  });
}

export interface InvitationInput {
  display_name?: string;
  email: string;
  role: z.infer<typeof Role>;
  send_email: boolean;
}

/** Invites an address; the link comes back once. */
export async function createInvitation(organizationID: string, input: InvitationInput): Promise<InvitationLink> {
  return (await adminRequest(`/admin/v1/organizations/${organizationID}/invitations`, InvitationLinkSchema, { body: input, method: "POST" })).data;
}

/** Replaces the link and the expiry; the earlier link stops working. */
export async function renewInvitation(organizationID: string, invitationID: string, sendEmail: boolean): Promise<InvitationLink> {
  return (await adminRequest(`/admin/v1/organizations/${organizationID}/invitations/${invitationID}/renew`, InvitationLinkSchema, { body: { send_email: sendEmail }, method: "POST" })).data;
}

export async function revokeInvitation(organizationID: string, invitationID: string): Promise<Invitation> {
  return (await adminRequest(`/admin/v1/organizations/${organizationID}/invitations/${invitationID}/revoke`, InvitationSchema, { method: "POST" })).data;
}

/** Adds the signed-in administrator to the organization the invitation is for. */
export async function claimInvitation(token: string) {
  return (await adminRequest("/admin/v1/auth/invitations/claim", ClaimedInvitationSchema, { body: { token }, method: "POST" })).data;
}

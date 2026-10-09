import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { type AdminProblem, type AdminSession, type InvitationPreview, previewInvitation, problemFromError, switchAdminOrganization } from "../../api/auth";
import { claimInvitation } from "../../api/invitations";
import { consoleSessionQueryOptions, consoleStateFromAdminSession } from "../../api/session";
import { ROLE_LABEL } from "../../pages/team/roles";
import { Button } from "../../ui";
import { AccountDialogFrame, AuthProblem } from "./auth-fields";
import { forgetInvitation, pendingInvitation } from "./invitation-link";

/**
 * Offers an invitation link opened while signed in. Accepting adds this account to the organization and, unless the
 * session came from single sign-on, moves the session there.
 */
export function InvitationClaimDialog({ onClose, onSignOut, onSwitched, session }: { onClose: () => void; onSignOut: () => void; onSwitched: () => void; session: AdminSession }) {
  const queryClient = useQueryClient();
  const invitation = pendingInvitation();
  const token = invitation && "token" in invitation ? invitation.token : undefined;
  const [preview, setPreview] = useState<InvitationPreview>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [pending, setPending] = useState(false);
  const [joinedWithSSO, setJoinedWithSSO] = useState<string>();

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    previewInvitation(token, controller.signal).then(setPreview, (error: unknown) => {
      if (!controller.signal.aborted) setProblem(problemFromError(error));
    });
    return () => controller.abort();
  }, [token]);

  function dismiss(): void {
    forgetInvitation();
    onClose();
  }

  async function accept(): Promise<void> {
    if (!token || !preview) return;
    setPending(true);
    setProblem(undefined);
    try {
      const joined = await claimInvitation(token);
      forgetInvitation();
      if (session.sign_in_method === "sso") {
        setJoinedWithSSO(preview.organization_name);
        setPending(false);
        return;
      }
      queryClient.setQueryData(consoleSessionQueryOptions.queryKey, consoleStateFromAdminSession(await switchAdminOrganization(joined.organization_id)));
      onSwitched();
    } catch (error) {
      setProblem(problemFromError(error));
      setPending(false);
    }
  }

  const otherAddress = preview && preview.email.toLowerCase() !== session.administrator.email.toLowerCase();
  let description = "Checking the invitation…";
  if (!token) description = "The invitation link is incomplete. Open the whole link, or ask an owner to send it again.";
  else if (joinedWithSSO) description = `You joined ${joinedWithSSO}. This session came from single sign-on, so it stays where it is: sign out, then sign in to ${joinedWithSSO}.`;
  else if (otherAddress) description = `This invitation is for ${preview.email}, but you're signed in as ${session.administrator.email}. Sign out, then open the link again to accept it.`;
  else if (preview) description = `${preview.invited_by} invited you to join ${preview.organization_name} as ${ROLE_LABEL[preview.role]}. Joining moves this session there.`;
  else if (problem) description = "This invitation can't be used.";
  return (
    <AccountDialogFrame description={description} onEscape={pending ? undefined : dismiss} title={joinedWithSSO ? "Invitation accepted" : "Join an organization"}>
      <div className="lw-confirm__body lw-auth__form">
        {problem ? <AuthProblem problem={problem} /> : null}
        <div className="lw-confirm__foot">
          {joinedWithSSO || !preview || problem ? <Button onClick={dismiss} size="sm">Close</Button> : otherAddress ? (
            <>
              <Button onClick={dismiss} size="sm">Not Now</Button>
              <Button onClick={onSignOut} size="sm" variant="primary">Sign Out</Button>
            </>
          ) : (
            <>
              <Button disabled={pending} onClick={dismiss} size="sm">Not Now</Button>
              <Button loading={pending} onClick={() => void accept()} size="sm" variant="primary">Join {preview.organization_name}</Button>
            </>
          )}
        </div>
      </div>
    </AccountDialogFrame>
  );
}

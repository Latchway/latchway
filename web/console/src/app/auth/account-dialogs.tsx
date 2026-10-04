import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, useRef, useState } from "react";

import { type AdminProblem, type AdminSession, loginAdministrator, problemFromError } from "../../api/auth";
import { consoleSessionQueryOptions, consoleStateFromAdminSession } from "../../api/session";
import { organizationsQueryOptions } from "../../api/workspace";
import { ROLE_LABEL } from "../../pages/team/roles";
import { Button, buttonClass, Field, Properties } from "../../ui";
import { scopeSearch } from "../navigation";
import { AccountDialogFrame, AuthProblem, PasswordInput } from "./auth-fields";
import { sessionEndText } from "./session-model";

/** Signs in again as the same administrator, into the given organization, and replaces the console's session. */
function useSignInAgain(session: AdminSession) {
  const queryClient = useQueryClient();
  const password = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  async function submit(organizationID: string): Promise<AdminSession | undefined> {
    setPending(true);
    setProblem(undefined);
    try {
      const next = await loginAdministrator({ email: session.administrator.email, organization_id: organizationID, password: password.current?.value ?? "" });
      queryClient.setQueryData(consoleSessionQueryOptions.queryKey, consoleStateFromAdminSession(next));
      return next;
    } catch (error) {
      setProblem(problemFromError(error));
      password.current?.focus();
      return undefined;
    } finally {
      if (password.current) password.current.value = "";
      setPending(false);
    }
  }
  return { password, pending, problem, submit };
}

/**
 * Sign in again without leaving the page. When the session has ended it can't be dismissed, only completed or traded
 * for a different account; when it's offered early the operator can close it.
 */
export function ReauthDialog({ onClose, onSignedIn, onSomeoneElse, session }: { onClose?: () => void; onSignedIn: () => void; onSomeoneElse: () => void; session: AdminSession }) {
  const queryClient = useQueryClient();
  const again = useSignInAgain(session);
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!(await again.submit(session.organization_id))) return;
    await queryClient.invalidateQueries({ predicate: (query) => query.queryKey[0] !== consoleSessionQueryOptions.queryKey[0] });
    onSignedIn();
  }
  return (
    <AccountDialogFrame
      description={onClose ? "Start a new session now so this one doesn't end while you work." : "Sign in again to carry on. This page stays as it was; anything that failed while you were signed out needs another try."}
      onEscape={onClose && !again.pending ? onClose : undefined}
      title={onClose ? "Sign in again" : "Your session ended"}
    >
      <form className="lw-confirm__body lw-auth__form" onSubmit={(event) => void submit(event)}>
        <Field id="reauth-email" label="Email address">
          <div className="lw-input-box" data-disabled="">
            <input autoComplete="username" className="lw-input" id="reauth-email" readOnly value={session.administrator.email} />
          </div>
        </Field>
        <PasswordInput autoFocus disabled={again.pending} id="reauth-password" inputRef={again.password} />
        {again.problem ? <AuthProblem problem={again.problem} /> : null}
        <div className="lw-confirm__foot">
          <Button disabled={again.pending} onClick={onSomeoneElse} size="sm" variant="ghost">Sign in as someone else</Button>
          {onClose ? <Button disabled={again.pending} onClick={onClose} size="sm">Cancel</Button> : null}
          <Button loading={again.pending} size="sm" type="submit" variant="primary">Sign In</Button>
        </div>
      </form>
    </AccountDialogFrame>
  );
}

/** Each session belongs to one organization, so switching signs in again into the other one. */
export function SwitchOrganizationDialog({ onClose, onSwitched, session }: { onClose: () => void; onSwitched: () => void; session: AdminSession }) {
  const organizations = useQuery(organizationsQueryOptions());
  const names = new Map((organizations.data?.items ?? []).map((item) => [item.id, item.display_name]));
  const others = session.memberships.filter((membership) => membership.organization_id !== session.organization_id);
  const [target, setTarget] = useState(others[0]?.organization_id ?? "");
  const again = useSignInAgain(session);
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!target || !(await again.submit(target))) return;
    onSwitched();
  }
  return (
    <AccountDialogFrame description="Each session works in one organization, so switching signs you in again." onEscape={again.pending ? undefined : onClose} title="Switch organization">
      <form className="lw-confirm__body lw-auth__form" onSubmit={(event) => void submit(event)}>
        <Field id="switch-organization" label="Organization">
          <div className="lw-input-box">
            <select className="lw-input" disabled={again.pending} id="switch-organization" onChange={(event) => setTarget(event.target.value)} value={target}>
              {others.map((membership) => <option key={membership.organization_id} value={membership.organization_id}>{names.get(membership.organization_id) ?? membership.organization_id} · {ROLE_LABEL[membership.role]}</option>)}
            </select>
          </div>
        </Field>
        <PasswordInput autoFocus disabled={again.pending} id="switch-password" inputRef={again.password} />
        <p className="lw-auth__fine">Your current session isn't signed out by the switch; it stops being used and ends when it expires.</p>
        {again.problem ? <AuthProblem problem={again.problem} /> : null}
        <div className="lw-confirm__foot">
          <Button disabled={again.pending} onClick={onClose} size="sm">Cancel</Button>
          <Button disabled={!target} loading={again.pending} size="sm" type="submit" variant="primary">Switch</Button>
        </div>
      </form>
    </AccountDialogFrame>
  );
}

/** Who is signed in, where and until when. Changing your own password has no API yet, so the dialog says so. */
export function AccountDialog({ onClose, organizationName, session }: { onClose: () => void; organizationName?: string; session: AdminSession }) {
  const role = session.memberships.find((membership) => membership.organization_id === session.organization_id)?.role;
  const owner = session.capabilities.includes("manage_owners");
  return (
    <AccountDialogFrame onEscape={onClose} title="Your account">
      <div className="lw-confirm__body">
        <Properties items={[
          { label: "Email", value: session.administrator.email },
          { label: "Role", value: role ? ROLE_LABEL[role] : "Unknown" },
          { label: "Organization", value: organizationName ?? session.organization_id },
          { label: "Session ends", value: session.expires_at ? sessionEndText(session.expires_at) : "Not reported" }
        ]} />
        <p className="lw-auth__fine">The console can't change your own password: the Admin API has no endpoint for it yet. {owner ? "Another owner" : "An owner"} can reset it from Team › Members.</p>
        {owner ? <Link className={buttonClass({ size: "sm" })} onClick={onClose} search={scopeSearch} to="/admin-sessions">Review Sessions</Link> : null}
      </div>
      <div className="lw-confirm__foot">
        <Button onClick={onClose} size="sm" variant="primary">Done</Button>
      </div>
    </AccountDialogFrame>
  );
}

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useRef, useState } from "react";

import { type AdminProblem, type AdminSession, finishSecondFactor, problemFromError, type SecondFactorAnswer, type SecondFactorMethod, startAdministratorSignIn, startSingleSignOn, switchAdminOrganization } from "../../api/auth";
import { consoleSessionQueryOptions, consoleStateFromAdminSession } from "../../api/session";
import { organizationsQueryOptions } from "../../api/workspace";
import { ROLE_LABEL } from "../../pages/team/roles";
import { Button, Field, Notice } from "../../ui";
import { AccountDialogFrame, AuthProblem, PasswordInput } from "./auth-fields";
import { leaveFor } from "./leave-for";
import { SecondFactorForm } from "./second-factor";

/**
 * Signs in again as the same administrator into the given organization and replaces the console's session. A
 * two-factor account answers the password with a challenge, finished by the code step.
 */
function useSignInAgain(session: AdminSession) {
  const queryClient = useQueryClient();
  const password = useRef<HTMLInputElement>(null);
  const challenge = useRef<string | undefined>(undefined);
  const [step, setStep] = useState<"password" | "two-factor">("password");
  const [methods, setMethods] = useState<readonly SecondFactorMethod[]>([]);
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  function accept(next: AdminSession): AdminSession {
    queryClient.setQueryData(consoleSessionQueryOptions.queryKey, consoleStateFromAdminSession(next));
    return next;
  }
  async function submit(organizationID: string): Promise<AdminSession | undefined> {
    setPending(true);
    setProblem(undefined);
    try {
      const result = await startAdministratorSignIn({ email: session.administrator.email, organization_id: organizationID, password: password.current?.value ?? "" });
      if (result.kind === "challenge") {
        challenge.current = result.challenge.challenge;
        setMethods(result.challenge.methods);
        setStep("two-factor");
        return undefined;
      }
      return accept(result.session);
    } catch (error) {
      setProblem(problemFromError(error));
      password.current?.focus();
      return undefined;
    } finally {
      if (password.current) password.current.value = "";
      setPending(false);
    }
  }
  async function verify(answer: SecondFactorAnswer): Promise<AdminSession | undefined> {
    if (!challenge.current) return undefined;
    setPending(true);
    setProblem(undefined);
    try {
      const next = await finishSecondFactor(challenge.current, answer);
      challenge.current = undefined;
      return accept(next);
    } catch (error) {
      const found = problemFromError(error);
      if (found.detail.includes("Sign in again")) {
        challenge.current = undefined;
        setStep("password");
      }
      setProblem(found);
      return undefined;
    } finally {
      setPending(false);
    }
  }
  return { methods, password, pending, problem, step, submit, verify };
}

/**
 * A single sign-on session signs in again at the identity provider, which means leaving the page; the console comes
 * back to its start once the provider answers.
 */
function SingleSignOnAgain({ endReason, onClose, onSomeoneElse, session }: { endReason?: string; onClose?: () => void; onSomeoneElse: () => void; session: AdminSession }) {
  const organizations = useQuery(organizationsQueryOptions());
  const slug = organizations.data?.items.find((item) => item.id === session.organization_id)?.slug;
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  async function start(): Promise<void> {
    if (!slug) return;
    setPending(true);
    setProblem(undefined);
    try {
      leaveFor(await startSingleSignOn(slug));
    } catch (error) {
      setProblem(problemFromError(error));
      setPending(false);
    }
  }
  return (
    <AccountDialogFrame
      description={`${endReason ? `${endReason} ` : ""}You signed in with your organization's identity provider. Signing in again leaves this page; unsaved changes here are lost.`}
      onEscape={onClose && !pending ? onClose : undefined}
      title={onClose ? "Sign in again" : "Your session ended"}
    >
      <div className="lw-confirm__body lw-auth__form">
        {organizations.error ? <Notice tone="warning">The console can&apos;t look up your organization while signed out. Sign out and choose Sign In with SSO.</Notice> : null}
        {problem ? <AuthProblem problem={problem} /> : null}
        <div className="lw-confirm__foot">
          <Button disabled={pending} onClick={onSomeoneElse} size="sm" variant="ghost">Sign out</Button>
          {onClose ? <Button disabled={pending} onClick={onClose} size="sm">Cancel</Button> : null}
          <Button disabled={!slug} loading={pending} onClick={() => void start()} size="sm" variant="primary">Sign In with SSO</Button>
        </div>
      </div>
    </AccountDialogFrame>
  );
}

/**
 * Sign in again without leaving the page. When the session has ended it can't be dismissed, only completed or traded
 * for a different account; when it's offered early the operator can close it.
 */
export function ReauthDialog({ endReason, onClose, onSignedIn, onSomeoneElse, session }: { endReason?: string; onClose?: () => void; onSignedIn: () => void; onSomeoneElse: () => void; session: AdminSession }) {
  if (session.sign_in_method === "sso") return <SingleSignOnAgain endReason={endReason} onClose={onClose} onSomeoneElse={onSomeoneElse} session={session} />;
  return <PasswordSignInAgain endReason={endReason} onClose={onClose} onSignedIn={onSignedIn} onSomeoneElse={onSomeoneElse} session={session} />;
}

function PasswordSignInAgain({ endReason, onClose, onSignedIn, onSomeoneElse, session }: { endReason?: string; onClose?: () => void; onSignedIn: () => void; onSomeoneElse: () => void; session: AdminSession }) {
  const queryClient = useQueryClient();
  const again = useSignInAgain(session);
  async function finished(next: AdminSession | undefined): Promise<void> {
    if (!next) return;
    await queryClient.invalidateQueries({ predicate: (query) => query.queryKey[0] !== consoleSessionQueryOptions.queryKey[0] });
    onSignedIn();
  }
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    await finished(await again.submit(session.organization_id));
  }
  return (
    <AccountDialogFrame
      description={onClose ? "Start a new session now so this one doesn't end while you work." : `${endReason ? `${endReason} ` : ""}Sign in again to carry on. This page stays as it was; anything that failed while you were signed out needs another try.`}
      onEscape={onClose && !again.pending ? onClose : undefined}
      title={onClose ? "Sign in again" : "Your session ended"}
    >
      {again.step === "two-factor" ? (
        <div className="lw-confirm__body">
          <SecondFactorForm idPrefix="reauth" methods={again.methods} onSubmit={(answer) => void again.verify(answer).then(finished)} pending={again.pending} problem={again.problem} />
        </div>
      ) : (
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
      )}
    </AccountDialogFrame>
  );
}

/** Moves this console session to another organization; the server ends the current session in the same step. */
export function SwitchOrganizationDialog({ onClose, onSwitched, session }: { onClose: () => void; onSwitched: () => void; session: AdminSession }) {
  const queryClient = useQueryClient();
  const organizations = useQuery(organizationsQueryOptions());
  const names = new Map((organizations.data?.items ?? []).map((item) => [item.id, item.display_name]));
  const others = session.memberships.filter((membership) => membership.organization_id !== session.organization_id);
  const [target, setTarget] = useState(others[0]?.organization_id ?? "");
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!target) return;
    setPending(true);
    setProblem(undefined);
    try {
      const next = await switchAdminOrganization(target);
      queryClient.setQueryData(consoleSessionQueryOptions.queryKey, consoleStateFromAdminSession(next));
      onSwitched();
    } catch (error) {
      setProblem(problemFromError(error));
      setPending(false);
    }
  }
  if (session.sign_in_method === "sso") {
    return (
      <AccountDialogFrame description="A single sign-on session stays in the organization it signed in to. Sign out, then sign in to the other organization." onEscape={onClose} title="Switch organization">
        <div className="lw-confirm__body"><div className="lw-confirm__foot"><Button onClick={onClose} size="sm">Close</Button></div></div>
      </AccountDialogFrame>
    );
  }
  return (
    <AccountDialogFrame description="This session moves to the organization you pick; nothing else changes." onEscape={pending ? undefined : onClose} title="Switch organization">
      <form className="lw-confirm__body lw-auth__form" onSubmit={(event) => void submit(event)}>
        <Field id="switch-organization" label="Organization">
          <div className="lw-input-box">
            <select className="lw-input" disabled={pending} id="switch-organization" onChange={(event) => setTarget(event.target.value)} value={target}>
              {others.map((membership) => <option key={membership.organization_id} value={membership.organization_id}>{names.get(membership.organization_id) ?? membership.organization_id} · {ROLE_LABEL[membership.role]}</option>)}
            </select>
          </div>
        </Field>
        {problem ? <AuthProblem problem={problem} /> : null}
        <div className="lw-confirm__foot">
          <Button disabled={pending} onClick={onClose} size="sm">Cancel</Button>
          <Button disabled={!target} loading={pending} size="sm" type="submit" variant="primary">Switch</Button>
        </div>
      </form>
    </AccountDialogFrame>
  );
}

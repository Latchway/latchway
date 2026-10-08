import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { type FormEvent, type RefObject, useEffect, useId, useRef, useState } from "react";

import {
  acceptInvitation,
  type AdminProblem,
  type AdminSession,
  adminSignInInfoQueryOptions,
  bootstrapFirstOwner,
  finishSecondFactor,
  type InvitationPreview,
  logoutAdministrator,
  previewInvitation,
  problemFromError,
  type SecondFactorAnswer,
  type SecondFactorMethod,
  signInWithPasskey,
  startAdministratorSignIn,
  startSingleSignOn,
  switchAdminOrganization
} from "../../api/auth";
import { consoleContractVersion } from "../../api/console-compatibility";
import { consoleSessionQueryOptions, consoleStateFromAdminSession } from "../../api/session";
import { passkeysAvailable } from "../../api/webauthn";
import { organizationsQueryOptions } from "../../api/workspace";
import { PasswordField } from "../../components/password-field";
import { ROLE_LABEL } from "../../pages/team/roles";
import { Badge, Button, Field, Icon, Input, Notice, Segmented } from "../../ui";
import { AuthProblem, PasswordInput } from "./auth-fields";
import { AuthLayout } from "./auth-layout";
import { lastSignedOutEmail, pauseSignIn, rememberSignedOutEmail, signInPausedUntil, wallClock } from "./auth-memory";
import { forgetInvitation, pendingInvitation } from "./invitation-link";
import { leaveFor } from "./leave-for";
import { acceptable, passwordStrength, type Strength } from "./password-strength";
import { SecondFactorForm } from "./second-factor";
import { StrengthMeter } from "./strength-meter";
import { type Platform, PLATFORMS, REMOVE_TOKEN_STEPS, SETUP_FIELDS, type SetupField, slugify, validateSetup } from "./setup-model";
import { forgetSSOReturn, ssoReturnMessage } from "./sso-return";

type View = "sign-in" | "invitation" | "sso" | "two-factor" | "choose-org" | "setup" | "setup-done" | "setup-closed" | "signed-out";

/** Failed attempts before the console mentions the server's pause, ahead of the pause itself. */
const PAUSE_NOTE_AFTER = 3;

function formText(form: HTMLFormElement, name: string): string {
  const field = form.elements.namedItem(name);
  return field instanceof HTMLInputElement ? field.value : "";
}

function clearInput(input: HTMLInputElement | null): void {
  if (input) input.value = "";
}

function SignInHelp() {
  return (
    <details className="lw-auth__help">
      <summary>Can't sign in?</summary>
      <ul>
        <li>A wrong password, an unknown email and a disabled account all get the same answer, so the console can't tell you which it was.</li>
        <li><strong>Forgot your password?</strong> Ask an owner to reset it from Team › Members, or with <span className="lw-code-inline">latchway admin accounts reset-password ADMIN_USER_ID --from-stdin</span>.</li>
        <li>There's no self-service reset. If you're the only owner, nobody else can reset your password, so add a second owner once you're in.</li>
      </ul>
    </details>
  );
}

/** Counts down the server's sign-in pause; mounted fresh for each pause so its clock starts when the pause does. */
function PauseNotice({ onElapsed, until }: { onElapsed: () => void; until: number }) {
  const [now, setNow] = useState(wallClock);
  const remaining = Math.max(0, Math.ceil((until - now) / 1000));
  const elapsed = useRef(onElapsed);
  useEffect(() => {
    elapsed.current = onElapsed;
  });
  useEffect(() => {
    const timer = window.setInterval(() => {
      const current = wallClock();
      setNow(current);
      if (current >= until) elapsed.current();
    }, 1000);
    return () => window.clearInterval(timer);
  }, [until]);
  return (
    <Notice title="Sign-in is paused for this email address." tone="warning">
      Too many failed attempts. Try again in <span className="lw-num" role="timer">{Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, "0")}</span>.
    </Notice>
  );
}

function SSOReturnNotice() {
  const message = ssoReturnMessage();
  return message ? <Notice title="Single sign-on didn't finish" tone="warning">{message}</Notice> : null;
}

const ROLE_ARTICLE: Readonly<Record<InvitationPreview["role"], string>> = { admin: "an Admin", operator: "an Operator", owner: "an Owner", viewer: "a Viewer" };

/**
 * Accepting an invitation link while signed out. A new address chooses a name and password here; an address that
 * already has an account signs in first and is offered the invitation inside the console.
 */
function InvitationView({ onAccepted, onSignIn }: { onAccepted: (session: AdminSession) => void; onSignIn: (email: string) => void }) {
  const invitation = pendingInvitation();
  const [preview, setPreview] = useState<InvitationPreview>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [pending, setPending] = useState(false);
  const [strength, setStrength] = useState<Strength>();
  const password = useRef<HTMLInputElement>(null);
  const name = useRef<HTMLInputElement>(null);
  const token = invitation && "token" in invitation ? invitation.token : undefined;

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    previewInvitation(token, controller.signal).then(setPreview, (error: unknown) => {
      if (!controller.signal.aborted) setProblem(problemFromError(error));
    });
    return () => controller.abort();
  }, [token]);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!token) return;
    if (!acceptable(passwordStrength(password.current?.value ?? ""))) {
      setProblem({ code: "request_invalid", detail: "Choose a password rated Good or Strong: at least 12 characters with some variety, or a longer passphrase.", retryable: false, status: 0, title: "Choose a stronger password" });
      password.current?.focus();
      return;
    }
    setPending(true);
    setProblem(undefined);
    try {
      const session = await acceptInvitation(token, name.current?.value ?? "", password.current);
      forgetInvitation();
      onAccepted(session);
    } catch (error) {
      setProblem(problemFromError(error));
      setStrength(undefined);
      setPending(false);
    }
  }

  if (!token) {
    return <Notice title="This invitation link is incomplete" tone="warning">Open the whole link from the invitation, or ask an owner to send it again.</Notice>;
  }
  if (!preview) {
    return problem ? <AuthProblem problem={problem} /> : <span aria-live="polite" className="lw-auth__fine">Checking the invitation…</span>;
  }
  const summary = <p className="lw-auth__lead">{preview.invited_by} invited you to join <strong>{preview.organization_name}</strong> as {ROLE_ARTICLE[preview.role]}.</p>;
  if (preview.account_exists) {
    return (
      <div className="lw-auth__body">
        {summary}
        <p className="lw-auth__fine">{preview.email} already has a Latchway account. Sign in to it, and you&apos;ll be asked to join {preview.organization_name}.</p>
        <Button className="lw-auth__submit" onClick={() => onSignIn(preview.email)} variant="primary">Sign In to Accept</Button>
      </div>
    );
  }
  return (
    <form aria-busy={pending} className="lw-auth__form" onSubmit={(event) => void submit(event)}>
      {summary}
      <Field id="invitation-email" label="Email address">
        <div className="lw-input-box" data-disabled=""><input autoComplete="username" className="lw-input" id="invitation-email" readOnly value={preview.email} /></div>
      </Field>
      <Field id="invitation-name" label="Your name">
        <div className="lw-input-box"><input autoComplete="name" className="lw-input" defaultValue={preview.display_name ?? ""} disabled={pending} id="invitation-name" maxLength={200} ref={name} required /></div>
      </Field>
      <PasswordField id="invitation-password" inputRef={password} label="Choose a password" name="new_password" onValueChange={(value) => setStrength(value ? passwordStrength(value) : undefined)} />
      <StrengthMeter strength={strength} />
      {problem ? <AuthProblem problem={problem} /> : null}
      <Button className="lw-auth__submit" loading={pending} type="submit" variant="primary">Join {preview.organization_name}</Button>
      <p className="lw-auth__fine">The invitation expires {new Date(preview.expires_at).toLocaleString()}.</p>
    </form>
  );
}

function SingleSignOnView({ onBack, onSubmit, pending, problem }: { onBack: () => void; onSubmit: (slug: string) => void; pending: boolean; problem?: AdminProblem }) {
  const slug = useRef<HTMLInputElement>(null);
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const value = slug.current?.value.trim() ?? "";
    if (value) onSubmit(value);
  }
  return (
    <div className="lw-auth__body">
      <SSOReturnNotice />
      <form aria-busy={pending} className="lw-auth__form" onSubmit={submit}>
        <Field hint="Your organization's short name, as it appears in console links, like acme. An owner can tell you." id="sso-organization" label="Organization">
          <div className="lw-input-box">
            <input autoCapitalize="none" autoComplete="organization" autoFocus className="lw-input" disabled={pending} id="sso-organization" maxLength={128} name="organization" ref={slug} required spellCheck={false} />
          </div>
        </Field>
        {problem ? <AuthProblem problem={problem} /> : null}
        <Button className="lw-auth__submit" loading={pending} type="submit" variant="primary">Continue to Your Identity Provider</Button>
      </form>
      <Button className="lw-auth__link" disabled={pending} onClick={onBack} size="sm" variant="ghost">Sign in with email instead</Button>
    </div>
  );
}

function SignInView({ email, emailRef, endReason, failures, mismatch, onPasskey, onSSO, onSetup, onSubmit, passwordRef, pending, problem, setEmail }: {
  email: string;
  emailRef: RefObject<HTMLInputElement | null>;
  endReason?: string;
  failures: number;
  /** The server's advertised contract when it differs from this console's. */
  mismatch?: string;
  /** Offered when the server accepts passkeys and this browser can use them. */
  onPasskey?: () => void;
  /** Offered when an organization on this server has single sign-on. */
  onSSO?: () => void;
  onSetup: () => void;
  onSubmit: () => void;
  passwordRef: RefObject<HTMLInputElement | null>;
  pending: "password" | "passkey" | undefined;
  problem?: AdminProblem;
  setEmail: (email: string) => void;
}) {
  const pausedUntil = signInPausedUntil(email);
  const [elapsedFor, setElapsedFor] = useState<number>();
  const paused = pausedUntil !== undefined && elapsedFor !== pausedUntil;
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (paused) return;
    onSubmit();
  }
  return (
    <div className="lw-auth__body">
      {mismatch ? <Notice title="This console and server are from different releases." tone="warning">The console expects contract {consoleContractVersion}; the server reports {mismatch}. Sign-in may fail until an upgrade finishes; reload this page afterwards.</Notice> : null}
      {endReason ? <Notice title="Your session ended">{endReason}</Notice> : null}
      <SSOReturnNotice />
      <form aria-busy={Boolean(pending)} className="lw-auth__form" onSubmit={submit}>
        <Field id="login-email" label="Email address">
          <div className="lw-input-box">
            <input autoComplete="username" className="lw-input" disabled={Boolean(pending)} id="login-email" maxLength={320} name="email" onChange={(event) => setEmail(event.target.value)} ref={emailRef} required spellCheck={false} type="email" value={email} />
          </div>
        </Field>
        <PasswordInput disabled={Boolean(pending)} id="login-password" inputRef={passwordRef} />
        {paused ? <PauseNotice key={pausedUntil} onElapsed={() => setElapsedFor(pausedUntil)} until={pausedUntil} /> : problem ? <AuthProblem problem={problem} /> : null}
        {failures >= PAUSE_NOTE_AFTER && !paused ? <p className="lw-auth__fine">After five failed attempts for one email address within five minutes, the server pauses sign-in for that address for up to five minutes.</p> : null}
        <Button className="lw-auth__submit" disabled={paused || pending === "passkey"} loading={pending === "password"} type="submit" variant="primary">{pending === "password" ? "Signing In…" : "Sign In"}</Button>
      </form>
      {onPasskey || onSSO ? (
        <div className="lw-auth__alternative">
          <span className="lw-auth__divider">or</span>
          {onPasskey ? <Button className="lw-auth__submit" disabled={pending === "password"} icon="key" loading={pending === "passkey"} onClick={onPasskey}>Sign In with a Passkey</Button> : null}
          {onSSO ? <Button className="lw-auth__submit" disabled={Boolean(pending)} icon="team" onClick={onSSO}>Sign In with SSO</Button> : null}
        </div>
      ) : null}
      <SignInHelp />
      <Button className="lw-auth__link" onClick={onSetup} size="sm" variant="ghost">Setting up a new server?</Button>
    </div>
  );
}

function ChooseOrganizationView({ onBack, onChoose, pending, problem, session }: { onBack: () => void; onChoose: (organizationID: string) => void; pending?: string; problem?: AdminProblem; session: AdminSession }) {
  const organizations = useQuery(organizationsQueryOptions());
  const names = new Map((organizations.data?.items ?? []).map((item) => [item.id, item]));
  return <>
    <ul aria-label="Your organizations" className="lw-orglist">
      {session.memberships.map((membership) => {
        const organization = names.get(membership.organization_id);
        const name = organization?.display_name ?? membership.organization_id;
        return (
          <li key={membership.organization_id}>
            <button aria-busy={pending === membership.organization_id} className="lw-orglist__item" disabled={Boolean(pending)} onClick={() => onChoose(membership.organization_id)} type="button">
              <span aria-hidden="true" className="lw-orglist__tile">{name.slice(0, 1).toUpperCase()}</span>
              <span className="lw-orglist__text"><strong>{name}</strong><span>{ROLE_LABEL[membership.role]}{organization ? ` · ${organization.slug}` : ""}</span></span>
              {membership.organization_id === session.organization_id ? <Badge title="Your last organization, or your first membership">Default</Badge> : null}
              <Icon name={pending === membership.organization_id ? "spinner" : "chevronRight"} spin={pending === membership.organization_id} />
            </button>
          </li>
        );
      })}
    </ul>
    {organizations.isError ? <p className="lw-auth__fine">Organization names couldn't be loaded, so IDs are shown instead.</p> : null}
    {problem ? <AuthProblem problem={problem} /> : null}
    <Button className="lw-auth__link" disabled={Boolean(pending)} onClick={onBack} size="sm" variant="ghost">Sign in as someone else</Button>
  </>;
}

function SetupView({ onCancel, onSubmit, pending, problem }: { onCancel: () => void; onSubmit: (form: HTMLFormElement, password: HTMLInputElement | null) => void; pending: boolean; problem?: AdminProblem }) {
  const [errors, setErrors] = useState<Partial<Record<SetupField, string>>>({});
  const [strength, setStrength] = useState<Strength>();
  const slugEdited = useRef(false);
  const password = useRef<HTMLInputElement>(null);
  const bannerID = useId();

  function suggestSlug(form: HTMLFormElement | null, name: string): void {
    if (slugEdited.current || !form) return;
    const slug = form.elements.namedItem("organization_slug");
    if (slug instanceof HTMLInputElement) slug.value = slugify(name);
  }

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const form = event.currentTarget;
    const found = validateSetup({
      bootstrap_token: formText(form, "bootstrap_token"),
      display_name: formText(form, "display_name"),
      email: formText(form, "email"),
      organization_name: formText(form, "organization_name"),
      organization_slug: formText(form, "organization_slug"),
      password: password.current?.value ?? ""
    });
    setErrors(found);
    const first = SETUP_FIELDS.find((field) => found[field]);
    if (first) {
      const element = form.elements.namedItem(first);
      if (element instanceof HTMLElement) element.focus();
      return;
    }
    onSubmit(form, password.current);
  }

  function clearError(field: SetupField): void {
    if (errors[field]) setErrors((current) => ({ ...current, [field]: undefined }));
  }

  const invalid = (field: SetupField) => (errors[field] ? { "aria-describedby": `setup-${field}-error`, invalid: true } : {});
  const visibleErrors = Object.values(errors).filter(Boolean).length;
  return (
    <form aria-busy={pending} aria-describedby={visibleErrors ? bannerID : undefined} className="lw-auth__form" noValidate onSubmit={submit}>
      {visibleErrors ? <div id={bannerID}><Notice title={`${visibleErrors} ${visibleErrors === 1 ? "field needs" : "fields need"} attention.`} tone="danger" /></div> : null}
      <fieldset className="lw-auth__step" disabled={pending}>
        <legend><span>1</span>Prove you run this server</legend>
        <Field error={errors.bootstrap_token} hint="The value of LATCHWAY_ADMIN_BOOTSTRAP_TOKEN in the server's environment. It works once." id="setup-bootstrap_token" label="One-time bootstrap token">
          <Input {...invalid("bootstrap_token")} autoCapitalize="none" autoComplete="off" id="setup-bootstrap_token" maxLength={2048} mono name="bootstrap_token" onInput={() => clearError("bootstrap_token")} spellCheck={false} type="password" />
        </Field>
      </fieldset>
      <fieldset className="lw-auth__step" disabled={pending}>
        <legend><span>2</span>Your organization</legend>
        <div className="lw-auth__row">
          <Field error={errors.organization_name} id="setup-organization_name" label="Organization name">
            <Input {...invalid("organization_name")} autoComplete="organization" id="setup-organization_name" maxLength={200} name="organization_name" onInput={(event) => { suggestSlug(event.currentTarget.form, event.currentTarget.value); clearError("organization_name"); }} />
          </Field>
          <Field error={errors.organization_slug} hint="Used in console URLs." id="setup-organization_slug" label="Organization slug">
            <Input {...invalid("organization_slug")} autoCapitalize="none" autoComplete="off" id="setup-organization_slug" maxLength={63} mono name="organization_slug" onInput={() => { slugEdited.current = true; clearError("organization_slug"); }} spellCheck={false} />
          </Field>
        </div>
      </fieldset>
      <fieldset className="lw-auth__step" disabled={pending}>
        <legend><span>3</span>The first owner</legend>
        <Field error={errors.display_name} id="setup-display_name" label="Owner display name">
          <Input {...invalid("display_name")} autoComplete="name" id="setup-display_name" maxLength={200} name="display_name" onInput={() => clearError("display_name")} />
        </Field>
        <Field error={errors.email} id="setup-email" label="Owner email address">
          <Input {...invalid("email")} autoComplete="username" id="setup-email" maxLength={320} name="email" onInput={() => clearError("email")} spellCheck={false} type="email" />
        </Field>
        <PasswordField error={errors.password} id="setup-password" inputRef={password} label="Owner password" name="password" onValueChange={(value) => { setStrength(value ? passwordStrength(value) : undefined); if (errors.password && acceptable(passwordStrength(value))) clearError("password"); }} />
        <StrengthMeter strength={strength} />
      </fieldset>
      {problem ? <AuthProblem problem={problem} /> : null}
      <p className="lw-auth__fine">Creating the owner closes first-run setup for good. Later administrators are invited from Team › Members.</p>
      <Button className="lw-auth__submit" loading={pending} type="submit" variant="primary">{pending ? "Creating Owner…" : "Create First Owner"}</Button>
      <Button className="lw-auth__link" disabled={pending} onClick={onCancel} size="sm" variant="ghost">Back to sign in</Button>
    </form>
  );
}

function CopyableCommand({ code }: { code: string }) {
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  function copy(): void {
    const write = navigator.clipboard ? navigator.clipboard.writeText(code) : Promise.reject(new Error("clipboard unavailable"));
    write.then(() => setCopied("copied"), () => setCopied("failed"));
  }
  return (
    <div className="lw-row lw-row--tight">
      <pre className="lw-code-block" style={{ flex: 1, margin: 0 }}>{code}</pre>
      <Button aria-label="Copy command" icon={copied === "copied" ? "check" : "copy"} onClick={copy} size="sm" variant="ghost" />
      {copied === "failed" ? <span className="lw-auth__fine">Select the command to copy it.</span> : null}
    </div>
  );
}

function SetupDoneView({ onContinue }: { onContinue: (to?: "/setup") => void }) {
  const [platform, setPlatform] = useState<Platform>("compose");
  const [removed, setRemoved] = useState(false);
  const step = REMOVE_TOKEN_STEPS[platform];
  return <>
    <Notice title="Remove the bootstrap token from the server." tone="warning">
      Setup is closed, so the token can't create another owner, but it's still a credential sitting in your deployment. Take it out.
    </Notice>
    <Segmented items={PLATFORMS.map((id) => ({ id, label: REMOVE_TOKEN_STEPS[id].label }))} label="Where the server runs" onChange={setPlatform} value={platform} />
    <p className="lw-auth__fine">{step.text}</p>
    <CopyableCommand code={step.code} />
    <label className="lw-check">
      <input checked={removed} onChange={(event) => setRemoved(event.target.checked)} type="checkbox" />
      I've removed LATCHWAY_ADMIN_BOOTSTRAP_TOKEN from the server's environment.
    </label>
    <Button className="lw-auth__submit" disabled={!removed} onClick={() => onContinue("/setup")} variant="primary">Add Your First App</Button>
    <Button className="lw-auth__submit" disabled={!removed} onClick={() => onContinue()}>Go to the Console</Button>
  </>;
}

/**
 * Everything before the console: signing in, choosing an organization, first-run setup and the states around them.
 * Passwords and the bootstrap token stay in their inputs and are cleared as soon as a request finishes; the parent
 * keeps this screen up while `onHoldChange(true)` so a background session refresh can't skip a step.
 */
export function AuthScreen({ checking, endReason, mode, onHoldChange, retry, retrying }: { checking: boolean; endReason?: string; mode: "configured" | "signed-out" | "unknown"; onHoldChange: (held: boolean) => void; retry: () => void; retrying: boolean }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const info = useQuery(adminSignInInfoQueryOptions);
  const [view, setView] = useState<View>(() => (pendingInvitation() ? "invitation" : lastSignedOutEmail() ? "signed-out" : "sign-in"));
  // An open setup leads with Set up Latchway until the operator chooses sign-in instead.
  const [preferSignIn, setPreferSignIn] = useState(false);
  const [email, setEmail] = useState(() => lastSignedOutEmail() ?? "");
  const [pending, setPending] = useState<string>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [failures, setFailures] = useState(0);
  const [chosen, setChosen] = useState<AdminSession>();
  const [created, setCreated] = useState<{ organization: string; session: AdminSession }>();
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  // The second-factor challenge is short-lived and sensitive, so it lives in a ref, never in rendered state.
  const challenge = useRef<string | undefined>(undefined);
  const [methods, setMethods] = useState<readonly SecondFactorMethod[]>([]);

  function show(next: View): void {
    setProblem(undefined);
    setView(next);
  }

  function enter(session: AdminSession, to?: "/setup"): void {
    clearInput(passwordRef.current);
    forgetSSOReturn();
    rememberSignedOutEmail(undefined);
    queryClient.setQueryData(consoleSessionQueryOptions.queryKey, consoleStateFromAdminSession(session));
    onHoldChange(false);
    if (to) void navigate({ to });
  }

  function fail(error: unknown): AdminProblem {
    clearInput(passwordRef.current);
    onHoldChange(false);
    const found = problemFromError(error);
    setProblem(found);
    setPending(undefined);
    return found;
  }

  async function signIn(): Promise<void> {
    const address = email.trim();
    const password = passwordRef.current?.value ?? "";
    setPending("sign-in");
    setProblem(undefined);
    onHoldChange(true);
    try {
      const result = await startAdministratorSignIn({ email: address, password });
      clearInput(passwordRef.current);
      setFailures(0);
      if (result.kind === "challenge") {
        challenge.current = result.challenge.challenge;
        setMethods(result.challenge.methods);
        setPending(undefined);
        setView("two-factor");
        return;
      }
      afterSignIn(result.session);
    } catch (error) {
      const found = fail(error);
      if (found.code === "rate_limited" && found.retryAfterSeconds) pauseSignIn(address, found.retryAfterSeconds);
      if (found.code === "authentication_required") setFailures((count) => count + 1);
      passwordRef.current?.focus();
    }
  }

  async function signInByPasskey(): Promise<void> {
    setPending("passkey");
    setProblem(undefined);
    onHoldChange(true);
    try {
      const session = await signInWithPasskey();
      clearInput(passwordRef.current);
      setFailures(0);
      setEmail(session.administrator.email);
      afterSignIn(session);
    } catch (error) {
      fail(error);
    }
  }

  async function singleSignOn(slug: string): Promise<void> {
    setPending("sso");
    setProblem(undefined);
    try {
      // The page leaves for the identity provider and comes back signed in, or with a reason.
      leaveFor(await startSingleSignOn(slug));
    } catch (error) {
      setProblem(problemFromError(error));
      setPending(undefined);
    }
  }

  function afterSignIn(session: AdminSession): void {
    if (session.memberships.length > 1) {
      setChosen(session);
      setPending(undefined);
      setView("choose-org");
      return;
    }
    enter(session);
  }

  async function verifySecondFactor(answer: SecondFactorAnswer): Promise<void> {
    if (!challenge.current) return;
    setPending("two-factor");
    setProblem(undefined);
    try {
      const session = await finishSecondFactor(challenge.current, answer);
      challenge.current = undefined;
      afterSignIn(session);
    } catch (error) {
      const found = problemFromError(error);
      setPending(undefined);
      if (found.detail.includes("Sign in again")) {
        challenge.current = undefined;
        onHoldChange(false);
        setView("sign-in");
      }
      setProblem(found);
    }
  }

  function cancelSecondFactor(): void {
    challenge.current = undefined;
    onHoldChange(false);
    show("sign-in");
  }

  async function chooseOrganization(organizationID: string): Promise<void> {
    if (!chosen) return;
    if (organizationID === chosen.organization_id) {
      enter(chosen);
      return;
    }
    setPending(organizationID);
    setProblem(undefined);
    try {
      // The server replaces the session it just issued with one for the chosen organization.
      enter(await switchAdminOrganization(organizationID));
    } catch (error) {
      setProblem(problemFromError(error));
      setPending(undefined);
    }
  }

  async function signInAsSomeoneElse(): Promise<void> {
    setPending("back");
    setProblem(undefined);
    try {
      await logoutAdministrator();
      clearInput(passwordRef.current);
      setChosen(undefined);
      setPending(undefined);
      onHoldChange(false);
      setEmail("");
      setView("sign-in");
    } catch (error) {
      setProblem(problemFromError(error));
      setPending(undefined);
    }
  }

  async function createOwner(form: HTMLFormElement, password: HTMLInputElement | null): Promise<void> {
    const token = form.elements.namedItem("bootstrap_token");
    setPending("setup");
    setProblem(undefined);
    onHoldChange(true);
    try {
      const organization = formText(form, "organization_name").trim();
      const session = await bootstrapFirstOwner({
        bootstrap_token: formText(form, "bootstrap_token"),
        display_name: formText(form, "display_name").trim(),
        email: formText(form, "email").trim(),
        organization_name: organization,
        organization_slug: formText(form, "organization_slug"),
        password: password?.value ?? ""
      });
      setCreated({ organization, session });
      setPending(undefined);
      setView("setup-done");
    } catch (error) {
      const found = fail(error);
      if (found.code === "bootstrap_disabled") show("setup-closed");
    } finally {
      clearInput(token instanceof HTMLInputElement ? token : null);
      clearInput(password);
    }
  }

  if (checking) {
    return <AuthLayout description="Checking for a session on this server…" title="Latchway console"><span aria-live="polite" className="lw-auth__fine">One moment.</span></AuthLayout>;
  }
  if (mode === "unknown" && !pending && view !== "setup-done") {
    return (
      <AuthLayout description="The console couldn't confirm a session with this server. It may be starting, restarting or unreachable from this network." title="Can't reach the server">
        <Button className="lw-auth__submit" loading={retrying} onClick={retry} variant="primary">Try Again</Button>
        <div className="lw-auth__help">
          <p>On the server host, <span className="lw-code-inline">latchway doctor</span> runs the deployment diagnostics. With an API token, <span className="lw-code-inline">latchway status</span> reports build, protocol and readiness.</p>
          <p>A console and server from different releases can also cause this; reload after an upgrade.</p>
        </div>
      </AuthLayout>
    );
  }

  const mismatch = info.data && info.data.contract_version !== consoleContractVersion ? info.data.contract_version : undefined;
  const passkeySignIn = info.data?.sign_in_methods.includes("passkey") && passkeysAvailable() ? () => void signInByPasskey() : undefined;
  const ssoOffered = info.data?.sign_in_methods.includes("sso") ? () => show("sso") : undefined;
  const signInView = <SignInView email={email} emailRef={emailRef} endReason={endReason} failures={failures} mismatch={mismatch} onPasskey={passkeySignIn} onSSO={ssoOffered} onSetup={() => show(info.data && !info.data.setup_open ? "setup-closed" : "setup")} onSubmit={() => void signIn()} passwordRef={passwordRef} pending={pending === "sign-in" ? "password" : pending === "passkey" ? "passkey" : undefined} problem={view === "sign-in" ? problem : undefined} setEmail={setEmail} />;
  const current: View = view === "sign-in" && info.data?.setup_open && !preferSignIn ? "setup" : view;

  switch (current) {
    case "signed-out":
      return (
        <AuthLayout description={email ? `${email} signed out of this server.` : "You signed out of this server."} title="You're signed out">
          <Button className="lw-auth__submit" onClick={() => show("sign-in")} variant="primary">Sign In Again</Button>
        </AuthLayout>
      );
    case "setup":
      return (
        <AuthLayout description="Create the first owner and organization for a new server. You need the one-time bootstrap token from the server's environment." title="Set up Latchway">
          <SetupView onCancel={() => { setPreferSignIn(true); show("sign-in"); }} onSubmit={(form, password) => void createOwner(form, password)} pending={pending === "setup"} problem={problem} />
        </AuthLayout>
      );
    case "setup-done":
      return (
        <AuthLayout description={`You're signed in as its owner. One step remains on the server.`} title={`${created?.organization ?? "Your organization"} is ready`}>
          <SetupDoneView onContinue={(to) => created && enter(created.session, to)} />
        </AuthLayout>
      );
    case "setup-closed":
      return (
        <AuthLayout description="This server already has an owner, so first-run setup is closed for good. Sign in with your administrator account instead." title="Setup is already done">
          <Button className="lw-auth__submit" onClick={() => show("sign-in")} variant="primary">Go to Sign In</Button>
          <p className="lw-auth__fine">Need an account? Ask an owner to add you from Team › Members.</p>
        </AuthLayout>
      );
    case "invitation": {
      const invited = pendingInvitation();
      return (
        <AuthLayout description="An owner invited you to their Latchway organization." title="You're invited">
          <InvitationView onAccepted={(session) => enter(session)} onSignIn={(address) => { setEmail(address); setPreferSignIn(true); show("sign-in"); }} />
          {invited && "invalid" in invited ? <Button className="lw-auth__link" onClick={() => { forgetInvitation(); show("sign-in"); }} size="sm" variant="ghost">Go to sign in</Button> : null}
        </AuthLayout>
      );
    }
    case "sso":
      return (
        <AuthLayout description="You'll continue at your organization's identity provider and come back here signed in." title="Sign in with SSO">
          <SingleSignOnView onBack={() => show("sign-in")} onSubmit={(slug) => void singleSignOn(slug)} pending={pending === "sso"} problem={problem} />
        </AuthLayout>
      );
    case "two-factor":
      return (
        <AuthLayout description={`Two-factor sign-in is on for ${email.trim()}. ${methods.includes("totp") ? "Enter the code from your authenticator app" : "Use one of your passkeys"} to finish signing in.`} title="Verify it's you">
          <SecondFactorForm idPrefix="sign-in" methods={methods} onCancel={cancelSecondFactor} onSubmit={(answer) => void verifySecondFactor(answer)} pending={pending === "two-factor"} problem={problem} />
        </AuthLayout>
      );
    case "choose-org":
      return (
        <AuthLayout description={`${email.trim()} belongs to more than one organization. Each session works in one; you can switch later from your account menu.`} title="Choose an organization">
          {chosen ? <ChooseOrganizationView onBack={() => void signInAsSomeoneElse()} onChoose={(id) => void chooseOrganization(id)} pending={pending} problem={problem} session={chosen} /> : null}
        </AuthLayout>
      );
    case "sign-in":
      return (
        <AuthLayout description="Sign in with your administrator account." title="Sign in to Latchway">
          {signInView}
        </AuthLayout>
      );
  }
}

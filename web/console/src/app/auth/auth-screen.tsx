import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { type FormEvent, type ReactNode, type RefObject, useEffect, useId, useRef, useState } from "react";

import {
  type AdminProblem,
  type AdminSession,
  bootstrapFirstOwner,
  loginAdministrator,
  logoutAdministrator,
  problemFromError
} from "../../api/auth";
import { overallHealthState, useSystemHealth } from "../../api/health";
import { consoleSessionQueryOptions, consoleStateFromAdminSession } from "../../api/session";
import { organizationsQueryOptions } from "../../api/workspace";
import { PasswordField } from "../../components/password-field";
import { ROLE_LABEL } from "../../pages/team/roles";
import { Button, Field, Icon, Input, Logo, Notice, Segmented } from "../../ui";
import { AuthProblem, PasswordInput } from "./auth-fields";
import { lastSignedOutEmail, pauseSignIn, rememberSignedOutEmail, signInPausedUntil, wallClock } from "./auth-memory";
import { acceptable, passwordStrength, STRENGTH_TEXT, type Strength } from "./password-strength";
import { type Platform, PLATFORMS, REMOVE_TOKEN_STEPS, SETUP_FIELDS, type SetupField, slugify, validateSetup } from "./setup-model";

type View = "sign-in" | "choose-org" | "setup" | "setup-done" | "setup-closed" | "signed-out";

/** Failed attempts before the console mentions the server's pause, ahead of the pause itself. */
const PAUSE_NOTE_AFTER = 3;

function formText(form: HTMLFormElement, name: string): string {
  const field = form.elements.namedItem(name);
  return field instanceof HTMLInputElement ? field.value : "";
}

function clearInput(input: HTMLInputElement | null): void {
  if (input) input.value = "";
}

function BrandArt() {
  return (
    <svg aria-hidden="true" className="lw-auth__art" viewBox="0 0 520 300">
      <rect className="is-tint" height="300" rx="24" width="520" />
      <rect className="is-ink" height="44" rx="12" width="184" x="40" y="48" />
      <rect className="is-pill-b" height="12" rx="6" width="96" x="60" y="64" />
      <rect className="is-accent" height="44" rx="12" width="184" x="40" y="128" />
      <rect className="is-pill-a" height="12" rx="6" width="120" x="60" y="144" />
      <rect className="is-ink" height="44" rx="12" width="184" x="40" y="208" />
      <rect className="is-pill-b" height="12" rx="6" width="72" x="60" y="224" />
      <rect className="is-accent" height="8" rx="4" width="72" x="240" y="146" />
      <rect className="is-accent" height="156" rx="20" width="160" x="320" y="72" />
      <rect className="is-pill-a" height="12" rx="6" width="96" x="344" y="100" />
      <rect className="is-pill-a" height="12" rx="6" width="64" x="344" y="124" />
      <rect className="is-prod" height="28" rx="14" width="112" x="344" y="176" />
      <rect className="is-pill-c" height="8" rx="4" width="48" x="260" y="70" />
      <rect className="is-pill-c" height="8" rx="4" width="48" x="260" y="230" />
    </svg>
  );
}

/** What the browser can see about this server before sign-in: its host and the public health endpoints. */
function ServerFacts() {
  const { liveness, readiness } = useSystemHealth();
  const state = overallHealthState(liveness.data, readiness.data);
  const version = liveness.data?.version ?? readiness.data?.version;
  const status = state === "available" ? "Reachable and ready" : state === "degraded" ? "Reachable, not ready" : state === "unavailable" ? "Not reachable" : "Checking…";
  return (
    <section aria-label="This server" className="lw-auth__facts">
      <strong>This server</strong>
      <dl>
        <div><dt>Host</dt><dd>{window.location.host}</dd></div>
        <div><dt>Version</dt><dd>{version ?? (state === "unavailable" ? "Unknown" : "Not reported before sign-in")}</dd></div>
        <div><dt>Status</dt><dd>{state === "loading" ? null : <span aria-hidden="true" className={state === "available" ? "lw-auth__dot" : "lw-auth__dot is-down"} />}{status}</dd></div>
      </dl>
    </section>
  );
}

function AuthLayout({ children, description, title }: { children: ReactNode; description?: ReactNode; title: string }) {
  return (
    <div className="lw-auth">
      <div className="lw-auth__panel">
        <main className="lw-auth__main" id="main-content">
          <div className="lw-auth__head">
            <Logo />
            <h1>{title}</h1>
            {description ? <p>{description}</p> : null}
          </div>
          <div className="lw-auth__body">{children}</div>
        </main>
        <p className="lw-auth__foot">Latchway console · Your session cookie stays on this server.</p>
      </div>
      <aside aria-label="About this server" className="lw-auth__brand">
        <BrandArt />
        <ServerFacts />
      </aside>
    </div>
  );
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

function SignInView({ email, emailRef, failures, hidden, onSetup, onSubmit, passwordRef, pending, problem, setEmail }: {
  email: string;
  emailRef: RefObject<HTMLInputElement | null>;
  failures: number;
  hidden: boolean;
  onSetup: () => void;
  onSubmit: () => void;
  passwordRef: RefObject<HTMLInputElement | null>;
  pending: boolean;
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
    <div className="lw-auth__body" hidden={hidden}>
      <form aria-busy={pending} className="lw-auth__form" onSubmit={submit}>
        <Field id="login-email" label="Email address">
          <div className="lw-input-box">
            <input autoComplete="username" className="lw-input" disabled={pending} id="login-email" maxLength={320} name="email" onChange={(event) => setEmail(event.target.value)} ref={emailRef} required spellCheck={false} type="email" value={email} />
          </div>
        </Field>
        <PasswordInput disabled={pending} id="login-password" inputRef={passwordRef} />
        {paused ? <PauseNotice key={pausedUntil} onElapsed={() => setElapsedFor(pausedUntil)} until={pausedUntil} /> : problem ? <AuthProblem problem={problem} /> : null}
        {failures >= PAUSE_NOTE_AFTER && !paused ? <p className="lw-auth__fine">After five failed attempts for one email address within five minutes, the server pauses sign-in for that address for up to five minutes.</p> : null}
        <Button className="lw-auth__submit" disabled={paused} loading={pending} type="submit" variant="primary">{pending ? "Signing In…" : "Sign In"}</Button>
      </form>
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

const STRENGTH_BARS: Readonly<Record<Strength, number>> = { good: 2, strong: 3, "too-short": 0, weak: 1 };
const STRENGTH_COLOR: Readonly<Record<Strength, string>> = { good: "var(--success)", strong: "var(--success)", "too-short": "var(--foreground-secondary)", weak: "var(--destructive)" };

function StrengthMeter({ strength }: { strength?: Strength }) {
  const filled = strength ? STRENGTH_BARS[strength] : 0;
  const color = strength ? STRENGTH_COLOR[strength] : "var(--foreground-secondary)";
  return (
    <div className="lw-strength">
      <div aria-hidden="true" className="lw-strength__bars">
        {[0, 1, 2].map((bar) => <span key={bar} style={{ background: bar < filled ? color : "var(--border)" }} />)}
      </div>
      <span aria-live="polite" className="lw-strength__label" style={{ color }}>{strength ? `Strength: ${STRENGTH_TEXT[strength]}` : "Use at least 12 characters; Good or better is required."}</span>
    </div>
  );
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
export function AuthScreen({ checking, mode, onHoldChange, retry, retrying }: { checking: boolean; mode: "configured" | "signed-out" | "unknown"; onHoldChange: (held: boolean) => void; retry: () => void; retrying: boolean }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [view, setView] = useState<View>(() => (lastSignedOutEmail() ? "signed-out" : "sign-in"));
  const [email, setEmail] = useState(() => lastSignedOutEmail() ?? "");
  const [pending, setPending] = useState<string>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [failures, setFailures] = useState(0);
  const [chosen, setChosen] = useState<AdminSession>();
  const [created, setCreated] = useState<{ organization: string; session: AdminSession }>();
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  function show(next: View): void {
    setProblem(undefined);
    setView(next);
  }

  function enter(session: AdminSession, to?: "/setup"): void {
    clearInput(passwordRef.current);
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
      const session = await loginAdministrator({ email: address, password });
      setFailures(0);
      if (session.memberships.length > 1) {
        // The password stays in its (now hidden) input so choosing another organization can sign in to it.
        setChosen(session);
        setPending(undefined);
        setView("choose-org");
        return;
      }
      enter(session);
    } catch (error) {
      const found = fail(error);
      if (found.code === "rate_limited" && found.retryAfterSeconds) pauseSignIn(address, found.retryAfterSeconds);
      if (found.code === "authentication_required") setFailures((count) => count + 1);
      passwordRef.current?.focus();
    }
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
      // End the session the first sign-in opened before opening one for the chosen organization.
      await logoutAdministrator();
      const session = await loginAdministrator({ email: email.trim(), organization_id: organizationID, password: passwordRef.current?.value ?? "" });
      enter(session);
    } catch (error) {
      fail(error);
      setChosen(undefined);
      setView("sign-in");
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

  const signInView = <SignInView email={email} emailRef={emailRef} failures={failures} hidden={view === "choose-org"} onSetup={() => show("setup")} onSubmit={() => void signIn()} passwordRef={passwordRef} pending={pending === "sign-in"} problem={view === "sign-in" ? problem : undefined} setEmail={setEmail} />;

  switch (view) {
    case "signed-out":
      return (
        <AuthLayout description={email ? `${email} signed out of this server.` : "You signed out of this server."} title="You're signed out">
          <Button className="lw-auth__submit" onClick={() => show("sign-in")} variant="primary">Sign In Again</Button>
        </AuthLayout>
      );
    case "setup":
      return (
        <AuthLayout description="Create the first owner and organization for a new server. You need the one-time bootstrap token from the server's environment." title="Set up Latchway">
          <SetupView onCancel={() => show("sign-in")} onSubmit={(form, password) => void createOwner(form, password)} pending={pending === "setup"} problem={problem} />
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
    case "choose-org":
      return (
        <AuthLayout description={`${email.trim()} belongs to more than one organization. Each session works in one; you can switch later from your account menu.`} title="Choose an organization">
          {signInView}
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

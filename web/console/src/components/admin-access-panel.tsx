import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";

import {
  bootstrapFirstOwner,
  loginAdministrator,
  problemFromError,
  type AdminProblem,
  type AdminSession
} from "../api/auth";
import {
  consoleSessionQueryOptions,
  consoleStateFromAdminSession
} from "../api/session";

type AccessMode = "login" | "bootstrap";

function formString(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

function clearSecretField(form: HTMLFormElement, name: string): void {
  const field = form.elements.namedItem(name);
  if (field instanceof HTMLInputElement) {
    field.value = "";
  }
}

function SubmissionProblem({ problem }: { problem: AdminProblem }) {
  return (
    <div className="auth-problem" role="alert">
      <strong>{problem.title}</strong>
      <p>{problem.detail}</p>
      <p className="auth-problem__meta">
        <span>Code: {problem.code}</span>
        {problem.requestId ? <span>Request: {problem.requestId}</span> : null}
      </p>
    </div>
  );
}

export function AdminAccessPanel() {
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<AccessMode>("login");
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();

  function selectMode(nextMode: AccessMode): void {
    setMode(nextMode);
    setProblem(undefined);
  }

  async function acceptSession(session: AdminSession, form: HTMLFormElement) {
    form.reset();
    queryClient.setQueryData(
      consoleSessionQueryOptions.queryKey,
      consoleStateFromAdminSession(session)
    );
    await queryClient.invalidateQueries({
      exact: true,
      queryKey: consoleSessionQueryOptions.queryKey,
      refetchType: "active"
    });
  }

  async function submitLogin(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const organizationID = formString(data, "organization_id").trim();

    setPending(true);
    setProblem(undefined);
    try {
      const session = await loginAdministrator({
        email: formString(data, "email").trim(),
        ...(organizationID ? { organization_id: organizationID } : {}),
        password: formString(data, "password")
      });
      await acceptSession(session, form);
    } catch (error) {
      clearSecretField(form, "password");
      setProblem(problemFromError(error));
      setPending(false);
    }
  }

  async function submitBootstrap(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);

    setPending(true);
    setProblem(undefined);
    try {
      const session = await bootstrapFirstOwner({
        bootstrap_token: formString(data, "bootstrap_token"),
        display_name: formString(data, "display_name").trim(),
        email: formString(data, "email").trim(),
        organization_name: formString(data, "organization_name").trim(),
        organization_slug: formString(data, "organization_slug").trim(),
        password: formString(data, "password")
      });
      await acceptSession(session, form);
    } catch (error) {
      clearSecretField(form, "bootstrap_token");
      clearSecretField(form, "password");
      setProblem(problemFromError(error));
      setPending(false);
    }
  }

  return (
    <section className="auth-card" aria-labelledby="auth-card-heading">
      <div className="auth-card__heading">
        <p className="auth-card__eyebrow">Administrator session</p>
        <h2 id="auth-card-heading">
          {mode === "login" ? "Sign in" : "Set up the first owner"}
        </h2>
      </div>

      <fieldset className="auth-mode-selector" disabled={pending}>
        <legend className="visually-hidden">Choose an access method</legend>
        <label className={mode === "login" ? "auth-mode-option auth-mode-option--active" : "auth-mode-option"}>
          <input
            checked={mode === "login"}
            name="access_mode"
            onChange={() => selectMode("login")}
            type="radio"
            value="login"
          />
          Sign in
        </label>
        <label className={mode === "bootstrap" ? "auth-mode-option auth-mode-option--active" : "auth-mode-option"}>
          <input
            checked={mode === "bootstrap"}
            name="access_mode"
            onChange={() => selectMode("bootstrap")}
            type="radio"
            value="bootstrap"
          />
          First-owner setup
        </label>
      </fieldset>

      {mode === "login" ? (
        <form
          aria-busy={pending}
          className="auth-form"
          onSubmit={(event) => void submitLogin(event)}
        >
          <p className="auth-form__intro">
            Use an administrator credential. The secure session cookie stays on this
            gateway.
          </p>
          <div className="form-field">
            <label htmlFor="login-email">Email address</label>
            <input
              autoComplete="username"
              id="login-email"
              maxLength={320}
              name="email"
              required
              type="email"
            />
          </div>
          <div className="form-field">
            <label htmlFor="login-password">Password</label>
            <input
              autoComplete="current-password"
              id="login-password"
              maxLength={1024}
              name="password"
              required
              type="password"
            />
          </div>
          <div className="form-field">
            <label htmlFor="login-organization">Organization ID (optional)</label>
            <input
              aria-describedby="login-organization-hint"
              autoCapitalize="none"
              autoComplete="off"
              id="login-organization"
              maxLength={132}
              name="organization_id"
              pattern="org_[A-Za-z0-9_-]{16,128}"
              spellCheck={false}
              type="text"
            />
            <span className="form-field__hint" id="login-organization-hint">
              Leave blank to use your first active membership.
            </span>
          </div>

          {problem ? <SubmissionProblem problem={problem} /> : null}

          <button className="primary-action auth-submit" disabled={pending} type="submit">
            {pending ? "Signing in…" : "Sign in securely"}
            {!pending ? <span aria-hidden="true">→</span> : null}
          </button>
        </form>
      ) : (
        <form
          aria-busy={pending}
          className="auth-form"
          onSubmit={(event) => void submitBootstrap(event)}
        >
          <p className="auth-form__intro auth-form__intro--warning">
            Use only on a new installation. Successful setup permanently closes the
            bootstrap endpoint.
          </p>
          <div className="form-field">
            <label htmlFor="bootstrap-token">One-time bootstrap token</label>
            <input
              aria-describedby="bootstrap-token-hint"
              autoCapitalize="none"
              autoComplete="off"
              id="bootstrap-token"
              maxLength={2048}
              minLength={32}
              name="bootstrap_token"
              required
              spellCheck={false}
              type="password"
            />
            <span className="form-field__hint" id="bootstrap-token-hint">
              Read from the gateway’s secure deployment configuration.
            </span>
          </div>
          <div className="form-field-grid">
            <div className="form-field">
              <label htmlFor="organization-name">Organization name</label>
              <input
                autoComplete="organization"
                id="organization-name"
                maxLength={200}
                name="organization_name"
                required
                type="text"
              />
            </div>
            <div className="form-field">
              <label htmlFor="organization-slug">Organization slug</label>
              <input
                aria-describedby="organization-slug-hint"
                autoCapitalize="none"
                autoComplete="off"
                id="organization-slug"
                maxLength={63}
                name="organization_slug"
                pattern="[a-z][a-z0-9_-]{0,62}"
                required
                spellCheck={false}
                type="text"
              />
              <span className="form-field__hint" id="organization-slug-hint">
                Lowercase letters, digits, underscores, and hyphens.
              </span>
            </div>
          </div>
          <div className="form-field">
            <label htmlFor="owner-name">Owner display name</label>
            <input
              autoComplete="name"
              id="owner-name"
              maxLength={200}
              name="display_name"
              required
              type="text"
            />
          </div>
          <div className="form-field">
            <label htmlFor="owner-email">Owner email address</label>
            <input
              autoComplete="username"
              id="owner-email"
              maxLength={320}
              name="email"
              required
              type="email"
            />
          </div>
          <div className="form-field">
            <label htmlFor="owner-password">Owner password</label>
            <input
              aria-describedby="owner-password-hint"
              autoComplete="new-password"
              id="owner-password"
              maxLength={1024}
              minLength={12}
              name="password"
              required
              type="password"
            />
            <span className="form-field__hint" id="owner-password-hint">
              Use at least 12 characters.
            </span>
          </div>

          {problem ? <SubmissionProblem problem={problem} /> : null}

          <button className="primary-action auth-submit" disabled={pending} type="submit">
            {pending ? "Creating owner…" : "Create first owner"}
            {!pending ? <span aria-hidden="true">→</span> : null}
          </button>
        </form>
      )}
    </section>
  );
}

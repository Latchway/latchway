import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useRef, useState } from "react";

import { removeSSOProvider, saveSSOProvider, ssoConfigurationQueryOptions, type SSOProviderInput } from "../../api/account";
import type { SSOProvider } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { Badge, Button, Card, ConfirmDialog, Field, Input, Notice, Properties } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";
import { CopyButton } from "../requests/request-detail";

type ProvisionRole = SSOProviderInput["provision_role"];

interface Draft {
  domains: string;
  clientID: string;
  enabled: boolean;
  issuer: string;
  provisionRole: ProvisionRole;
  requireSSO: boolean;
}

const ROLE_CHOICES: readonly { label: string; value: ProvisionRole }[] = [
  { label: "Don't create accounts", value: null },
  { label: "Create as Viewer", value: "viewer" },
  { label: "Create as Operator", value: "operator" },
  { label: "Create as Admin", value: "admin" }
];

function draftFrom(provider: SSOProvider | null | undefined): Draft {
  return {
    clientID: provider?.client_id ?? "",
    domains: provider?.allowed_email_domains.join(", ") ?? "",
    enabled: provider?.enabled ?? true,
    issuer: provider?.issuer ?? "",
    provisionRole: provider?.provision_role ?? null,
    requireSSO: provider?.require_sso ?? false
  };
}

function inputFrom(draft: Draft): SSOProviderInput {
  return {
    allowed_email_domains: draft.domains.split(/[\s,]+/).map((domain) => domain.trim()).filter(Boolean),
    client_id: draft.clientID.trim(),
    enabled: draft.enabled,
    issuer: draft.issuer.trim(),
    provision_role: draft.provisionRole,
    require_sso: draft.enabled && draft.requireSSO
  };
}

/** What saving would end, so the owner confirms before it happens. */
function sessionImpact(saved: SSOProvider | null | undefined, next: SSOProviderInput): string | undefined {
  if (saved?.enabled && !next.enabled) return "Turning single sign-on off ends every single sign-on session in this organization except yours.";
  if (next.require_sso && !saved?.require_sso) return "Members other than owners must sign in through your identity provider. Their password and passkey sessions end now; owners keep their other sign-in methods.";
  return undefined;
}

/**
 * Owners connect the organization to an OpenID Connect identity provider. The server reads the provider's discovery
 * document when saving, so a wrong issuer is caught here rather than at someone's sign-in. The client secret lives only
 * in its input until it's sent and is never shown again.
 */
export function SingleSignOnCard({ organizationID }: { organizationID: string }) {
  const queryClient = useQueryClient();
  const compatibility = useConsoleCompatibility();
  const config = useQuery(ssoConfigurationQueryOptions(organizationID));
  const provider = config.data?.provider;
  const [draft, setDraft] = useState<Draft>();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [saved, setSaved] = useState(false);
  const [confirm, setConfirm] = useState<"save" | "remove">();
  const secret = useRef<HTMLInputElement>(null);
  const current = draft ?? draftFrom(provider);
  const editable = compatibility.mutationAllowed;

  // The secret field closes with the rest of the form when the console turns read-only.
  if (!editable && (confirm || draft)) {
    setConfirm(undefined);
    setDraft(undefined);
  }

  function change(patch: Partial<Draft>): void {
    setSaved(false);
    setDraft({ ...current, ...patch });
  }

  async function save(): Promise<void> {
    setPending(true);
    setProblem(undefined);
    try {
      const next = await saveSSOProvider(organizationID, inputFrom(current), secret.current);
      queryClient.setQueryData(ssoConfigurationQueryOptions(organizationID).queryKey, next);
      setDraft(undefined);
      setConfirm(undefined);
      setSaved(true);
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setPending(false);
    }
  }

  async function remove(): Promise<void> {
    setPending(true);
    setProblem(undefined);
    try {
      await removeSSOProvider(organizationID);
      setConfirm(undefined);
      setDraft(undefined);
      setSaved(false);
      await queryClient.invalidateQueries({ queryKey: ssoConfigurationQueryOptions(organizationID).queryKey });
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setPending(false);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!provider && !secret.current?.value) {
      setProblem({ code: "request_invalid", detail: "Enter the client secret your identity provider gave you for this application.", retryable: false, status: 0, title: "Client secret needed" });
      return;
    }
    if (sessionImpact(provider, inputFrom(current))) {
      setConfirm("save");
      return;
    }
    void save();
  }

  const status = provider ? (provider.enabled ? (provider.require_sso ? "Required" : "On") : "Off") : "Not set up";
  return (
    <Card
      description="Let members sign in with your organization's identity provider, such as Okta, Microsoft Entra ID, Google Workspace or Keycloak, over OpenID Connect."
      icon="team"
      meta={config.data ? <Badge color={provider?.enabled ? "success" : undefined} variant="soft">{status}</Badge> : undefined}
      title="Single sign-on"
    >
      {config.error ? <ProblemNotice problem={problemFromError(config.error)} /> : null}
      {config.data ? (
        <div className="lw-stack">
          <Field hint="Register this as the redirect (callback) URI of the application you create at your identity provider." id="sso-redirect-uri" label="Redirect URI">
            <div className="lw-row lw-row--wrap"><code className="lw-code-inline">{config.data.redirect_uri}</code><CopyButton label="Copy redirect URI" value={config.data.redirect_uri} /></div>
          </Field>
          {editable ? (
            <form aria-busy={pending} className="lw-stack lw-form" onSubmit={submit}>
              <Field hint="The provider's issuer URL; the server reads its discovery document from here." id="sso-issuer" label="Issuer">
                <Input disabled={pending} id="sso-issuer" maxLength={2048} onChange={(event) => change({ issuer: event.target.value })} placeholder="https://login.example.com" required spellCheck={false} type="url" value={current.issuer} />
              </Field>
              <Field id="sso-client-id" label="Client ID">
                <Input disabled={pending} id="sso-client-id" maxLength={512} onChange={(event) => change({ clientID: event.target.value })} required spellCheck={false} value={current.clientID} />
              </Field>
              <Field hint={provider ? "Stored and never shown. Leave blank to keep it." : "Sealed with the server's master key and never shown again."} id="sso-client-secret" label="Client secret">
                <div className="lw-input-box"><input autoComplete="off" className="lw-input" disabled={pending} id="sso-client-secret" maxLength={1024} name="client_secret" onChange={() => setSaved(false)} ref={secret} spellCheck={false} type="password" /></div>
              </Field>
              <Field hint="Optional. Only verified addresses in these domains can sign in or be linked, like example.com." id="sso-domains" label="Allowed email domains">
                <Input disabled={pending} id="sso-domains" onChange={(event) => change({ domains: event.target.value })} placeholder="example.com, example.org" spellCheck={false} value={current.domains} />
              </Field>
              <Field hint="A verified email that matches a member always signs in as that member. Owners are never created this way." id="sso-provision" label="People without an account">
                <div className="lw-input-box">
                  <select className="lw-input" disabled={pending} id="sso-provision" onChange={(event) => change({ provisionRole: (event.target.value || null) as ProvisionRole })} value={current.provisionRole ?? ""}>
                    {ROLE_CHOICES.map((choice) => <option key={choice.label} value={choice.value ?? ""}>{choice.label}</option>)}
                  </select>
                </div>
              </Field>
              <label className="lw-check"><input checked={current.enabled} disabled={pending} onChange={(event) => change({ enabled: event.target.checked, requireSSO: event.target.checked && current.requireSSO })} type="checkbox" /><span>Offer Sign In with SSO</span></label>
              <label className="lw-check"><input checked={current.enabled && current.requireSSO} disabled={pending || !current.enabled} onChange={(event) => change({ requireSSO: event.target.checked })} type="checkbox" /><span>Require it for members other than owners</span></label>
              {problem ? <ProblemNotice problem={problem} /> : null}
              {saved && provider ? <Notice title="Saved." tone="success">Endpoints were read from the issuer&apos;s discovery document.</Notice> : null}
              <div className="lw-row lw-row--wrap">
                <Button loading={pending && confirm === undefined} type="submit" variant="primary">{provider ? "Save Changes" : "Set Up Single Sign-On"}</Button>
                {provider ? <Button destructive disabled={pending} onClick={() => setConfirm("remove")} variant="ghost">Remove</Button> : null}
              </div>
            </form>
          ) : <Notice icon="lock" title="Single sign-on changes are unavailable." tone="info">The console is read-only until it can verify the server.</Notice>}
          {provider ? (
            <Properties columns={1} items={[
              { label: "Authorization endpoint", value: <span className="lw-mono lw-mono--sm">{provider.authorization_endpoint}</span> },
              { label: "Token endpoint", value: <span className="lw-mono lw-mono--sm">{provider.token_endpoint}</span> },
              { label: "Last changed", value: new Date(provider.updated_at).toLocaleString() }
            ]} />
          ) : null}
        </div>
      ) : config.isPending ? <p className="lw-secondary lw-note">Loading…</p> : null}
      {confirm === "save" ? (
        <ConfirmDialog confirmLabel="Save" description={sessionImpact(provider, inputFrom(current))} onCancel={() => setConfirm(undefined)} onConfirm={() => void save()} pending={pending} title="Save single sign-on changes?">
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
      {confirm === "remove" ? (
        <ConfirmDialog confirmLabel="Remove" description="Members can no longer sign in with SSO, and every single sign-on session here ends except yours. Accounts created by single sign-on have no password until an owner resets it." destructive onCancel={() => setConfirm(undefined)} onConfirm={() => void remove()} pending={pending} title="Remove single sign-on?">
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </Card>
  );
}

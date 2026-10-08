import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, type ReactNode, useState } from "react";

import { setTwoFactorRequirement, twoFactorStatusQueryOptions } from "../../api/account";
import { AdministratorPageSchema, adminRequest, DoctorReportSchema, queryPath, SystemStatusSchema } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { consoleContractVersion, consoleProtocolVersion } from "../../api/console-compatibility";
import { type ApplicationResource, ApplicationResourceSchema, type EnvironmentResource, EnvironmentResourceSchema } from "../../api/resources";
import { consoleSessionQueryOptions, useConsoleSession } from "../../api/session";
import { applicationsQueryOptions, environmentsQueryOptions, organizationsQueryOptions } from "../../api/workspace";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { clearTheme, setTheme, storedTheme } from "../../app/theme";
import { useOptionalWorkspace } from "../../app/workspace-context-value";
import { Badge, Button, Card, ConfirmDialog, DetailPanel, EnvironmentBadge, Field, ImpactDialog, Input, Notice, PageHeader, Properties, Segmented } from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { evaluateSettingsCompatibility } from "../settings-compatibility";
import { CopyButton } from "../requests/request-detail";
import { SingleSignOnCard } from "./single-sign-on-card";

const SLUG = /^[a-z][a-z0-9_-]{0,62}$/;

function scoped(previous: Record<string, unknown>) {
  return { application: previous.application as string | undefined, environment: previous.environment as string | undefined, organization: previous.organization as string | undefined };
}

// ─── General ────────────────────────────────────────────────────────────────

/** Owners require, or stop requiring, a second factor for every member of this organization. */
function SignInSecurityCard({ organizationID }: { organizationID: string }) {
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const queryClient = useQueryClient();
  const owner = session.data?.session?.capabilities.includes("manage_owners") ?? false;
  const status = useQuery(twoFactorStatusQueryOptions);
  const members = useQuery({ enabled: owner, queryFn: async () => (await adminRequest(queryPath("/admin/v1/administrators", { page_size: "200" }), AdministratorPageSchema)).data.items, queryKey: ["team", "members", "security"], retry: false });
  const [confirm, setConfirm] = useState<boolean>();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const required = status.data?.required_by_organization ?? false;
  const withoutTwoFactor = (members.data ?? []).filter((member) => member.status === "active" && !member.two_factor_enabled);
  async function save(next: boolean): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      await setTwoFactorRequirement(organizationID, next);
      setConfirm(undefined);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: twoFactorStatusQueryOptions.queryKey }),
        queryClient.invalidateQueries({ queryKey: consoleSessionQueryOptions.queryKey })
      ]);
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card icon="shield" meta={status.data ? <Badge color={required ? "success" : undefined} variant="soft">{required ? "Required" : "Optional"}</Badge> : undefined} title="Sign-in security">
      <p className="lw-note">When two-factor sign-in is required, members without it can only set it up after signing in. API tokens aren&apos;t affected.</p>
      {owner && members.data ? <p className="lw-secondary lw-note">{withoutTwoFactor.length === 0 ? "Every active member has two-factor sign-in on." : `${withoutTwoFactor.length} active ${withoutTwoFactor.length === 1 ? "member doesn't" : "members don't"} have it on yet.`}</p> : null}
      {owner ? (
        <div><Button disabled={!compatibility.mutationAllowed || !status.data} onClick={() => setConfirm(!required)} size="sm" variant={required ? "secondary" : "primary"}>{required ? "Stop Requiring Two-Factor" : "Require Two-Factor"}</Button></div>
      ) : <p className="lw-secondary lw-note">Only owners change this.</p>}
      {confirm !== undefined ? (
        <ConfirmDialog confirmLabel={confirm ? "Require Two-Factor" : "Stop Requiring"} description={confirm ? (withoutTwoFactor.length ? `${withoutTwoFactor.length} active ${withoutTwoFactor.length === 1 ? "member is" : "members are"} limited to setting it up from their next request.` : "Every active member already has it on.") : "Members keep their authenticators; new members won't be asked to set one up."} onCancel={() => setConfirm(undefined)} onConfirm={() => void save(confirm)} pending={busy} title={confirm ? "Require two-factor sign-in?" : "Stop requiring two-factor sign-in?"}>
          {confirm && withoutTwoFactor.length ? <ul className="lw-issue-items">{withoutTwoFactor.slice(0, 8).map((member) => <li key={member.id}>{member.display_name} · {member.email}</li>)}</ul> : null}
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </Card>
  );
}

function GeneralView() {
  const workspace = useOptionalWorkspace();
  const session = useConsoleSession();
  const organizations = useQuery({ ...organizationsQueryOptions(), enabled: !workspace?.organization });
  const compatibility = useConsoleCompatibility();
  const status = useQuery({ queryFn: async () => (await adminRequest("/admin/v1/system", SystemStatusSchema)).data, queryKey: ["system", "status"], retry: false });
  const doctor = useQuery({ queryFn: async () => (await adminRequest("/admin/v1/system/doctor", DoctorReportSchema)).data, queryKey: ["system", "doctor"], retry: false });
  const [theme, setThemeChoice] = useState<"system" | "light" | "dark">(() => storedTheme() ?? "system");
  // Organization pages may not carry an organization in the URL; fall back to the one this session signed in to.
  const organization = workspace?.organization ?? organizations.data?.items.find((item) => item.id === session.data?.session?.organization_id);
  const runtime = doctor.data?.facts.runtime;
  const retention = doctor.data?.facts.retention;
  const pickTheme = (next: "system" | "light" | "dark") => {
    setThemeChoice(next);
    if (next === "system") clearTheme();
    else setTheme(next);
  };
  return (
    <div className="lw-page">
      <PageHeader description="This organization, how the console looks for you, and the server it talks to." title="General" />
      <div className="lw-body lw-hgrid lw-hgrid--2">
        <Card icon="domains" title="Organization">
          {organization ? (
            <Properties columns={1} items={[
              { label: "Name", value: organization.display_name },
              { label: "ID", value: <span className="lw-row lw-row--tight"><span className="lw-mono lw-mono--sm">{organization.id}</span><CopyButton label="Copy organization ID" value={organization.id} /></span> },
              { label: "Applications", value: workspace?.applications.length ?? 0 }
            ]} />
          ) : session.data?.session?.organization_id ? (
            <Properties columns={1} items={[{ label: "ID", value: <span className="lw-row lw-row--tight"><span className="lw-mono lw-mono--sm">{session.data.session.organization_id}</span><CopyButton label="Copy organization ID" value={session.data.session.organization_id} /></span> }]} />
          ) : <p className="lw-secondary lw-note">No organization selected.</p>}
          <p className="lw-secondary lw-note">The organization name can&apos;t be changed from the console yet.</p>
        </Card>
        <Card icon="sun" title="Appearance">
          <Segmented items={[{ id: "system", label: "System" }, { id: "light", label: "Light" }, { id: "dark", label: "Dark" }]} label="Theme" onChange={pickTheme} value={theme} />
          <p className="lw-secondary lw-note">Only for you · saved in this browser.</p>
        </Card>
        <Card icon="server" meta={compatibility.mutationAllowed ? <Badge color="success" variant="soft">Changes allowed</Badge> : <Badge color="orange" variant="soft">Read-only</Badge>} title="About this server">
          {status.error ? <ProblemNotice problem={problemFromError(status.error)} /> : null}
          <Properties columns={2} items={[
            { label: "Server version", value: <>{status.data?.server_version ?? "—"}{runtime && runtime.latest_compatible_version !== runtime.server_version ? <> <Badge color="orange" variant="soft">{runtime.latest_compatible_version} available</Badge></> : null}</> },
            { label: "Contract", value: `${status.data?.contract_version ?? "—"} (console ${consoleContractVersion})` },
            { label: "Protocols", value: `${status.data?.protocol_versions.join(", ") ?? "—"} (console needs ${consoleProtocolVersion})` },
            { label: "Changes allowed", value: compatibility.mutationAllowed ? "Yes" : "No: the console is read-only until the server is compatible" },
            { label: "Database schema", value: status.data?.database_schema_version ?? "—" },
            { label: "Serving traffic", value: status.data ? (status.data.ready ? "Yes" : "No") : "—" }
          ]} />
          {status.data && evaluateSettingsCompatibility(status.data).readOnlySafeMode ? <Notice title="Why the console is read-only" tone="warning"><ul className="lw-issue-list">{evaluateSettingsCompatibility(status.data).reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></Notice> : null}
          <Link className="lw-link lw-note" search={scoped} to="/system-health">Open System Health</Link>
        </Card>
        {organization && compatibility.status?.server_capabilities.includes("admin_two_factor") ? <SignInSecurityCard organizationID={organization.id} /> : null}
        {organization && compatibility.status?.server_capabilities.includes("admin_sso") && session.data?.session?.capabilities.includes("manage_owners") ? <SingleSignOnCard organizationID={organization.id} /> : null}
        <Card icon="lock" title="Data handling">
          <ul className="lw-issue-list lw-note">
            <li><strong>Prompts and responses: never stored.</strong> There&apos;s no setting; a configuration that tries to store them is refused when published.</li>
            <li><strong>OpenTelemetry: set on the server,</strong> by whoever deploys it, not from the console.</li>
            <li><strong>Product analytics: none.</strong> The console sends no usage telemetry.</li>
          </ul>
          {retention ? (
            <Properties columns={2} items={[
              { label: "Oldest request", value: retention.oldest_request_at ? new Date(retention.oldest_request_at).toLocaleDateString() : "None" },
              { label: "Oldest usage", value: retention.oldest_usage_at ? new Date(retention.oldest_usage_at).toLocaleDateString() : "None" },
              { label: "Oldest audit event", value: retention.oldest_audit_at ? new Date(retention.oldest_audit_at).toLocaleDateString() : "None" },
              { label: "Console sessions kept", value: `${retention.admin_session_retention_hours} h` }
            ]} />
          ) : null}
          <p className="lw-secondary lw-note">How long requests, usage and audit events are kept is set by your deployment.</p>
        </Card>
      </div>
    </div>
  );
}

// ─── Applications ───────────────────────────────────────────────────────────

const KIND_TEXT = { development: "Development", production: "Production", staging: "Staging" } as const;

function AddApplicationDrawer({ onClose, onCreated, organizationID }: { onClose: () => void; onCreated: (application: ApplicationResource) => void; organizationID: string }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      onCreated((await adminRequest("/admin/v1/applications", ApplicationResourceSchema, { body: { display_name: name.trim(), organization_id: organizationID, slug }, method: "POST" })).data);
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }
  return (
    <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">Names and slugs can&apos;t be changed later</span>} title="Add application">
      <form className="lw-stack" onSubmit={(event) => void submit(event)}>
        <Field id="app-name" label="Name"><Input id="app-name" maxLength={128} onChange={(event) => { setName(event.target.value); if (!slug || slug === slugify(name)) setSlug(slugify(event.target.value)); }} required value={name} /></Field>
        <Field error={slug && !SLUG.test(slug) ? "Lowercase letters, digits, - or _, starting with a letter." : undefined} hint="Appears in URLs and the SDK configuration." id="app-slug" label="Slug"><Input id="app-slug" mono onChange={(event) => setSlug(event.target.value)} required value={slug} /></Field>
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!name.trim() || !SLUG.test(slug)} loading={busy} type="submit" variant="primary">Add Application</Button></div>
      </form>
    </DetailPanel>
  );
}

function slugify(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^[^a-z]+/, "").replace(/-+$/, "").slice(0, 63);
}

function AddEnvironmentDrawer({ application, existing, onClose, onCreated }: { application: ApplicationResource; existing: readonly EnvironmentResource[]; onClose: () => void; onCreated: (environment: EnvironmentResource) => void }) {
  const [kind, setKind] = useState<EnvironmentResource["kind"]>("development");
  const [name, setName] = useState("Development");
  const [slug, setSlug] = useState("development");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const taken = existing.some((environment) => environment.slug === slug);
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      const created = (await adminRequest(`/admin/v1/applications/${application.id}/environments`, EnvironmentResourceSchema, { body: { display_name: name.trim(), kind, slug }, method: "POST" })).data;
      if (created.application_id !== application.id) throw new Error("The new environment belongs to another application.");
      onCreated(created);
    } catch (failure) {
      setProblem(failure instanceof Error && !("problem" in failure) ? { code: "context_mismatch", detail: failure.message, retryable: false, status: 0, title: "Unexpected environment" } : problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }
  return (
    <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">In {application.display_name}</span>} title="Add environment">
      <form className="lw-stack" onSubmit={(event) => void submit(event)}>
        <div className="lw-role-cards" role="radiogroup">
          {(["development", "staging", "production"] as const).map((value) => (
            <label className={`lw-role-card${kind === value ? " is-on" : ""}`} key={value}>
              <input checked={kind === value} name="environment-kind" onChange={() => { setKind(value); if (name === KIND_TEXT[kind]) setName(KIND_TEXT[value]); if (slug === kind) setSlug(value); }} type="radio" value={value} />
              <strong>{KIND_TEXT[value]}</strong>
              <span className="lw-faint lw-note">{value === "production" ? "Real users. Changes need extra confirmation." : value === "staging" ? "A copy of production for checking releases." : "Local and debug builds; mock connections allowed."}</span>
            </label>
          ))}
        </div>
        <Field id="env-name" label="Name"><Input id="env-name" maxLength={256} onChange={(event) => setName(event.target.value)} required value={name} /></Field>
        <Field error={taken ? "This application already has an environment with this slug." : slug && !SLUG.test(slug) ? "Lowercase letters, digits, - or _, starting with a letter." : undefined} hint="Unique in the application; it can't change later." id="env-slug" label="Slug"><Input id="env-slug" mono onChange={(event) => setSlug(event.target.value)} required value={slug} /></Field>
        <Notice tone="info">It starts empty and refuses requests until a configuration is published. Run Setup or build one from the Build pages.</Notice>
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!name.trim() || !SLUG.test(slug) || taken} loading={busy} type="submit" variant="primary">Add Environment</Button></div>
      </form>
    </DetailPanel>
  );
}

type Lifecycle = { application: ApplicationResource; enable: boolean; environment?: EnvironmentResource };

function ApplicationsView() {
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const workspace = useOptionalWorkspace();
  const queryClient = useQueryClient();
  const organizationID = workspace?.organization?.id ?? session.data?.session?.organization_id ?? "";
  const applications = useQuery(applicationsQueryOptions(organizationID));
  const items = applications.data?.items ?? [];
  const environments = useQueries({ queries: items.map((application) => environmentsQueryOptions(application.id)) });
  const [addingApp, setAddingApp] = useState(false);
  const [addingEnvironment, setAddingEnvironment] = useState<ApplicationResource>();
  const [lifecycle, setLifecycle] = useState<Lifecycle>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [notice, setNotice] = useState<string>();
  const [busy, setBusy] = useState(false);
  const canManage = compatibility.mutationAllowed && (session.data?.session?.capabilities.includes("activate_configuration") ?? false);

  async function refresh(): Promise<void> {
    await queryClient.invalidateQueries({ queryKey: ["organization", organizationID, "applications"] });
    await queryClient.invalidateQueries({ predicate: (query) => query.queryKey[0] === "application" });
  }

  async function changeLifecycle(reason?: string): Promise<void> {
    if (!lifecycle) return;
    setBusy(true);
    setProblem(undefined);
    const target = lifecycle.environment ? `/admin/v1/environments/${lifecycle.environment.id}` : `/admin/v1/applications/${lifecycle.application.id}`;
    try {
      if (lifecycle.environment) await adminRequest(`${target}/${lifecycle.enable ? "enable" : "disable"}`, EnvironmentResourceSchema, lifecycle.enable ? { method: "POST" } : { body: { reason }, method: "POST" });
      else await adminRequest(`${target}/${lifecycle.enable ? "enable" : "disable"}`, ApplicationResourceSchema, lifecycle.enable ? { method: "POST" } : { body: { reason }, method: "POST" });
      const what = lifecycle.environment ? `${lifecycle.application.display_name} · ${lifecycle.environment.display_name}` : lifecycle.application.display_name;
      setNotice(lifecycle.enable ? `${what} is enabled. New sessions are allowed; revoked credentials stay revoked.` : `${what} is disabled. Requests are refused and its configuration is read-only.`);
      setLifecycle(undefined);
      await refresh();
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  const lifecycleName = lifecycle ? (lifecycle.environment ? `${lifecycle.application.slug}/${lifecycle.environment.slug}` : lifecycle.application.slug) : "";
  return (
    <div className="lw-page">
      <PageHeader actions={<Button disabled={!canManage} icon="plus" onClick={() => setAddingApp(true)} variant="primary">Add Application</Button>} description="Every application in this organization and its environments. Renaming and deleting aren't in the Admin API yet, so names are read-only." title="Applications" />
      {notice ? <div className="lw-page-notice"><Notice tone="success">{notice}</Notice></div> : null}
      {applications.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(applications.error)} /></div> : null}
      {!canManage ? <div className="lw-page-notice"><Notice tone="info">View only: adding, disabling and enabling need the Admin role (activate_configuration) and a compatible server.</Notice></div> : null}
      <div className="lw-body lw-stack">
        {applications.isPending ? <p role="status">Loading applications…</p> : items.map((application, index) => {
          const list = environments[index]?.data?.items ?? [];
          return (
            <Card actions={canManage ? <div className="lw-row"><Button disabled={application.status === "disabled"} icon="plus" onClick={() => setAddingEnvironment(application)} size="sm">Add Environment</Button><Button destructive={application.status !== "disabled"} onClick={() => setLifecycle({ application, enable: application.status === "disabled" })} size="sm">{application.status === "disabled" ? "Enable App" : "Disable App"}</Button></div> : undefined} key={application.id} meta={<span className="lw-row lw-row--tight"><span className="lw-mono lw-mono--sm">{application.slug}</span>{application.status === "disabled" ? <Badge color="red" variant="soft">Disabled</Badge> : null}</span>} title={application.display_name}>
              {environments[index]?.isPending ? <p role="status" className="lw-note">Loading environments…</p> : list.length ? (
                <table className="lw-mini-table">
                  <thead><tr><th>Environment</th><th>Slug</th><th>Status</th><th>Live revision</th><th /></tr></thead>
                  <tbody>
                    {list.map((environment) => (
                      <tr key={environment.id}>
                        <td><span className="lw-row lw-row--tight"><EnvironmentBadge kind={environment.kind} />{environment.display_name}</span></td>
                        <td className="lw-mono lw-mono--sm">{environment.slug}</td>
                        <td>{environment.status === "disabled" ? <Badge color="red" variant="soft">Disabled</Badge> : <Badge color="success" variant="soft">Active</Badge>}</td>
                        <td className="lw-mono lw-mono--sm">{environment.active_revision_id ?? <span className="lw-faint">No configuration</span>}</td>
                        <td>{canManage ? <Button destructive={environment.status !== "disabled"} onClick={() => setLifecycle({ application, enable: environment.status === "disabled", environment })} size="sm" variant="ghost">{environment.status === "disabled" ? "Enable" : "Disable"}</Button> : null}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <p className="lw-secondary lw-note">No environments yet.</p>}
            </Card>
          );
        })}
        {!applications.isPending && !items.length ? <Notice tone="info">No applications yet. Add one, or use Setup to create an application with its first environment.</Notice> : null}
        <p className="lw-secondary lw-note">Users per environment and copying one environment&apos;s configuration into a new one aren&apos;t available from the Admin API yet.</p>
      </div>
      {addingApp ? <div className="lw-drawer-dock"><AddApplicationDrawer onClose={() => setAddingApp(false)} onCreated={(application) => { setAddingApp(false); setNotice(`${application.display_name} was added. Add its first environment next.`); void refresh(); }} organizationID={organizationID} /></div> : null}
      {addingEnvironment ? <div className="lw-drawer-dock lw-drawer-dock--wide"><AddEnvironmentDrawer application={addingEnvironment} existing={environments[items.indexOf(addingEnvironment)]?.data?.items ?? []} onClose={() => setAddingEnvironment(undefined)} onCreated={(environment) => { setAddingEnvironment(undefined); setNotice(`${environment.display_name} was added. It refuses requests until a configuration is published.`); void refresh(); }} /></div> : null}
      {lifecycle && !lifecycle.enable ? (
        <ImpactDialog
          acknowledgement="I understand requests are refused and client credentials are revoked now."
          confirmLabel={lifecycle.environment ? "Disable Environment" : "Disable App"}
          facts={[["Still readable", "History, users, installations, the audit log and configuration history stay available; configuration becomes read-only."], ["Undo", "Enable allows new sessions again. Revoked credentials aren't restored."]]}
          impacts={[]}
          onCancel={() => setLifecycle(undefined)}
          onConfirm={({ reason }) => void changeLifecycle(reason)}
          pending={busy}
          reasonHint="The server checks that a reason is given; it doesn't store the text."
          scope={lifecycle.environment ? `Every app user and installation in ${lifecycle.application.display_name} · ${lifecycle.environment.display_name}.` : `Every environment of ${lifecycle.application.display_name}. Each environment keeps its own status.`}
          targetId={lifecycleName}
          title={`Disable ${lifecycle.environment ? `${lifecycle.application.display_name} · ${lifecycle.environment.display_name}` : lifecycle.application.display_name}?`}
        >
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ImpactDialog>
      ) : null}
      {lifecycle?.enable ? (
        <ConfirmDialog confirmLabel="Enable" description="New sessions are allowed again. Credentials revoked when it was disabled stay revoked; apps sign in again." onCancel={() => setLifecycle(undefined)} onConfirm={() => void changeLifecycle()} pending={busy} title={`Enable ${lifecycleName}?`}>
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

function OrganizationScope({ children }: { children: ReactNode }) {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <>{children}</>;
}

/** Settings → General. */
export function GeneralSettingsPage() { return <OrganizationScope><GeneralView /></OrganizationScope>; }
/** Settings → Applications. */
export function ApplicationsSettingsPage() { return <OrganizationScope><ApplicationsView /></OrganizationScope>; }

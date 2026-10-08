import { type FormEvent, useState } from "react";

import { useConsoleSession } from "../../api/session";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useOptionalWorkspace } from "../../app/workspace-context-value";
import { Badge, Button, Card, DetailPanel, Field, Input, Notice, PageHeader } from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { configurationAreas, type JSONRecord } from "../configuration-slice";
import { useConfigurationTask } from "../configuration-task";
import { ClientAccessSetup, PlatformReadiness } from "../task-configuration-pages";
import { CollectionPage, DraftSaveNotice } from "./collection-page";
import { useEnvironmentDraft } from "./environment-draft";
import { object, specCollection } from "./feature-model";

const PROVIDER_LABEL: Readonly<Record<string, string>> = { clerk: "Clerk", custom_jwt: "Custom JWT", firebase: "Firebase", generic_oidc: "OpenID Connect", supabase: "Supabase" };

function list(value: unknown): string {
  return Array.isArray(value) ? value.map(String).join(", ") : "—";
}

function UserSignInView() {
  const draft = useEnvironmentDraft();
  return (
    <CollectionPage
      addLabel="Add Provider"
      definition={configurationAreas.identity}
      description="Who your users sign in with. Latchway verifies their tokens from these providers and keeps only the claims you map."
      draft={draft}
      extraColumns={() => [
        { header: "Type", key: "type", render: (row) => <Badge variant="soft">{PROVIDER_LABEL[String(row.value.type)] ?? String(row.value.type)}</Badge> },
        { header: "Project or issuer", key: "issuer", render: (row) => <span className="lw-mono lw-mono--sm">{String(row.value.projectId ?? row.value.issuer ?? row.value.projectUrl ?? "—")}</span> },
        { header: "Audiences", key: "audiences", render: (row) => list(row.value.audiences) }
      ]}
      title="User sign-in"
    />
  );
}

function AppVerificationView() {
  const draft = useEnvironmentDraft();
  const task = useConfigurationTask();
  const [adding, setAdding] = useState(false);
  return (
    <>
      <CollectionPage
        addAction={<Button disabled={!draft.canConfigure} icon="plus" onClick={() => setAdding(true)} variant="primary">Add Platform</Button>}
        definition={configurationAreas.attestation}
        description="How Latchway checks that requests come from your genuine app: App Attest, Play Integrity, App Check or Turnstile, per platform."
        draft={draft}
        extraColumns={() => [
          { header: "Platforms", key: "platforms", render: (row) => object(row.value.platforms) ? Object.keys(row.value.platforms).map((platform) => platform.replaceAll("_", " ")).join(", ") : "—" },
          { header: "Used by", key: "features", render: (row) => draft.document ? specCollection(draft.document, "features").filter((feature) => feature.attestationPolicy === row.key).map((feature) => String(feature.id)).join(", ") || <span className="lw-faint">No feature</span> : "—" }
        ]}
        after={<div className="lw-page-notice"><PlatformReadiness task={task} /></div>}
        title="App verification"
      />
      {adding ? (
        <div className="lw-drawer-dock lw-drawer-dock--wide">
          <DetailPanel className="lw-request-drawer" onClose={() => { setAdding(false); task.setDraft(undefined); }} subtitle={<span className="lw-faint">Saved to the draft; verification secrets are stored right away and never returned</span>} title="Add platform">
            {task.problem ? <ProblemNotice problem={task.problem} /> : null}
            <ClientAccessSetup task={task} />
          </DetailPanel>
        </div>
      ) : null}
    </>
  );
}

function ComponentsView() {
  const draft = useEnvironmentDraft();
  return (
    <CollectionPage
      addLabel="Add Component"
      definition={configurationAreas.components}
      description="The app parts that may join an installation: the main app as the root, and the widgets and extensions it may delegate its trust to."
      draft={draft}
      extraColumns={() => [
        { header: "Platform", key: "platform", render: (row) => String(row.value.platform ?? "—").replaceAll("_", " ") },
        { header: "Kind", key: "kind", render: (row) => String(row.value.kind ?? "—").replaceAll("_", " ") },
        { header: "Role", key: "role", render: (row) => row.value.familyRole === "root" ? <Badge color="accent" variant="soft">Root</Badge> : <Badge variant="soft">Delegated</Badge> },
        { header: "Features", key: "features", render: (row) => list(row.value.allowedFeatures) }
      ]}
      title="Components"
    />
  );
}

const DURATION = /^[1-9][0-9]*(ms|s|m|h|d)$/;

function SessionsView() {
  const draft = useEnvironmentDraft();
  const session = draft.document && object(draft.document.spec) && object(draft.document.spec.session) ? draft.document.spec.session : {};
  const [values, setValues] = useState({
    accessTokenTtl: String(session.accessTokenTtl ?? ""),
    challengeTtl: String(session.challengeTtl ?? ""),
    maximumClockSkewSeconds: session.maximumClockSkewSeconds === undefined ? "" : String(session.maximumClockSkewSeconds),
    refreshTokenTtl: String(session.refreshTokenTtl ?? "")
  });
  const [error, setError] = useState<string>();
  const set = (key: keyof typeof values, value: string) => setValues((current) => ({ ...current, [key]: value }));

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const durations = (["accessTokenTtl", "challengeTtl", "refreshTokenTtl"] as const).filter((key) => values[key] && !DURATION.test(values[key]));
    const skew = values.maximumClockSkewSeconds === "" ? undefined : Number(values.maximumClockSkewSeconds);
    if (durations.length) return setError("Write durations as a number and a unit, like 15m, 30d or 900s.");
    if (skew !== undefined && (!Number.isInteger(skew) || skew < 0 || skew > 300)) return setError("Clock skew is a whole number of seconds from 0 to 300.");
    setError(undefined);
    const next: JSONRecord = {};
    for (const key of ["accessTokenTtl", "challengeTtl", "refreshTokenTtl"] as const) if (values[key]) next[key] = values[key];
    if (skew !== undefined) next.maximumClockSkewSeconds = skew;
    await draft.save((document) => {
      const copy = JSON.parse(JSON.stringify(document)) as JSONRecord;
      const spec = copy.spec as JSONRecord;
      if (Object.keys(next).length) spec.session = next;
      else delete spec.session;
      return copy;
    });
  }

  return (
    <div className="lw-page">
      <PageHeader description="How long your app users' Latchway sessions last. Leave a field empty to use the server default." title="Sessions" />
      <DraftSaveNotice draft={draft} />
      <div className="lw-body">
        <form className="lw-stack" key={JSON.stringify(session)} onSubmit={(event) => void save(event)}>
          <Card icon="clock" title="Session lifetimes">
            <div className="lw-form-grid">
              <Field hint="How long an access token works before the app refreshes it, e.g. 15m." id="session-access" label="Access token"><Input id="session-access" onChange={(event) => set("accessTokenTtl", event.target.value)} placeholder="Server default" value={values.accessTokenTtl} /></Field>
              <Field hint="How long a signed-in app can keep refreshing without signing in again, e.g. 30d." id="session-refresh" label="Refresh token"><Input id="session-refresh" onChange={(event) => set("refreshTokenTtl", event.target.value)} placeholder="Server default" value={values.refreshTokenTtl} /></Field>
              <Field hint="How long a session challenge stays valid, e.g. 2m." id="session-challenge" label="Challenge"><Input id="session-challenge" onChange={(event) => set("challengeTtl", event.target.value)} placeholder="Server default" value={values.challengeTtl} /></Field>
              <Field hint="Allowed difference between device and server clocks, 0–300 seconds." id="session-skew" label="Clock skew (seconds)"><Input id="session-skew" max={300} min={0} onChange={(event) => set("maximumClockSkewSeconds", event.target.value)} placeholder="Server default" type="number" value={values.maximumClockSkewSeconds} /></Field>
            </div>
          </Card>
          {error ? <Notice title="Fix this before saving" tone="danger">{error}</Notice> : null}
          <p className="lw-secondary lw-note">Shorter sessions limit how long a stolen token works; longer ones sign users in less often. Changes apply to sessions created after publishing.</p>
          <div className="lw-row"><Button disabled={!draft.canConfigure} loading={draft.busy} type="submit" variant="primary">Save to Draft</Button></div>
        </form>
      </div>
    </div>
  );
}

function ModelsPricingView() {
  const draft = useEnvironmentDraft();
  return <CollectionPage definition={configurationAreas.modelsPricing} description="The models each AI connection serves, how Latchway bounds their input before sending, and the prices it uses for cost." draft={draft} title="Models & pricing" />;
}

const VIEWS = { appVerification: AppVerificationView, components: ComponentsView, modelsPricing: ModelsPricingView, sessions: SessionsView, signIn: UserSignInView } as const;

/** Signed-in and scoped to an environment; the view's local state resets when the application or environment changes. */
function ScopedTrustPage({ view }: { view: keyof typeof VIEWS }) {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  const View = VIEWS[view];
  return <EnvironmentRequired><View key={`${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? "none"}`} /></EnvironmentRequired>;
}

/** Build → Client Trust → User sign-in. */
export function AuthenticationProvidersPage() { return <ScopedTrustPage view="signIn" />; }
/** Build → Client Trust → App verification. */
export function ClientAccessWorkspacePage() { return <ScopedTrustPage view="appVerification" />; }
/** Build → Client Trust → Components. */
export function ComponentDefinitionsPage() { return <ScopedTrustPage view="components" />; }
/** Build → Client Trust → Sessions. */
export function SessionsPolicyPage() { return <ScopedTrustPage view="sessions" />; }
/** Build → AI Connections → Models & pricing. */
export function ModelsPricingPage() { return <ScopedTrustPage view="modelsPricing" />; }

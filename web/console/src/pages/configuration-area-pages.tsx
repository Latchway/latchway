import { useConsoleSession } from "../api/session";
import { EnvironmentRequired } from "../app/workspace-context";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { AuthenticationProvidersPage as UserSignInPage, ClientAccessWorkspacePage, ComponentDefinitionsPage, ModelsPricingPage } from "./build/client-trust-pages";
import { CollectionPage } from "./build/collection-page";
import { ConnectionWorkspacePage } from "./build/connections-page";
import { useEnvironmentDraft } from "./build/environment-draft";
import { FeaturesPage } from "./build/features-page";
import { RoutingPage } from "./build/routing-page";
import { AccessRequired } from "./control-plane-pages";
import { configurationAreas, type ConfigurationAreaDefinition } from "./configuration-slice";
import { UsagePlanWorkspacePage } from "./task-configuration-pages";

/** A configuration area edited as a list of resources in the shared draft. */
function AreaPage({ definition }: { definition: ConfigurationAreaDefinition }) {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><AreaView definition={definition} key={`${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? "none"}`} /></EnvironmentRequired>;
}

function AreaView({ definition }: { definition: ConfigurationAreaDefinition }) {
  const draft = useEnvironmentDraft();
  return <CollectionPage definition={definition} description={definition.description} draft={draft} title={definition.title} />;
}

export function AuthenticationProvidersPage() { return <UserSignInPage />; }
export function AttestationConfigurationPage() { return <ClientAccessWorkspacePage />; }
export function ComponentDefinitionsConfigurationPage() { return <ComponentDefinitionsPage />; }
export function FeaturesConfigurationPage() { return <FeaturesPage />; }
export function RoutesConfigurationPage() { return <RoutingPage />; }
export function UpstreamsConfigurationPage() { return <ConnectionWorkspacePage />; }
export function ModelsPricingConfigurationPage() { return <ModelsPricingPage />; }
export function AccessPoliciesConfigurationPage() { return <AreaPage definition={configurationAreas.access} />; }
export function LimitPlansConfigurationPage() { return <UsagePlanWorkspacePage />; }
export function AbuseControlsConfigurationPage() { return <AreaPage definition={configurationAreas.abuse} />; }

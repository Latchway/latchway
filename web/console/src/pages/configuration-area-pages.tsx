import { AuthenticationProvidersPage as UserSignInPage, ClientAccessWorkspacePage, ComponentDefinitionsPage, ModelsPricingPage } from "./build/client-trust-pages";
import { ConnectionWorkspacePage } from "./build/connections-page";
import { FeaturesPage } from "./build/features-page";
import { RoutingPage } from "./build/routing-page";

export function AuthenticationProvidersPage() { return <UserSignInPage />; }
export function AttestationConfigurationPage() { return <ClientAccessWorkspacePage />; }
export function ComponentDefinitionsConfigurationPage() { return <ComponentDefinitionsPage />; }
export function FeaturesConfigurationPage() { return <FeaturesPage />; }
export function RoutesConfigurationPage() { return <RoutingPage />; }
export function UpstreamsConfigurationPage() { return <ConnectionWorkspacePage />; }
export function ModelsPricingConfigurationPage() { return <ModelsPricingPage />; }

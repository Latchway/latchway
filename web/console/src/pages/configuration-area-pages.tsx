import { ConfigurationEditorPage } from "./configuration-pages";

export function AuthenticationProvidersPage() {
  return <ConfigurationEditorPage areaDescription="Manage trusted identity issuers and normalized claim mappings in the complete immutable environment document." areaTitle="Authentication providers" canonicalPaths={["/spec/identityProviders"]} />;
}

export function AttestationConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Manage iOS, Android, web, React Native, and physical-device proof policy in the complete immutable environment document." areaTitle="Attestation" canonicalPaths={["/spec/attestationPolicies"]} />;
}

export function FeaturesConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Manage the client-visible feature surface in the complete immutable environment document." areaTitle="Features" canonicalPaths={["/spec/features"]} />;
}

export function RoutesConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Manage ordered route candidates and production resolution policy in the complete immutable environment document." areaTitle="Routes" canonicalPaths={["/spec/features/*/routes"]} />;
}

export function UpstreamsConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Manage bounded provider destinations and server-held credential references in the complete immutable environment document." areaTitle="Upstreams" canonicalPaths={["/spec/upstreams"]} />;
}

export function ModelsPricingConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Manage logical-to-physical model mappings, trusted input accounting, and operator-reviewed prices in the complete immutable environment document." areaTitle="Models & pricing" canonicalPaths={["/spec/models", "/spec/inputAccountingProfiles", "/spec/pricingCatalogs"]} />;
}

export function AccessPoliciesConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Manage per-feature authorization expressions in the complete immutable environment document." areaTitle="Access policies" canonicalPaths={["/spec/features/*/access"]} />;
}

export function LimitPlansConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Manage durable quota rules and per-feature plan selection in the complete immutable environment document." areaTitle="Limit plans" canonicalPaths={["/spec/limitPlans", "/spec/features/*/limitPlan"]} />;
}

export function AbuseControlsConfigurationPage() {
  return <ConfigurationEditorPage areaDescription="Abuse controls are an explicit composition of access, attestation, and limit policy; there is no separate hidden control document." areaTitle="Abuse controls" canonicalPaths={["/spec/features/*/access", "/spec/features/*/attestationPolicy", "/spec/limitPlans"]} />;
}

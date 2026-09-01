import { Link } from "@tanstack/react-router";
import { type FormEvent, useMemo, useState } from "react";

import {
  adminRequest,
  queryPath,
  RequestPageSchema,
  SecretMetadataSchema,
  SelfTestSchema,
  type ConfigurationRevision,
  type LogicalRequest,
  type SelfTestRun
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { EnvironmentRequired } from "../app/workspace-context";
import { type JSONRecord } from "./configuration-slice";
import { localTaskProblem, useConfigurationTask } from "./configuration-task";
import {
  buildClientAccessDocument,
  buildConnectionDocument,
  buildUsagePlanDocument,
  describeLimit,
  isJSONRecord,
  specRecords,
  type TaskProtocol
} from "./task-configuration-builders";

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
}

const protocols: TaskProtocol[] = ["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages"];

function integer(form: FormData, name: string): number {
  const value = Number(form.get(name));
  if (!Number.isSafeInteger(value)) throw new Error(`${name.replaceAll("_", " ")} must be a safe integer.`);
  return value;
}

function TaskScope({ application, environment, purpose }: { application?: { display_name: string }; environment?: { display_name: string; id: string; kind: string }; purpose: string }) {
  return environment ? <section aria-label={purpose} className={`production-context production-context--${environment.kind}`}><strong>{application?.display_name} / {environment.display_name}</strong><span>{environment.kind === "production" ? "Production configuration · publishing affects client traffic" : `${environment.kind} configuration`}</span><code>{environment.id}</code></section> : null;
}

function LoadingConfiguration({ pending }: { pending: boolean }) {
  return pending ? <section className="empty-state" role="status"><h2>Loading active configuration…</h2><p>The task will remain disabled until the exact environment revision is available.</p></section> : null;
}

function DraftReview({ draft, environmentName, production, title, busy, clear, publish }: {
  busy: boolean;
  clear: () => void;
  draft?: ReturnType<typeof useConfigurationTask>["activeDraft"];
  environmentName?: string;
  production: boolean;
  publish: () => Promise<ConfigurationRevision | undefined>;
  title: string;
}) {
  if (!draft) return null;
  return <section aria-labelledby="task-publish-heading" className={`publish-review ${draft.report.valid ? "publish-review--valid" : "publish-review--invalid"}`}><p className="eyebrow">Draft revision {draft.revision.version}</p><h2 id="task-publish-heading">Publish {title} to {production ? "Production" : environmentName}?</h2><div className="impact-grid"><div><strong>{draft.report.valid ? "Configuration valid" : "Configuration needs changes"}</strong><span>{draft.report.issues.length ? `${draft.report.issues.length} server issue(s)` : "All references resolve"}</span></div><div><strong>{draft.plan?.changes.length ?? 0} planned change(s)</strong><span>{draft.plan?.warnings.length ? `${draft.plan.warnings.length} warning(s)` : "No structural warnings"}</span></div><div><strong>{production ? "Production traffic" : "Non-production traffic"}</strong><span>Publishing is atomic; rollback creates a new revision</span></div></div>{draft.report.issues.length ? <ul>{draft.report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code>{issue.path}</code> — {issue.message}</li>)}</ul> : null}{draft.plan?.changes.length ? <ul>{draft.plan.changes.map((change, index) => <li key={`${change.path}-${index}`}><strong>{change.operation}</strong> <code>{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul> : null}<div className="button-row"><button className="secondary-action" disabled={busy} onClick={clear} type="button">Keep server draft unpublished</button><button className="primary-action" disabled={busy || !draft.report.valid} onClick={() => void publish()} type="button">Publish to {production ? "Production" : environmentName}</button></div><p className="draft-retention-note">The Admin API currently retains server drafts for audit and exposes no abandon/delete mutation. Keeping it unpublished is safe; use Configuration revisions to inspect it.</p></section>;
}

function loopbackURL(value: unknown): boolean {
  try {
    const parsed = new URL(String(value));
    return parsed.protocol === "http:" && new Set(["localhost", "127.0.0.1", "[::1]"]).has(parsed.hostname);
  } catch {
    return false;
  }
}

function ConnectionWorkspace() {
  const task = useConfigurationTask("connections");
  const [connectionType, setConnectionType] = useState<"anthropic" | "openai_compatible">("openai_compatible");
  const [lastConnection, setLastConnection] = useState<{ id: string; model: string; selfTestSupported: boolean }>();
  const [connectionPublished, setConnectionPublished] = useState(false);
  const [secretCreated, setSecretCreated] = useState<string>();
  const [selfTest, setSelfTest] = useState<SelfTestRun>();
  const [verifiedRequest, setVerifiedRequest] = useState<LogicalRequest>();
  const document = task.source?.document as JSONRecord | undefined;
  const upstreams = useMemo(() => document ? specRecords(document, "upstreams") : [], [document]);
  const models = useMemo(() => document ? specRecords(document, "models") : [], [document]);
  const features = useMemo(() => document ? specRecords(document, "features") : [], [document]);
  const localMock = task.environment?.kind === "development" && upstreams.some((upstream) => loopbackURL(upstream.baseUrl));
  const sampleFeature = String(features.find((feature) => feature.id === "habit-assistant")?.id ?? features[0]?.id ?? "habit-assistant");

  async function stageConnection(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!document || !task.environment) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const authentication = String(data.get("authentication")) as "bearer" | "none";
    const secretName = String(data.get("secret_name"));
    const secretInput = form.elements.namedItem("secret_value");
    const secretValue = secretInput instanceof HTMLInputElement ? secretInput.value : "";
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    try {
      const connectionID = String(data.get("connection_id"));
      const modelID = String(data.get("model_id"));
      const protocol = String(data.get("protocol")) as TaskProtocol;
      const providerType = String(data.get("provider_type")) as "anthropic" | "openai_compatible";
      const next = buildConnectionDocument(document, {
        authentication,
        baseURL: String(data.get("base_url")),
        connectionID,
        inputPriceUSDPerMillion: String(data.get("input_price")),
        maximumContextTokens: integer(data, "maximum_context_tokens"),
        maximumFramingTokensPerMessage: integer(data, "framing_per_message"),
        maximumFramingTokensPerRequest: integer(data, "framing_per_request"),
        modelID,
        outputPriceUSDPerMillion: String(data.get("output_price")),
        physicalModel: String(data.get("physical_model")),
        protocol,
        providerType,
        requestPriceUSD: String(data.get("request_price")),
        ...(authentication === "bearer" ? { secretName } : {})
      });
      if (authentication === "bearer") {
        if (!secretValue) throw new Error("Enter the write-only provider credential.");
        await adminRequest("/admin/v1/secrets", SecretMetadataSchema, { method: "POST", body: { environment_id: task.environment.id, name: secretName, value: secretValue } });
        setSecretCreated(secretName);
      }
      const staged = await task.stage(next, `Admin console add AI connection ${connectionID}`);
      if (staged) {
        setConnectionPublished(false);
        setLastConnection({ id: connectionID, model: modelID, selfTestSupported: ["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages"].includes(protocol) });
      }
    } catch (error) {
      const isInputProblem = error instanceof Error && ["Enter", "Connection", "Derived", "Physical", "HTTPS", "USD", "Choose"].some((prefix) => error.message.startsWith(prefix));
      task.setProblem(isInputProblem ? localTaskProblem(error.message, "AI connection is incomplete") : problemFromError(error));
    }
  }

  async function runSelfTest(): Promise<void> {
    if (!task.environment || !lastConnection) return;
    task.setProblem(undefined);
    try {
      setSelfTest((await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body: { environment_id: task.environment.id, kind: "upstream", max_cost_nano_usd: 10_000_000, model: lastConnection.model, upstream: lastConnection.id } })).data);
    } catch (error) { task.setProblem(problemFromError(error)); }
  }

  async function verifySample(): Promise<void> {
    if (!task.environment) return;
    task.setProblem(undefined);
    try {
      const result = (await adminRequest(queryPath("/admin/v1/requests", { environment_id: task.environment.id, page_size: "50" }), RequestPageSchema)).data;
      const matching = result.items.find((request) => request.feature === sampleFeature);
      if (!matching) throw new Error("sample_missing");
      setVerifiedRequest(matching);
    } catch (error) {
      task.setProblem(error instanceof Error && error.message === "sample_missing" ? localTaskProblem(`No durable ${sampleFeature} request is visible yet. Run the client sample, then check again.`, "Sample request not observed") : problemFromError(error));
    }
  }

  return <div className="control-page task-workspace">
    <section className="page-heading"><div><p className="eyebrow">AI connections</p><h1>Connect a provider without exposing its credential.</h1><p>Add the endpoint, one physical model, trusted input-accounting bounds, and operator-reviewed pricing as one preserved configuration change.</p></div><button className="secondary-action" disabled={task.busy || task.configuration.isFetching} onClick={() => void task.configuration.refetch()} type="button">Refresh connections</button></section>
    <TaskScope application={task.application} environment={task.environment} purpose="AI connection change scope" />
    <ProblemNotice problem={task.problem ?? (task.configuration.error ? problemFromError(task.configuration.error) : undefined)} />
    <LoadingConfiguration pending={task.configuration.isPending} />
    {document ? <>
      <section className="task-card-list"><div className="detail-card__heading"><div><p className="eyebrow">Active revision {task.source?.version}</p><h2>Connections</h2></div><code>{task.sourceETag}</code></div>{upstreams.length ? upstreams.map((upstream) => { const related = models.filter((model) => model.upstream === upstream.id); return <article className="task-summary-card" key={String(upstream.id)}><div><strong>{String(upstream.id)}</strong><span className="state-badge state-badge--available"><span aria-hidden="true" className="state-badge__dot" />Configured</span></div><p>{String(upstream.type).replaceAll("_", " ")} · {String(upstream.baseUrl)}</p><dl><div><dt>Credential</dt><dd>{isJSONRecord(upstream.authentication) ? String(upstream.authentication.type) : "unknown"}</dd></div><div><dt>Models</dt><dd>{related.map((model) => String(model.id)).join(", ") || "None"}</dd></div></dl></article>; }) : <p>No AI connections are active.</p>}</section>
      {task.environment?.kind === "development" ? <section className={`development-path ${localMock ? "development-path--ready" : ""}`}><div><p className="eyebrow">Development-first path</p><h2>{localMock ? "Local mock connection is ready." : "Start the isolated local development stack."}</h2><p>{localMock ? "This Development revision points to a loopback mock upstream. Provider cost is deterministic and no live provider account is required." : "The Admin API cannot create a mock server. Start the gateway-owned fixture, then reopen its Console."}</p></div>{!localMock ? <pre>latchway develop --browser-origin {typeof window === "undefined" ? "http://localhost:5173" : window.location.origin}</pre> : <><ol><li>Use the CLI-provided console credential.</li><li>Run the official JavaScript development client with application <code>{task.application?.id}</code> and feature <code>{sampleFeature}</code>.</li><li>Return here to verify the durable request record.</li></ol><p>The console only reads durable request records; it does not impersonate an application user or send a client request.</p><div className="button-row"><button className="primary-action" onClick={() => void verifySample()} type="button">Check for verified sample request</button><Link className="secondary-action" search={(previous) => previous} to="/requests">Open request explorer</Link></div>{verifiedRequest ? <p className="resource-result">Observed <code>{verifiedRequest.id}</code>: <strong>{verifiedRequest.status}</strong> via {verifiedRequest.attempts.at(-1)?.model ?? "recorded model"}.</p> : null}</>}</section> : null}
      <form className="control-form task-builder" onSubmit={(event) => void stageConnection(event)}><div><p className="eyebrow">Add connection</p><h2>Endpoint, credential, model, and price</h2><p>A bearer value is sent once to the Secrets API and cleared before the request completes. The configuration references only its logical name.</p></div><fieldset><legend>1. Provider destination</legend><div className="form-field-grid"><label>Connection ID<input defaultValue="primary" name="connection_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Connection type<select name="provider_type" onChange={(event) => setConnectionType(event.target.value as "anthropic" | "openai_compatible")} value={connectionType}><option value="openai_compatible">OpenAI-compatible provider or gateway</option><option value="anthropic">Anthropic-compatible provider or gateway</option></select></label><label>Base URL<input defaultValue="https://api.openai.com/v1" name="base_url" required type="url" /></label></div><small>This guided flow accepts HTTPS only. The loopback fixture is gateway-owned and appears above when started with <code>latchway develop</code>.</small></fieldset><fieldset><legend>2. Server-held credential</legend><div className="form-field-grid"><label>Authentication<select defaultValue="bearer" name="authentication"><option value="bearer">Bearer secret</option><option value="none">No authentication</option></select></label><label>Secret name<input defaultValue="provider_api_key" name="secret_name" pattern="[a-z][a-z0-9_-]{0,62}" /></label><label>Provider credential<input autoComplete="new-password" name="secret_value" type="password" /></label></div><small>No-auth is appropriate only for a deliberately controlled destination. A created secret remains encrypted server-side even if its configuration draft stays unpublished.</small></fieldset><fieldset><legend>3. Model and protocol</legend><div className="form-field-grid"><label>Logical model ID<input defaultValue="assistant_default" name="model_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Physical provider model<input defaultValue="gpt-5-mini" name="physical_model" required /></label><label>Protocol<select defaultValue={connectionType === "anthropic" ? "anthropic_messages" : "openai_responses"} key={connectionType} name="protocol">{protocols.filter((protocol) => connectionType === "anthropic" ? protocol === "anthropic_messages" : protocol !== "anthropic_messages").map((protocol) => <option key={protocol} value={protocol}>{protocol.replaceAll("_", " ")}</option>)}</select></label><label>Maximum context tokens<input defaultValue={128000} min={1} name="maximum_context_tokens" type="number" /></label><label>Framing tokens / request<input defaultValue={8} min={0} name="framing_per_request" type="number" /></label><label>Framing tokens / message<input defaultValue={4} min={0} name="framing_per_message" type="number" /></label></div></fieldset><fieldset><legend>4. Operator-reviewed USD pricing</legend><div className="form-field-grid"><label>Input USD / 1M tokens<input defaultValue="0.25" inputMode="decimal" name="input_price" /></label><label>Output USD / 1M tokens<input defaultValue="2" inputMode="decimal" name="output_price" /></label><label>USD / request<input defaultValue="0" inputMode="decimal" name="request_price" /></label></div><small>Decimal USD is converted exactly to integer nano-USD. Latchway does not fetch provider prices.</small></fieldset><button className="primary-action" disabled={!task.canConfigure || task.busy} type="submit">Review connection change</button></form>
      {secretCreated ? <p className="control-notice"><strong>Credential stored</strong><span><code>secret/{secretCreated}</code> exists server-side and is not part of the draft document.</span></p> : null}
      <DraftReview busy={task.busy} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={async () => { const revision = await task.publish(); if (revision) setConnectionPublished(true); return revision; }} title={lastConnection?.id ?? "connection change"} />
      {lastConnection && connectionPublished ? <section className="detail-card"><h2>Test the published connection</h2><p>The bounded self-test uses the selected upstream and model with a 10,000,000 nano-USD ceiling. Generative protocols exercise non-streaming and streaming; Embeddings sends one non-streaming request and records non-applicable checks as skipped. It does not impersonate an application user.</p>{lastConnection.selfTestSupported ? <button className="primary-action" onClick={() => void runSelfTest()} type="button">Run bounded connection test</button> : <p className="control-notice"><strong>Self-test unavailable for this protocol</strong><span>Connection self-tests support OpenAI Responses, Chat, Embeddings, and Anthropic Messages. Verify another protocol through a real client request.</span></p>}{selfTest ? <p className="resource-result">Self-test <code>{selfTest.id}</code>: <strong>{selfTest.state}</strong></p> : null}</section> : null}
    </> : null}
  </div>;
}

function ClientAccessWorkspace() {
  const task = useConfigurationTask("client-access");
  const [platform, setPlatform] = useState<"android" | "ios" | "web">("ios");
  const [addIdentity, setAddIdentity] = useState(false);
  const [selectedFeatureID, setSelectedFeatureID] = useState("");
  const [changeLabel, setChangeLabel] = useState("client access change");
  const document = task.source?.document as JSONRecord | undefined;
  const identities = useMemo(() => document ? specRecords(document, "identityProviders") : [], [document]);
  const policies = useMemo(() => document ? specRecords(document, "attestationPolicies") : [], [document]);
  const components = useMemo(() => document ? specRecords(document, "componentDefinitions") : [], [document]);
  const features = useMemo(() => document ? specRecords(document, "features") : [], [document]);
  const effectiveFeatureID = features.some((feature) => feature.id === selectedFeatureID) ? selectedFeatureID : String(features[0]?.id ?? "");
  const suggestedPolicyID = String(features.find((feature) => feature.id === effectiveFeatureID)?.attestationPolicy ?? `${platform}_clients`);

  async function stageClient(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!document || !task.environment) return;
    const data = new FormData(event.currentTarget);
    try {
      const componentID = String(data.get("component_id"));
      const next = buildClientAccessDocument(document, {
        androidCertificateDigest: String(data.get("android_certificate_digest")),
        androidCloudProjectNumber: Number(data.get("android_cloud_project")),
        androidPackageName: String(data.get("android_package_name")),
        androidVersionCode: Number(data.get("android_version_code")),
        appIDPrefix: String(data.get("app_id_prefix")),
        appleBundleID: String(data.get("apple_bundle_id")),
        appleBundleVersion: String(data.get("apple_bundle_version")),
        appleValidationCategory: Number(data.get("apple_validation_category")) as 2 | 3 | 4 | 5,
        attestationPolicyID: String(data.get("policy_id")),
        componentID,
        environmentKind: task.environment.kind,
        featureID: String(data.get("feature_id")),
        firebaseAppID: String(data.get("firebase_app_id")),
        firebaseProjectNumber: String(data.get("firebase_project_number")),
        ...(addIdentity ? { firebaseProjectID: String(data.get("firebase_project_id")), identityProviderID: String(data.get("identity_provider_id")) } : {}),
        platform,
        webOrigin: String(data.get("web_origin"))
      });
      const staged = await task.stage(next, `Admin console add ${platform} client access ${componentID}`);
      if (staged) setChangeLabel(componentID);
    } catch (error) { task.setProblem(localTaskProblem(error instanceof Error ? error.message : "Client access details are invalid.", "Client access is incomplete")); }
  }

  return <div className="control-page task-workspace"><section className="page-heading"><div><p className="eyebrow">Client access</p><h1>Trust an application surface.</h1><p>Connect user authentication, platform verification, a root component identity, and its feature grant without exposing the underlying schema.</p></div><button className="secondary-action" disabled={task.busy || task.configuration.isFetching} onClick={() => void task.configuration.refetch()} type="button">Refresh client access</button></section><TaskScope application={task.application} environment={task.environment} purpose="Client access change scope" /><ProblemNotice problem={task.problem ?? (task.configuration.error ? problemFromError(task.configuration.error) : undefined)} /><LoadingConfiguration pending={task.configuration.isPending} />{document ? <><section className="client-access-overview"><article><span>{identities.length}</span><strong>User authentication provider(s)</strong><p>{identities.map((item) => String(item.id)).join(", ") || "None configured"}</p></article><article><span>{policies.length}</span><strong>App-verification policy(s)</strong><p>{policies.map((item) => String(item.id)).join(", ") || "None configured"}</p></article><article><span>{components.length}</span><strong>Client component(s)</strong><p>{components.map((item) => String(item.id)).join(", ") || "None configured"}</p></article></section><form className="control-form task-builder" onSubmit={(event) => void stageClient(event)}><div><p className="eyebrow">Add application surface</p><h2>Identity, proof, component, and feature grant</h2><p>Production defaults require real platform evidence. Debug signing remains confined to the isolated <code>latchway develop</code> fixture.</p></div><fieldset><legend>1. Choose the surface</legend><div className="segmented-control" role="group" aria-label="Client platform">{(["ios", "android", "web"] as const).map((value) => <button aria-pressed={platform === value} className={platform === value ? "segmented-control__active" : ""} key={value} onClick={() => setPlatform(value)} type="button">{value === "ios" ? "iOS" : value === "android" ? "Android" : "Web"}</button>)}</div><div className="form-field-grid"><label>Component ID<input defaultValue={`${platform}_main`} key={`component-${platform}`} name="component_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Verification policy ID<input defaultValue={suggestedPolicyID} key={`policy-${platform}-${effectiveFeatureID}-${suggestedPolicyID}`} name="policy_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Allowed feature<select name="feature_id" onChange={(event) => setSelectedFeatureID(event.target.value)} required value={effectiveFeatureID}><option value="">Choose a feature</option>{features.map((feature) => <option key={String(feature.id)} value={String(feature.id)}>{String(feature.id)}</option>)}</select></label></div></fieldset><fieldset><legend>2. User authentication</legend><label className="check-row"><input checked={addIdentity} onChange={(event) => setAddIdentity(event.target.checked)} type="checkbox" />Add a Firebase authentication provider with this change</label>{addIdentity ? <div className="form-field-grid"><label>Provider ID<input defaultValue="firebase" name="identity_provider_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Firebase project ID<input name="firebase_project_id" required /></label></div> : <p>{identities.length ? `Existing providers remain available: ${identities.map((identity) => String(identity.id)).join(", ")}.` : "No provider exists yet. Add Firebase authentication or configure an advanced OIDC provider."}</p>}</fieldset>{platform === "ios" ? <fieldset><legend>3. Apple App Attest</legend><div className="form-field-grid"><label>App ID prefix<input name="app_id_prefix" required /></label><label>Bundle identifier<input name="apple_bundle_id" required /></label><label>CFBundleVersion<input name="apple_bundle_version" required /></label><label>Distribution<select defaultValue={task.environment?.kind === "development" ? "3" : "4"} name="apple_validation_category"><option value="3">Development signing</option><option value="2">TestFlight</option><option value="4">App Store</option><option value="5">Ad hoc / enterprise</option></select></label></div></fieldset> : platform === "android" ? <fieldset><legend>3. Google Play Integrity</legend><div className="form-field-grid"><label>Package name<input name="android_package_name" required /></label><label>Cloud project number<input min={1} name="android_cloud_project" required type="number" /></label><label>Signing certificate SHA-256 (base64url)<input name="android_certificate_digest" pattern="[A-Za-z0-9_-]{43}=?" required /></label><label>Exact version code<input min={0} name="android_version_code" type="number" /></label></div></fieldset> : <fieldset><legend>3. Firebase App Check for web</legend><div className="form-field-grid"><label>Exact browser origin<input defaultValue={typeof window === "undefined" ? "https://app.example.com" : window.location.origin} name="web_origin" required type="url" /></label><label>Firebase project number<input name="firebase_project_number" required /></label><label>Firebase web app ID<input name="firebase_app_id" required /></label></div></fieldset>}<button className="primary-action" disabled={!task.canConfigure || task.busy || features.length === 0} type="submit">Review client-access change</button></form><DraftReview busy={task.busy} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={task.publish} title={changeLabel} /></> : null}</div>;
}

function UsagePlanWorkspace() {
  const task = useConfigurationTask("usage-plans");
  const [changeLabel, setChangeLabel] = useState("usage plan");
  const document = task.source?.document as JSONRecord | undefined;
  const plans = useMemo(() => document ? specRecords(document, "limitPlans") : [], [document]);

  async function stagePlan(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!document) return;
    const data = new FormData(event.currentTarget);
    try {
      const planID = String(data.get("plan_id"));
      const next = buildUsagePlanDocument(document, {
        dailyCostUSD: String(data.get("daily_cost_usd")),
        dailyInputTokens: integer(data, "daily_input_tokens"),
        dailyLogicalRequests: integer(data, "daily_requests"),
        dailyOutputTokens: integer(data, "daily_output_tokens"),
        dailyTotalTokens: integer(data, "daily_total_tokens"),
        maximumConcurrentRequests: integer(data, "concurrent_requests"),
        perRequestInputTokens: integer(data, "per_request_input_tokens"),
        perRequestOutputTokens: integer(data, "per_request_output_tokens"),
        planID,
        scope: String(data.get("scope")) as "environment_feature" | "user" | "user_feature",
        timezone: String(data.get("timezone"))
      });
      const staged = await task.stage(next, `Admin console add usage plan ${planID}`);
      if (staged) setChangeLabel(planID);
    } catch (error) { task.setProblem(localTaskProblem(error instanceof Error ? error.message : "Usage-plan details are invalid.", "Usage plan is incomplete")); }
  }

  return <div className="control-page task-workspace"><section className="page-heading"><div><p className="eyebrow">Usage plans</p><h1>Set limits in operator language.</h1><p>Group enforceable volume, cost, per-request, and concurrency limits into a plan. Advanced units remain available in the full configuration editor.</p></div><button className="secondary-action" disabled={task.busy || task.configuration.isFetching} onClick={() => void task.configuration.refetch()} type="button">Refresh plans</button></section><TaskScope application={task.application} environment={task.environment} purpose="Usage-plan change scope" /><ProblemNotice problem={task.problem ?? (task.configuration.error ? problemFromError(task.configuration.error) : undefined)} /><LoadingConfiguration pending={task.configuration.isPending} />{document ? <><section className="task-card-list"><div className="detail-card__heading"><div><p className="eyebrow">Active revision {task.source?.version}</p><h2>Configured plans</h2></div><code>{task.sourceETag}</code></div>{plans.length ? plans.map((plan) => <article className="task-summary-card" key={String(plan.id)}><div><strong>{String(plan.id)}</strong><span>{Array.isArray(plan.limits) ? `${plan.limits.length} limit(s)` : "Invalid limits"}</span></div>{Array.isArray(plan.limits) ? <ul>{plan.limits.filter(isJSONRecord).map((limit, index) => <li key={`${String(limit.metric)}-${String(limit.algorithm)}-${index}`}>{describeLimit(limit)}</li>)}</ul> : null}</article>) : <p>No usage plans are active.</p>}</section><form className="control-form task-builder" onSubmit={(event) => void stagePlan(event)}><div><p className="eyebrow">New usage plan</p><h2>Choose only the limits this plan needs.</h2><p>Leave a numeric field at zero to omit that rule. Every generated rule is hard, server-owned, and grouped by the selected scope.</p></div><fieldset><legend>1. Plan identity and audience</legend><div className="form-field-grid"><label>Plan ID<input defaultValue="starter" name="plan_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Group usage by<select defaultValue="user_feature" name="scope"><option value="user_feature">User + feature</option><option value="user">User across features</option><option value="environment_feature">Environment + feature</option></select></label><label>Calendar timezone<input defaultValue="UTC" name="timezone" /></label></div></fieldset><fieldset><legend>2. Daily volume and cost</legend><div className="form-field-grid"><label>Requests / day<input defaultValue={100} min={0} name="daily_requests" type="number" /></label><label>Input tokens / day<input defaultValue={100000} min={0} name="daily_input_tokens" type="number" /></label><label>Output tokens / day<input defaultValue={100000} min={0} name="daily_output_tokens" type="number" /></label><label>Total tokens / day<input defaultValue={200000} min={0} name="daily_total_tokens" type="number" /></label><label>Cost USD / day<input defaultValue="1" inputMode="decimal" name="daily_cost_usd" /></label></div></fieldset><fieldset><legend>3. Per-request and simultaneous work</legend><div className="form-field-grid"><label>Input tokens / request<input defaultValue={20000} min={0} name="per_request_input_tokens" type="number" /></label><label>Output tokens / request<input defaultValue={2000} min={0} name="per_request_output_tokens" type="number" /></label><label>Concurrent requests<input defaultValue={4} min={0} name="concurrent_requests" type="number" /></label></div></fieldset><button className="primary-action" disabled={!task.canConfigure || task.busy} type="submit">Review usage-plan change</button></form><p className="control-notice"><strong>Effective-limit inspection</strong><span>The current Admin API exposes configured plans and per-user overrides, but no endpoint returns the fully resolved effective limits with sources. The console does not approximate that answer.</span></p><DraftReview busy={task.busy} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={task.publish} title={changeLabel} /></> : null}</div>;
}

export function ConnectionWorkspacePage() { return <EnvironmentRequired><ConnectionWorkspace /></EnvironmentRequired>; }
export function ClientAccessWorkspacePage() { return <EnvironmentRequired><ClientAccessWorkspace /></EnvironmentRequired>; }
export function UsagePlanWorkspacePage() { return <EnvironmentRequired><UsagePlanWorkspace /></EnvironmentRequired>; }

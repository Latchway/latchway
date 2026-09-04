import { Link } from "@tanstack/react-router";
import { type FormEvent, useMemo, useState } from "react";

import {
  adminRequest,
  queryPath,
  RequestPageSchema,
  RequestSchema,
  runDevelopmentSample,
  SelfTestSchema,
  type ConfigurationRevision,
  type LogicalRequest,
  type SelfTestRun
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { EnvironmentRequired } from "../app/workspace-context";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { type JSONRecord } from "./configuration-slice";
import { localTaskProblem, useConfigurationTask } from "./configuration-task";
import {
  buildClientAccessDocument,
  buildConnectionDocument,
  buildUsagePlanDocument,
  clientPlatformReadiness,
  describeLimit,
  isJSONRecord,
  specRecords,
  type ClientPlatform,
  type TaskProtocol,
  type WebVerificationProvider
} from "./task-configuration-builders";
import {
  resolveWriteOnlySecret,
  WriteOnlySecretResolutionError,
  type WriteOnlySecretAction,
  type WriteOnlySecretResolution
} from "./write-only-secret";

function ProblemNotice({ problem }: { problem?: AdminProblem }) {
  return problem ? <div className="control-notice control-notice--error" role="alert"><strong>{problem.title}</strong><span>{problem.detail}</span><small>Code: {problem.code}{problem.requestId ? ` · Request: ${problem.requestId}` : ""}{problem.operationId ? ` · Operation: ${problem.operationId}` : ""}</small>{problem.documentationURL ? <a href={problem.documentationURL} rel="noreferrer" target="_blank">View troubleshooting</a> : null}</div> : null;
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

function DraftReview({ draft, environmentName, production, title, busy, canPublish, clear, publish }: {
  busy: boolean;
  canPublish: boolean;
  clear: () => void;
  draft?: ReturnType<typeof useConfigurationTask>["activeDraft"];
  environmentName?: string;
  production: boolean;
  publish: () => Promise<ConfigurationRevision | undefined>;
  title: string;
}) {
  if (!draft) return null;
  return <section aria-labelledby="task-publish-heading" className={`publish-review ${draft.report.valid ? "publish-review--valid" : "publish-review--invalid"}`}><p className="eyebrow">Draft revision {draft.revision.version}</p><h2 id="task-publish-heading">Publish {title} to {production ? "Production" : environmentName}?</h2><div className="impact-grid"><div><strong>{draft.report.valid ? "Configuration valid" : "Configuration needs changes"}</strong><span>{draft.report.issues.length ? `${draft.report.issues.length} server issue(s)` : "All references resolve"}</span></div><div><strong>{draft.plan?.changes.length ?? 0} planned change(s)</strong><span>{draft.plan?.warnings.length ? `${draft.plan.warnings.length} warning(s)` : "No structural warnings"}</span></div><div><strong>{production ? "Production traffic" : "Non-production traffic"}</strong><span>Publishing is atomic; rollback creates a new revision</span></div></div>{draft.report.issues.length ? <ul>{draft.report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code>{issue.path}</code> — {issue.message}</li>)}</ul> : null}{draft.plan?.changes.length ? <ul>{draft.plan.changes.map((change, index) => <li key={`${change.path}-${index}`}><strong>{change.operation}</strong> <code>{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul> : null}<div className="button-row"><button className="secondary-action" disabled={busy} onClick={clear} type="button">Keep server draft unpublished</button><button className="primary-action" disabled={busy || !canPublish || !draft.report.valid} onClick={() => void publish()} type="button">Publish to {production ? "Production" : environmentName}</button></div><p className="draft-retention-note">The Admin API currently retains server drafts for audit and exposes no abandon/delete mutation. Keeping it unpublished is safe; use Configuration revisions to inspect it.</p></section>;
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
  const [authenticationMode, setAuthenticationMode] = useState<"bearer" | "none">("bearer");
  const [secretAction, setSecretAction] = useState<WriteOnlySecretAction>("create");
  const [secretResolution, setSecretResolution] = useState<WriteOnlySecretResolution>();
  const [lastConnection, setLastConnection] = useState<{ id: string; model: string; selfTestSupported: boolean }>();
  const [connectionPublished, setConnectionPublished] = useState(false);
  const [secretCreated, setSecretCreated] = useState<string>();
  const [selfTest, setSelfTest] = useState<SelfTestRun>();
  const [verifiedRequest, setVerifiedRequest] = useState<LogicalRequest>();
  const [sampleBusy, setSampleBusy] = useState(false);
  const document = task.source?.document as JSONRecord | undefined;
  const upstreams = useMemo(() => document ? specRecords(document, "upstreams") : [], [document]);
  const models = useMemo(() => document ? specRecords(document, "models") : [], [document]);
  const features = useMemo(() => document ? specRecords(document, "features") : [], [document]);
  const localMock = task.environment?.kind === "development" && upstreams.some((upstream) => loopbackURL(upstream.baseUrl));
  const sampleFeature = String(features.find((feature) => feature.id === "habit-assistant")?.id ?? features[0]?.id ?? "habit-assistant");

  async function stageConnection(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const authentication = String(data.get("authentication")) as "bearer" | "none";
    const secretName = String(data.get("secret_name"));
    const secretInput = form.elements.namedItem("secret_value");
    const secretValue = secretInput instanceof HTMLInputElement ? secretInput.value : "";
    data.delete("secret_value");
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    if (!task.canConfigure || !document || !task.environment) return;
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
        if (!task.canManageSecrets) throw new Error("Your session needs manage_secrets before it can verify or store provider-secret metadata.");
        if (secretAction === "create" && !secretValue) throw new Error("Enter the write-only provider credential.");
        const resolved = await resolveWriteOnlySecret({
          action: secretAction,
          environmentID: task.environment.id,
          name: secretName,
          ...(secretAction === "create" ? { value: secretValue } : {})
        });
        setSecretResolution(resolved);
        if (resolved.outcome === "confirmation_required") {
          task.setProblem(localTaskProblem(
            resolved.reason === "already_exists"
              ? `Secret ${secretName} already exists in this environment. Its value was not read or inferred. Explicitly choose “Use existing named secret” and review again, or rotate it from Secrets.`
              : `The create response for secret ${secretName} was indeterminate, but exact metadata now exists. Its value cannot be verified or inferred. Explicitly choose “Use existing named secret” and review again, or rotate it from Secrets.`,
            "Credential metadata requires confirmation"
          ));
          return;
        }
        setSecretCreated(resolved.metadata.name);
        if (resolved.outcome === "created") setSecretAction("use_existing");
      } else {
        setSecretResolution(undefined);
      }
      const staged = await task.stage(next, `Admin console add AI connection ${connectionID}`);
      if (staged) {
        setConnectionPublished(false);
        setLastConnection({ id: connectionID, model: modelID, selfTestSupported: ["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages"].includes(protocol) });
      }
    } catch (error) {
      const isInputProblem = error instanceof WriteOnlySecretResolutionError || (error instanceof Error && ["Enter", "Connection", "Derived", "Physical", "Upstream", "USD", "Choose", "Your"].some((prefix) => error.message.startsWith(prefix)));
      const local = isInputProblem ? localTaskProblem(error.message, "AI connection is incomplete") : undefined;
      task.setProblem(local && error instanceof WriteOnlySecretResolutionError
        ? { ...local, ...(error.operationId ? { operationId: error.operationId } : {}), retryable: error.code === "outcome_unknown" }
        : local ?? problemFromError(error));
    }
  }

  async function runSelfTest(): Promise<void> {
    if (!task.canRunSelfTests || !task.environment || !lastConnection || !task.source) return;
    task.setProblem(undefined);
    try {
      const result = (await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body: { config_revision_id: task.source.id, environment_id: task.environment.id, kind: "upstream", max_cost_nano_usd: 10_000_000, model: lastConnection.model, upstream: lastConnection.id } })).data;
      if (result.environment_id !== task.environment.id || result.config_revision_id !== task.source.id) throw new Error("The self-test result did not match the published configuration revision and environment.");
      setSelfTest(result);
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

  async function runAndVerifyDevelopmentSample(): Promise<void> {
    if (!task.mutationAllowed || !task.environment) return;
    setSampleBusy(true);
    setVerifiedRequest(undefined);
    task.setProblem(undefined);
    try {
      const sample = (await runDevelopmentSample()).data;
      const durable = (await adminRequest(`/admin/v1/requests/${sample.request_id}`, RequestSchema)).data;
      if (durable.id !== sample.request_id || durable.environment_id !== task.environment.id ||
        durable.feature !== sample.feature || durable.protocol !== sample.protocol ||
        durable.status !== sample.status || durable.selected_physical_model !== sample.model) {
        throw new Error("sample_mismatch");
      }
      setVerifiedRequest(durable);
    } catch (error) {
      task.setProblem(error instanceof Error && error.message === "sample_mismatch"
        ? localTaskProblem("The synthetic request completed, but its durable request record did not match the exact environment, feature, protocol, status, and physical model.", "Development sample verification failed")
        : problemFromError(error));
    } finally {
      setSampleBusy(false);
    }
  }

  return <div className="control-page task-workspace">
    <section className="page-heading"><div><p className="eyebrow">AI connections</p><h1>Connect a provider without exposing its credential.</h1><p>Add the endpoint, one physical model, trusted input-accounting bounds, and operator-reviewed pricing as one preserved configuration change.</p></div><button className="secondary-action" disabled={task.busy || task.configuration.isFetching} onClick={() => void task.configuration.refetch()} type="button">Refresh connections</button></section>
    <TaskScope application={task.application} environment={task.environment} purpose="AI connection change scope" />
    <ProblemNotice problem={task.problem ?? (task.configuration.error ? problemFromError(task.configuration.error) : undefined)} />
    <LoadingConfiguration pending={task.configuration.isPending} />
    {document ? <>
      <section className="task-card-list"><div className="detail-card__heading"><div><p className="eyebrow">Active revision {task.source?.version}</p><h2>Connections</h2></div><code>{task.sourceETag}</code></div>{upstreams.length ? upstreams.map((upstream) => { const related = models.filter((model) => model.upstream === upstream.id); return <article className="task-summary-card" key={String(upstream.id)}><div><strong>{String(upstream.id)}</strong><span className="state-badge state-badge--available"><span aria-hidden="true" className="state-badge__dot" />Configured</span></div><p>{String(upstream.type).replaceAll("_", " ")} · {String(upstream.baseUrl)}</p><dl><div><dt>Credential</dt><dd>{isJSONRecord(upstream.authentication) ? String(upstream.authentication.type) : "unknown"}</dd></div><div><dt>Models</dt><dd>{related.map((model) => String(model.id)).join(", ") || "None"}</dd></div></dl></article>; }) : <p>No AI connections are active.</p>}</section>
      {task.environment?.kind === "development" ? <section className={`development-path ${localMock ? "development-path--ready" : ""}`}><div><p className="eyebrow">Development-first path</p><h2>{localMock ? "Local mock connection is ready." : "Start the isolated local development stack."}</h2><p>{localMock ? "This Development revision points to a loopback mock upstream. Provider cost is deterministic and no live provider account is required." : "The Admin API cannot create a mock server. Start the gateway-owned fixture, then reopen its Console."}</p></div>{!localMock ? <pre>latchway develop --browser-origin {typeof window === "undefined" ? "http://localhost:5173" : window.location.origin}</pre> : <><ol><li>Run the gateway-owned synthetic development client.</li><li>Exercise mock identity, challenge-bound debug attestation, DPoP, policy, quota, routing, and settlement.</li><li>Read back the exact durable request before reporting success.</li></ol><p>This loopback-only helper is a development-path verification, not production attestation or physical-device proof.</p><div className="button-row"><button className="primary-action" disabled={sampleBusy || !task.mutationAllowed} onClick={() => void runAndVerifyDevelopmentSample()} type="button">{sampleBusy ? "Running development sample…" : "Run and verify development sample"}</button><button className="secondary-action" disabled={sampleBusy} onClick={() => void verifySample()} type="button">Check for another client request</button><Link className="secondary-action" search={(previous) => previous} to="/requests">Open request explorer</Link></div>{verifiedRequest ? <p className="resource-result">Observed <code>{verifiedRequest.id}</code>: <strong>{verifiedRequest.status}</strong> via {verifiedRequest.selected_physical_model ?? verifiedRequest.attempts.at(-1)?.model ?? "recorded model"}.</p> : null}</>}</section> : null}
      <form className="control-form task-builder" onSubmit={(event) => void stageConnection(event)}><div><p className="eyebrow">Add connection</p><h2>Endpoint, credential, model, and price</h2><p>A bearer value is sent once to the Secrets API and cleared before the request completes. The configuration references only its logical name.</p></div><fieldset><legend>1. Provider destination</legend><div className="form-field-grid"><label>Connection ID<input defaultValue="primary" name="connection_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Connection type<select name="provider_type" onChange={(event) => setConnectionType(event.target.value as "anthropic" | "openai_compatible")} value={connectionType}><option value="openai_compatible">OpenAI-compatible provider or gateway</option><option value="anthropic">Anthropic-compatible provider or gateway</option></select></label><label>Base URL<input defaultValue="https://api.openai.com/v1" name="base_url" required type="url" /></label></div><small>This guided flow accepts HTTPS only. The loopback fixture is gateway-owned and appears above when started with <code>latchway develop</code>.</small></fieldset><fieldset><legend>2. Server-held credential</legend><div className="form-field-grid"><label>Authentication<select name="authentication" onChange={(event) => setAuthenticationMode(event.target.value as "bearer" | "none")} value={authenticationMode}><option value="bearer">Bearer secret</option><option value="none">No authentication</option></select></label>{authenticationMode === "bearer" ? <label>Credential operation<select aria-label="Credential operation" name="secret_action" onChange={(event) => setSecretAction(event.target.value as WriteOnlySecretAction)} value={secretAction}><option value="create">Store new secret value</option><option value="use_existing">Use existing named secret</option></select></label> : null}<label>Secret name<input defaultValue="provider_api_key" disabled={authenticationMode === "none"} name="secret_name" pattern="[a-z][a-z0-9_-]{0,62}" /></label><label>Provider credential<input autoComplete="new-password" disabled={authenticationMode !== "bearer" || secretAction === "use_existing" || !task.canManageSecrets} name="secret_value" required={authenticationMode === "bearer" && secretAction === "create"} type="password" /></label></div><small>No-auth is appropriate only for a deliberately controlled destination. Existing-secret mode confirms only exact environment/name metadata and never reads or infers the value.</small>{authenticationMode === "bearer" && !task.canManageSecrets ? <p className="control-notice"><strong>Secret management required</strong><span>Your session needs <code>manage_secrets</code> to inspect exact existing metadata or store a new provider credential. Select no authentication only for a controlled destination.</span></p> : null}</fieldset><fieldset><legend>3. Model and protocol</legend><div className="form-field-grid"><label>Logical model ID<input defaultValue="assistant_default" name="model_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Physical provider model<input defaultValue="gpt-5-mini" name="physical_model" required /></label><label>Protocol<select defaultValue={connectionType === "anthropic" ? "anthropic_messages" : "openai_responses"} key={connectionType} name="protocol">{protocols.filter((protocol) => connectionType === "anthropic" ? protocol === "anthropic_messages" : protocol !== "anthropic_messages").map((protocol) => <option key={protocol} value={protocol}>{protocol.replaceAll("_", " ")}</option>)}</select></label><label>Maximum context tokens<input defaultValue={128000} min={1} name="maximum_context_tokens" type="number" /></label><label>Framing tokens / request<input defaultValue={8} min={0} name="framing_per_request" type="number" /></label><label>Framing tokens / message<input defaultValue={4} min={0} name="framing_per_message" type="number" /></label></div></fieldset><fieldset><legend>4. Operator-reviewed USD pricing</legend><div className="form-field-grid"><label>Input USD / 1M tokens<input defaultValue="0.25" inputMode="decimal" name="input_price" /></label><label>Output USD / 1M tokens<input defaultValue="2" inputMode="decimal" name="output_price" /></label><label>USD / request<input defaultValue="0" inputMode="decimal" name="request_price" /></label></div><small>Decimal USD is converted exactly to integer nano-USD. Latchway does not fetch provider prices.</small></fieldset><button className="primary-action" disabled={!task.canConfigure || task.busy || (authenticationMode === "bearer" && !task.canManageSecrets)} type="submit">Review connection change</button></form>
      {secretResolution?.outcome === "confirmation_required" ? <div className="control-notice"><strong>Credential metadata needs explicit confirmation</strong><span><code>secret/{secretResolution.metadata.name}</code> exists in this environment. The Console did not read or infer its value.</span><button className="secondary-action" onClick={() => setSecretAction("use_existing")} type="button">Use this existing named secret on next review</button></div> : null}
      {secretCreated ? <p className="control-notice"><strong>Credential stored</strong><span><code>secret/{secretCreated}</code> exists server-side and is not part of the draft document.</span></p> : null}
      <DraftReview busy={task.busy} canPublish={task.canConfigure} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={async () => { const revision = await task.publish(); if (revision) setConnectionPublished(true); return revision; }} title={lastConnection?.id ?? "connection change"} />
      {lastConnection && connectionPublished ? <section className="detail-card"><h2>Test the published connection</h2><p>The bounded self-test uses the selected upstream and model with a 10,000,000 nano-USD ceiling. Generative protocols exercise non-streaming and streaming; Embeddings sends one non-streaming request and records non-applicable checks as skipped. It does not impersonate an application user.</p>{lastConnection.selfTestSupported ? <button className="primary-action" disabled={!task.canRunSelfTests} onClick={() => void runSelfTest()} type="button">Run bounded connection test</button> : <p className="control-notice"><strong>Self-test unavailable for this protocol</strong><span>Connection self-tests support OpenAI Responses, Chat, Embeddings, and Anthropic Messages. Verify another protocol through a real client request.</span></p>}{selfTest ? <p className="resource-result">Self-test <code>{selfTest.id}</code>: <strong>{selfTest.state}</strong></p> : null}</section> : null}
    </> : null}
  </div>;
}

function ClientAccessWorkspace() {
  const task = useConfigurationTask("client-access");
  const [platform, setPlatform] = useState<ClientPlatform>("ios");
  const [webProvider, setWebProvider] = useState<WebVerificationProvider>("firebase_app_check");
  const [playCredentialSource, setPlayCredentialSource] = useState<"metadata" | "service_account">("metadata");
  const [playSecretAction, setPlaySecretAction] = useState<WriteOnlySecretAction>("create");
  const [turnstileSecretAction, setTurnstileSecretAction] = useState<WriteOnlySecretAction>("create");
  const [secretResolution, setSecretResolution] = useState<{ kind: "play_integrity" | "turnstile"; resolution: WriteOnlySecretResolution }>();
  const [addIdentity, setAddIdentity] = useState(false);
  const [selectedFeatureID, setSelectedFeatureID] = useState("");
  const [changeLabel, setChangeLabel] = useState("client access change");
  const [secretCreated, setSecretCreated] = useState<string>();
  const document = task.source?.document as JSONRecord | undefined;
  const identities = useMemo(() => document ? specRecords(document, "identityProviders") : [], [document]);
  const features = useMemo(() => document ? specRecords(document, "features") : [], [document]);
  const platformCards = useMemo(() => document ? clientPlatformReadiness(document) : [], [document]);
  const effectiveFeatureID = features.some((feature) => feature.id === selectedFeatureID) ? selectedFeatureID : String(features[0]?.id ?? "");
  const suggestedPolicyID = String(features.find((feature) => feature.id === effectiveFeatureID)?.attestationPolicy ?? `${platform}_clients`);
  const appleSurface = platform === "ios" || platform === "react_native_ios";
  const androidSurface = platform === "android" || platform === "react_native_android";
  const platformLabels: Record<ClientPlatform, string> = {
    android: "Android",
    ios: "iOS",
    react_native_android: "React Native Android",
    react_native_ios: "React Native iOS",
    web: "Web"
  };

  async function stageClient(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const submittedWebProvider = String(data.get("web_verification_provider") ?? "firebase_app_check") as WebVerificationProvider;
    const turnstileSecretInput = form.elements.namedItem("turnstile_secret_value");
    const turnstileSecretValue = turnstileSecretInput instanceof HTMLInputElement ? turnstileSecretInput.value : "";
    const playSecretInput = form.elements.namedItem("play_integrity_secret_value");
    const playSecretValue = playSecretInput instanceof HTMLInputElement ? playSecretInput.value : "";
    data.delete("turnstile_secret_value");
    data.delete("play_integrity_secret_value");
    if (turnstileSecretInput instanceof HTMLInputElement) turnstileSecretInput.value = "";
    if (playSecretInput instanceof HTMLInputElement) playSecretInput.value = "";
    if (!task.canConfigure || !document || !task.environment) return;
    try {
      const componentID = String(data.get("component_id"));
      const turnstileSecretName = String(data.get("turnstile_secret_name"));
      const playSecretName = String(data.get("play_integrity_secret_name"));
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
        playIntegrityCredential: playCredentialSource === "service_account"
          ? { type: "service_account", secretName: String(data.get("play_integrity_secret_name")) }
          : { type: "metadata" },
        turnstileExpectedAction: String(data.get("turnstile_expected_action")),
        turnstileSecretName,
        webVerificationProvider: submittedWebProvider,
        webOrigin: String(data.get("web_origin"))
      });
      const writeOnlySecret = platform === "web" && submittedWebProvider === "turnstile"
        ? { action: turnstileSecretAction, kind: "turnstile" as const, name: turnstileSecretName, value: turnstileSecretValue }
        : androidSurface && playCredentialSource === "service_account"
          ? { action: playSecretAction, kind: "play_integrity" as const, name: playSecretName, value: playSecretValue }
          : undefined;
      if (writeOnlySecret) {
        if (!task.canManageSecrets) {
          throw new Error("Your session needs manage_secrets before it can verify or store verification-secret metadata.");
        }
        if (writeOnlySecret.action === "create" && !writeOnlySecret.value) {
          throw new Error("Enter the new write-only verification credential.");
        }
        const resolved = await resolveWriteOnlySecret({
          action: writeOnlySecret.action,
          environmentID: task.environment.id,
          name: writeOnlySecret.name,
          ...(writeOnlySecret.action === "create" ? { value: writeOnlySecret.value } : {})
        });
        setSecretResolution({ kind: writeOnlySecret.kind, resolution: resolved });
        if (resolved.outcome === "confirmation_required") {
          task.setProblem(localTaskProblem(
            resolved.reason === "already_exists"
              ? `Secret ${writeOnlySecret.name} already exists in this environment. Its value was not read or inferred. Explicitly choose use-existing and review again, or rotate it from Secrets.`
              : `The create response for secret ${writeOnlySecret.name} was indeterminate, but exact metadata now exists. Its value cannot be verified or inferred. Explicitly choose use-existing and review again, or rotate it from Secrets.`,
            "Verification credential metadata requires confirmation"
          ));
          return;
        }
        setSecretCreated(resolved.metadata.name);
        if (resolved.outcome === "created") {
          if (writeOnlySecret.kind === "turnstile") setTurnstileSecretAction("use_existing");
          else setPlaySecretAction("use_existing");
        }
      } else {
        setSecretResolution(undefined);
      }
      const staged = await task.stage(next, `Admin console add ${platform} client access ${componentID}`);
      if (staged) setChangeLabel(componentID);
    } catch (error) {
      const isInputProblem = error instanceof WriteOnlySecretResolutionError || (error instanceof Error && ["Enter", "Your"].some((prefix) => error.message.startsWith(prefix)));
      const local = isInputProblem ? localTaskProblem(error.message, "Client access is incomplete") : undefined;
      task.setProblem(local && error instanceof WriteOnlySecretResolutionError
        ? { ...local, ...(error.operationId ? { operationId: error.operationId } : {}), retryable: error.code === "outcome_unknown" }
        : local ?? problemFromError(error));
    }
  }

  return <div className="control-page task-workspace">
    <section className="page-heading"><div><p className="eyebrow">Client access</p><h1>Trust an application surface.</h1><p>Connect user authentication, platform verification, a root component identity, and its feature grant without exposing the underlying schema.</p></div><button className="secondary-action" disabled={task.busy || task.configuration.isFetching} onClick={() => void task.configuration.refetch()} type="button">Refresh client access</button></section>
    <TaskScope application={task.application} environment={task.environment} purpose="Client access change scope" />
    <ProblemNotice problem={task.problem ?? (task.configuration.error ? problemFromError(task.configuration.error) : undefined)} />
    <LoadingConfiguration pending={task.configuration.isPending} />
    {document ? <>
      <section aria-labelledby="platform-readiness-heading" className="task-card-list">
        <div><p className="eyebrow">Active revision {task.source?.version}</p><h2 id="platform-readiness-heading">Platform readiness</h2><p>Each card follows an exact server platform. “Configuration ready” confirms only the active document structure: policy, root component, user authentication, and feature binding. It does not confirm environment status, secret usability, or physical-device/browser execution.</p></div>
        <div className="client-access-overview">
          {platformCards.map((card) => <article data-platform={card.key} key={card.key}>
            <div className="feature-card__heading"><strong>{card.label}</strong><span className={`state-badge ${card.ready ? "state-badge--available" : "state-badge--warning"}`}><span aria-hidden="true" className="state-badge__dot" />{card.ready ? "Configuration ready" : "Needs setup"}</span></div>
            <p><code>{card.key}</code></p>
            <p><strong>Configured</strong><br />{card.configured}</p>
            <p><strong>Still missing</strong><br />{card.missing.length ? card.missing.join("; ") : "No server-side prerequisite."}</p>
            <p><strong>Production requires</strong><br />{card.productionRequirement}</p>
            <p><strong>How to test</strong><br />{card.test}</p>
            <div className="button-row"><Link className="small-action" search={(previous) => ({ ...previous, platform: card.key })} to="/requests">Inspect requests</Link><a className="small-action" href={card.documentationURL} rel="noreferrer" target="_blank">Client documentation</a></div>
          </article>)}
        </div>
      </section>
      <form className="control-form task-builder" onSubmit={(event) => void stageClient(event)}>
        <div><p className="eyebrow">Add application surface</p><h2>Identity, proof, component, and feature grant</h2><p>Production defaults require real platform evidence. Debug signing remains confined to the isolated <code>latchway develop</code> fixture.</p></div>
        <fieldset><legend>1. Choose the exact client surface</legend><div className="segmented-control" role="group" aria-label="Client platform">{(["ios", "android", "web", "react_native_ios", "react_native_android"] as const).map((value) => <button aria-pressed={platform === value} className={platform === value ? "segmented-control__active" : ""} key={value} onClick={() => setPlatform(value)} type="button">{platformLabels[value]}</button>)}</div><p>React Native uses the schema-backed <code>react_native_ios</code> and <code>react_native_android</code> runtimes; it is not a separate generic server platform.</p><div className="form-field-grid"><label>Component ID<input defaultValue={`${platform}_main`} key={`component-${platform}`} name="component_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Verification policy ID<input defaultValue={suggestedPolicyID} key={`policy-${platform}-${effectiveFeatureID}-${suggestedPolicyID}`} name="policy_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Allowed feature<select name="feature_id" onChange={(event) => setSelectedFeatureID(event.target.value)} required value={effectiveFeatureID}><option value="">Choose a feature</option>{features.map((feature) => <option key={String(feature.id)} value={String(feature.id)}>{String(feature.id)}</option>)}</select></label></div></fieldset>
        <fieldset><legend>2. User authentication</legend><label className="check-row"><input checked={addIdentity} onChange={(event) => setAddIdentity(event.target.checked)} type="checkbox" />Add a Firebase authentication provider with this change</label>{addIdentity ? <div className="form-field-grid"><label>Provider ID<input defaultValue="firebase" name="identity_provider_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Firebase project ID<input name="firebase_project_id" required /></label></div> : <p>{identities.length ? `Existing providers remain available: ${identities.map((identity) => String(identity.id)).join(", ")}.` : "No provider exists yet. Add Firebase authentication or configure an advanced OIDC provider."}</p>}</fieldset>
        {appleSurface ? <fieldset><legend>3. Apple App Attest · {platformLabels[platform]}</legend><div className="form-field-grid"><label>App ID prefix<input name="app_id_prefix" pattern="[A-Z0-9]{1,64}" required /></label><label>Bundle identifier<input maxLength={255} minLength={3} name="apple_bundle_id" required /></label><label>CFBundleVersion<input maxLength={128} name="apple_bundle_version" required /></label><label>Distribution<select defaultValue={task.environment?.kind === "development" ? "3" : "4"} name="apple_validation_category"><option value="3">Development signing</option><option value="2">TestFlight</option><option value="4">App Store</option><option value="5">Ad hoc / enterprise</option></select></label></div></fieldset> : androidSurface ? <fieldset><legend>3. Google Play Integrity · {platformLabels[platform]}</legend><p>Use metadata only when Latchway itself runs with an attached Google Cloud service identity. Docker Compose and other hosts require the service-account JSON option.</p><div className="form-field-grid"><label>Package name<input maxLength={255} minLength={3} name="android_package_name" required /></label><label>Cloud project number<input min={100000} name="android_cloud_project" required type="number" /></label><label>Signing certificate SHA-256 (base64url)<input name="android_certificate_digest" pattern="[A-Za-z0-9_-]{43}=?" required /></label><label>Exact version code<input min={1} name="android_version_code" required type="number" /></label><label>Server credential source<select name="play_integrity_credential_source" onChange={(event) => setPlayCredentialSource(event.target.value as "metadata" | "service_account")} value={playCredentialSource}><option value="metadata">Attached Google Cloud service identity</option><option value="service_account">Write-only service-account JSON secret</option></select></label>{playCredentialSource === "service_account" ? <><label>Credential operation<select aria-label="Play Integrity credential operation" name="play_integrity_secret_action" onChange={(event) => setPlaySecretAction(event.target.value as WriteOnlySecretAction)} value={playSecretAction}><option value="create">Store new service-account JSON</option><option value="use_existing">Use existing named secret</option></select></label><label>Play credential secret name<input defaultValue="play_integrity_service_account" name="play_integrity_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>New service-account JSON (write-only)<input autoComplete="new-password" disabled={playSecretAction === "use_existing" || !task.canManageSecrets} name="play_integrity_secret_value" required={playSecretAction === "create"} type="password" /></label></> : null}</div>{playCredentialSource === "service_account" ? <small>Existing-secret mode confirms exact metadata in this environment and never reads or infers the service-account JSON. A successful create switches to use-existing before any draft request.</small> : null}{playCredentialSource === "service_account" && playSecretAction === "create" && !task.canManageSecrets ? <p className="control-notice"><strong>Secret management required</strong><span>Your session cannot store a new Play Integrity credential. Choose use-existing to verify an exact named secret, or use an administrator with <code>manage_secrets</code>.</span></p> : null}</fieldset> : <fieldset><legend>3. Browser protection</legend><div className="form-field-grid"><label>Protection provider<select name="web_verification_provider" onChange={(event) => setWebProvider(event.target.value as WebVerificationProvider)} value={webProvider}><option value="firebase_app_check">Firebase App Check</option><option value="turnstile">Cloudflare Turnstile</option></select></label><label>Exact customer web-app origin<input name="web_origin" placeholder="https://app.example.com" required type="url" /></label></div>{webProvider === "firebase_app_check" ? <div className="form-field-grid"><label>Firebase project number<input inputMode="numeric" pattern="[1-9][0-9]{0,19}" name="firebase_project_number" required /></label><label>Firebase web app ID<input maxLength={256} minLength={5} name="firebase_app_id" required /></label></div> : <><div className="form-field-grid"><label>Expected widget action<input defaultValue="latchway_session" name="turnstile_expected_action" pattern="[A-Za-z0-9_-]{1,32}" required /></label><label>Credential operation<select aria-label="Turnstile credential operation" name="turnstile_secret_action" onChange={(event) => setTurnstileSecretAction(event.target.value as WriteOnlySecretAction)} value={turnstileSecretAction}><option value="create">Store new Turnstile secret</option><option value="use_existing">Use existing named secret</option></select></label><label>Secret name<input defaultValue="turnstile_secret" name="turnstile_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>New Turnstile secret (write-only)<input autoComplete="new-password" disabled={turnstileSecretAction === "use_existing" || !task.canManageSecrets} name="turnstile_secret_value" required={turnstileSecretAction === "create"} type="password" /></label></div><small>The hostname is derived from the exact origin. Existing-secret mode confirms exact metadata in this environment and never reads or infers the value. A successful create switches to use-existing before any draft request. The public site key stays in your web application.</small>{turnstileSecretAction === "create" && !task.canManageSecrets ? <p className="control-notice"><strong>Secret management required</strong><span>Your session cannot store a new Turnstile credential. Choose use-existing to verify an exact named secret, or use an administrator with <code>manage_secrets</code>.</span></p> : null}</>}</fieldset>}
        <button className="primary-action" disabled={!task.canConfigure || task.busy || features.length === 0 || (platform === "web" && webProvider === "turnstile" && !task.canManageSecrets) || (androidSurface && playCredentialSource === "service_account" && !task.canManageSecrets)} type="submit">Review client-access change</button>
      </form>
      {secretResolution?.resolution.outcome === "confirmation_required" ? <div className="control-notice"><strong>Verification credential metadata needs explicit confirmation</strong><span><code>secret/{secretResolution.resolution.metadata.name}</code> exists in this environment. The Console did not read or infer its value.{secretResolution.resolution.operationId ? ` Preserve operation ${secretResolution.resolution.operationId} for audit correlation.` : ""}</span><button className="secondary-action" onClick={() => { if (secretResolution.kind === "turnstile") setTurnstileSecretAction("use_existing"); else setPlaySecretAction("use_existing"); }} type="button">Use this existing named verification secret on next review</button></div> : null}
      {secretCreated ? <p className="control-notice"><strong>Verification secret stored</strong><span><code>secret/{secretCreated}</code> exists server-side; its value was cleared from the form and is absent from the configuration draft.</span></p> : null}
      <DraftReview busy={task.busy} canPublish={task.canConfigure} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={task.publish} title={changeLabel} />
    </> : null}
  </div>;
}

function UsagePlanWorkspace() {
  const task = useConfigurationTask("usage-plans");
  const [changeLabel, setChangeLabel] = useState("usage plan");
  const document = task.source?.document as JSONRecord | undefined;
  const plans = useMemo(() => document ? specRecords(document, "limitPlans") : [], [document]);

  async function stagePlan(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!task.canConfigure || !document) return;
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

  return <div className="control-page task-workspace"><section className="page-heading"><div><p className="eyebrow">Usage plans</p><h1>Set limits in operator language.</h1><p>Group enforceable volume, cost, per-request, and concurrency limits into a plan. Advanced units remain available in the full configuration editor.</p></div><button className="secondary-action" disabled={task.busy || task.configuration.isFetching} onClick={() => void task.configuration.refetch()} type="button">Refresh plans</button></section><TaskScope application={task.application} environment={task.environment} purpose="Usage-plan change scope" /><ProblemNotice problem={task.problem ?? (task.configuration.error ? problemFromError(task.configuration.error) : undefined)} /><LoadingConfiguration pending={task.configuration.isPending} />{document ? <><section className="task-card-list"><div className="detail-card__heading"><div><p className="eyebrow">Active revision {task.source?.version}</p><h2>Configured plans</h2></div><code>{task.sourceETag}</code></div>{plans.length ? plans.map((plan) => <article className="task-summary-card" key={String(plan.id)}><div><strong>{String(plan.id)}</strong><span>{Array.isArray(plan.limits) ? `${plan.limits.length} limit(s)` : "Invalid limits"}</span></div>{Array.isArray(plan.limits) ? <ul>{plan.limits.filter(isJSONRecord).map((limit, index) => <li key={`${String(limit.metric)}-${String(limit.algorithm)}-${index}`}>{describeLimit(limit)}</li>)}</ul> : null}</article>) : <p>No usage plans are active.</p>}</section><form className="control-form task-builder" onSubmit={(event) => void stagePlan(event)}><div><p className="eyebrow">New usage plan</p><h2>Choose only the limits this plan needs.</h2><p>Leave a numeric field at zero to omit that rule. Every generated rule is hard, server-owned, and grouped by the selected scope.</p></div><fieldset><legend>1. Plan identity and audience</legend><div className="form-field-grid"><label>Plan ID<input defaultValue="starter" name="plan_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Group usage by<select defaultValue="user_feature" name="scope"><option value="user_feature">User + feature</option><option value="user">User across features</option><option value="environment_feature">Environment + feature</option></select></label><label>Calendar timezone<input defaultValue="UTC" name="timezone" /></label></div></fieldset><fieldset><legend>2. Daily volume and cost</legend><div className="form-field-grid"><label>Requests / day<input defaultValue={100} min={0} name="daily_requests" type="number" /></label><label>Input tokens / day<input defaultValue={100000} min={0} name="daily_input_tokens" type="number" /></label><label>Output tokens / day<input defaultValue={100000} min={0} name="daily_output_tokens" type="number" /></label><label>Total tokens / day<input defaultValue={200000} min={0} name="daily_total_tokens" type="number" /></label><label>Cost USD / day<input defaultValue="1" inputMode="decimal" name="daily_cost_usd" /></label></div></fieldset><fieldset><legend>3. Per-request and simultaneous work</legend><div className="form-field-grid"><label>Input tokens / request<input defaultValue={20000} min={0} name="per_request_input_tokens" type="number" /></label><label>Output tokens / request<input defaultValue={2000} min={0} name="per_request_output_tokens" type="number" /></label><label>Concurrent requests<input defaultValue={4} min={0} name="concurrent_requests" type="number" /></label></div></fieldset><button className="primary-action" disabled={!task.canConfigure || task.busy} type="submit">Review usage-plan change</button></form><p className="control-notice"><strong>Effective-limit inspection</strong><span>Resolve the current hard limits and their source for a specific pseudonymous user in the Users inspector.</span><Link to="/users">Inspect resolved limits in Users</Link></p><DraftReview busy={task.busy} canPublish={task.canConfigure} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={task.publish} title={changeLabel} /></> : null}</div>;
}

function useTaskWorkspaceKey(): string {
  const workspace = useOptionalWorkspace();
  return `${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? "none"}`;
}

export function ConnectionWorkspacePage() { const key = useTaskWorkspaceKey(); return <EnvironmentRequired><ConnectionWorkspace key={key} /></EnvironmentRequired>; }
export function ClientAccessWorkspacePage() { const key = useTaskWorkspaceKey(); return <EnvironmentRequired><ClientAccessWorkspace key={key} /></EnvironmentRequired>; }
export function UsagePlanWorkspacePage() { const key = useTaskWorkspaceKey(); return <EnvironmentRequired><UsagePlanWorkspace key={key} /></EnvironmentRequired>; }

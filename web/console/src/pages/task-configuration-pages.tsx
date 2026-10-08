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
import { problemFromError } from "../api/auth";
import { Badge, Button, buttonClass, Notice, Segmented } from "../ui";
import { type JSONRecord } from "./configuration-slice";
import { localTaskProblem, useConfigurationTask } from "./configuration-task";
import { ApplePolicyFields, PlayTestingField } from "./attestation-policy-fields";
import { applePolicyFromForm } from "./attestation-policy-input";
import {
  buildClientAccessDocument,
  buildConnectionDocument,
  clientPlatformReadiness,
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

const protocols: TaskProtocol[] = ["openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages"];

function integer(form: FormData, name: string): number {
  const value = Number(form.get(name));
  if (!Number.isSafeInteger(value)) throw new Error(`${name.replaceAll("_", " ")} must be a safe integer.`);
  return value;
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
  const target = production ? "Production" : environmentName;
  return <section aria-labelledby="task-publish-heading" className="lw-card">
    <header className="lw-card__head">
      <div><p className="lw-kicker">Draft revision {draft.revision.version}</p><h2 className="lw-card__title" id="task-publish-heading">Publish {title} to {target}?</h2></div>
      <Badge color={draft.report.valid ? "success" : "danger"} dot>{draft.report.valid ? "Valid" : "Needs changes"}</Badge>
    </header>
    <div className="lw-card__body lw-stack">
      <dl className="lw-effective__facts">
        <div><dt>{draft.report.valid ? "Configuration valid" : "Configuration needs changes"}</dt><dd>{draft.report.issues.length ? `${draft.report.issues.length} server issue(s)` : "All references resolve"}</dd></div>
        <div><dt>{draft.plan?.changes.length ?? 0} planned change(s)</dt><dd>{draft.plan?.warnings.length ? `${draft.plan.warnings.length} warning(s)` : "No structural warnings"}</dd></div>
        <div><dt>{production ? "Production traffic" : "Non-production traffic"}</dt><dd>Publishing is atomic; rollback creates a new revision</dd></div>
      </dl>
      {draft.report.issues.length ? <ul className="lw-issue-items">{draft.report.issues.map((issue, index) => <li key={`${issue.path}-${issue.code}-${index}`}><strong>{issue.severity}: {issue.code}</strong> <code className="lw-code-inline">{issue.path}</code> — {issue.message}</li>)}</ul> : null}
      {draft.plan?.changes.length ? <ul className="lw-issue-items">{draft.plan.changes.map((change, index) => <li key={`${change.path}-${index}`}><strong>{change.operation}</strong> <code className="lw-code-inline">{change.path}</code>{change.summary ? ` — ${change.summary}` : ""}</li>)}</ul> : null}
      <p className="lw-note lw-secondary">The Admin API currently retains server drafts for audit and exposes no abandon/delete mutation. Keeping it unpublished is safe; use Configuration revisions to inspect it.</p>
    </div>
    <div className="lw-card__foot lw-row lw-row--wrap">
      <Button disabled={busy} onClick={clear} size="sm">Keep server draft unpublished</Button>
      <Button disabled={busy || !canPublish || !draft.report.valid} onClick={() => void publish()} size="sm" variant="primary">Publish to {target}</Button>
    </div>
  </section>;
}

function loopbackURL(value: unknown): boolean {
  try {
    const parsed = new URL(String(value));
    return parsed.protocol === "http:" && new Set(["localhost", "127.0.0.1", "[::1]"]).has(parsed.hostname);
  } catch {
    return false;
  }
}

export type ConfigurationTask = ReturnType<typeof useConfigurationTask>;

/** The guided Add Connection flow: endpoint, write-only credential, model and price, saved into the working draft. */
export function ConnectionSetup({ task }: { task: ConfigurationTask }) {
  const [connectionType, setConnectionType] = useState<"anthropic" | "openai_compatible">("openai_compatible");
  const [authenticationMode, setAuthenticationMode] = useState<"bearer" | "none">("bearer");
  const [secretAction, setSecretAction] = useState<WriteOnlySecretAction>("create");
  const [secretResolution, setSecretResolution] = useState<WriteOnlySecretResolution>();
  const [lastConnection, setLastConnection] = useState<{ id: string; model: string; selfTestSupported: boolean }>();
  const [connectionPublished, setConnectionPublished] = useState(false);
  const [secretCreated, setSecretCreated] = useState<string>();
  const [selfTest, setSelfTest] = useState<SelfTestRun>();
  const document = task.source?.document as JSONRecord | undefined;

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
    if (!task.canRunSelfTests || !task.environment || !lastConnection || !task.active) return;
    task.setProblem(undefined);
    try {
      const result = (await adminRequest("/admin/v1/self-tests", SelfTestSchema, { method: "POST", body: { config_revision_id: task.active.id, environment_id: task.environment.id, kind: "upstream", max_cost_nano_usd: 10_000_000, model: lastConnection.model, upstream: lastConnection.id } })).data;
      if (result.environment_id !== task.environment.id || result.config_revision_id !== task.active.id) throw new Error("The self-test result did not match the published configuration revision and environment.");
      setSelfTest(result);
    } catch (error) { task.setProblem(problemFromError(error)); }
  }

  return <div className="lw-stack">
    {document ? <>
      <form className="lw-form lw-panel" onSubmit={(event) => void stageConnection(event)}><div><p className="lw-kicker">Add connection</p><h2 className="lw-section-title">Endpoint, credential, model, and price</h2><p>A bearer value is sent once to the Secrets API and cleared before the request completes. The configuration references only its logical name.</p></div><fieldset><legend>1. Provider destination</legend><div className="lw-form-grid"><label>Connection ID<input defaultValue="primary" name="connection_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Connection type<select name="provider_type" onChange={(event) => setConnectionType(event.target.value as "anthropic" | "openai_compatible")} value={connectionType}><option value="openai_compatible">OpenAI-compatible provider or gateway</option><option value="anthropic">Anthropic-compatible provider or gateway</option></select></label><label>Base URL<input defaultValue="https://api.openai.com/v1" name="base_url" required type="url" /></label></div><small>This guided flow accepts HTTPS only. The loopback fixture is gateway-owned and appears above when started with <code>latchway develop</code>.</small></fieldset><fieldset><legend>2. Server-held credential</legend><div className="lw-form-grid"><label>Authentication<select name="authentication" onChange={(event) => setAuthenticationMode(event.target.value as "bearer" | "none")} value={authenticationMode}><option value="bearer">Bearer secret</option><option value="none">No authentication</option></select></label>{authenticationMode === "bearer" ? <label>Credential operation<select aria-label="Credential operation" name="secret_action" onChange={(event) => setSecretAction(event.target.value as WriteOnlySecretAction)} value={secretAction}><option value="create">Store new secret value</option><option value="use_existing">Use existing named secret</option></select></label> : null}<label>Secret name<input defaultValue="provider_api_key" disabled={authenticationMode === "none"} name="secret_name" pattern="[a-z][a-z0-9_-]{0,62}" /></label><label>Provider credential<input autoComplete="new-password" disabled={authenticationMode !== "bearer" || secretAction === "use_existing" || !task.canManageSecrets} name="secret_value" required={authenticationMode === "bearer" && secretAction === "create"} type="password" /></label></div><small>No-auth is appropriate only for a deliberately controlled destination. Existing-secret mode confirms only exact environment/name metadata and never reads or infers the value.</small>{authenticationMode === "bearer" && !task.canManageSecrets ? <Notice title="Secret management required" tone="warning">Your session needs <code>manage_secrets</code> to inspect exact existing metadata or store a new provider credential. Select no authentication only for a controlled destination.</Notice> : null}</fieldset><fieldset><legend>3. Model and protocol</legend><div className="lw-form-grid"><label>Logical model ID<input defaultValue="assistant_default" name="model_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Physical provider model<input defaultValue="gpt-5-mini" name="physical_model" required /></label><label>Protocol<select defaultValue={connectionType === "anthropic" ? "anthropic_messages" : "openai_responses"} key={connectionType} name="protocol">{protocols.filter((protocol) => connectionType === "anthropic" ? protocol === "anthropic_messages" : protocol !== "anthropic_messages").map((protocol) => <option key={protocol} value={protocol}>{protocol.replaceAll("_", " ")}</option>)}</select></label><label>Maximum context tokens<input defaultValue={128000} min={1} name="maximum_context_tokens" type="number" /></label><label>Framing tokens / request<input defaultValue={8} min={0} name="framing_per_request" type="number" /></label><label>Framing tokens / message<input defaultValue={4} min={0} name="framing_per_message" type="number" /></label></div></fieldset><fieldset><legend>4. Operator-reviewed USD pricing</legend><div className="lw-form-grid"><label>Input USD / 1M tokens<input defaultValue="0.25" inputMode="decimal" name="input_price" /></label><label>Output USD / 1M tokens<input defaultValue="2" inputMode="decimal" name="output_price" /></label><label>USD / request<input defaultValue="0" inputMode="decimal" name="request_price" /></label></div><small>Decimal USD is converted exactly to integer nano-USD. Latchway does not fetch provider prices.</small></fieldset><button className={buttonClass({ variant: "primary" })} disabled={!task.canConfigure || task.busy || (authenticationMode === "bearer" && !task.canManageSecrets)} type="submit">Review connection change</button></form>
      {secretResolution?.outcome === "confirmation_required" ? <Notice action={<button className={buttonClass()} onClick={() => setSecretAction("use_existing")} type="button">Use this existing named secret on next review</button>} title="Credential metadata needs explicit confirmation" tone="warning"><code>secret/{secretResolution.metadata.name}</code> exists in this environment. The Console did not read or infer its value.</Notice> : null}
      {secretCreated ? <Notice title="Credential stored" tone="success"><code>secret/{secretCreated}</code> exists server-side and is not part of the draft document.</Notice> : null}
      <DraftReview busy={task.busy} canPublish={task.canConfigure} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={async () => { const revision = await task.publish(); if (revision) setConnectionPublished(true); return revision; }} title={lastConnection?.id ?? "connection change"} />
      {lastConnection && connectionPublished ? <section className="lw-panel lw-stack"><h2 className="lw-section-title">Test the published connection</h2><p>The bounded self-test uses the selected upstream and model with a 10,000,000 nano-USD ceiling. Generative protocols exercise non-streaming and streaming; Embeddings sends one non-streaming request and records non-applicable checks as skipped. It does not impersonate an application user.</p>{lastConnection.selfTestSupported ? <button className={buttonClass({ variant: "primary" })} disabled={!task.canRunSelfTests} onClick={() => void runSelfTest()} type="button">Run bounded connection test</button> : <Notice title="Self-test unavailable for this protocol" tone="info">Connection self-tests support OpenAI Responses, Chat, Embeddings, and Anthropic Messages. Verify another protocol through a real client request.</Notice>}{selfTest ? <p className="lw-note">Self-test <code>{selfTest.id}</code>: <strong>{selfTest.state}</strong></p> : null}</section> : null}
    </> : null}
  </div>;
}

/** Development environments can run the gateway-owned synthetic client and read back its exact durable request. */
export function DevelopmentPath({ task }: { task: ConfigurationTask }) {
  const [verifiedRequest, setVerifiedRequest] = useState<LogicalRequest>();
  const [sampleBusy, setSampleBusy] = useState(false);
  const document = task.source?.document as JSONRecord | undefined;
  const upstreams = useMemo(() => document ? specRecords(document, "upstreams") : [], [document]);
  const features = useMemo(() => document ? specRecords(document, "features") : [], [document]);
  const localMock = task.environment?.kind === "development" && upstreams.some((upstream) => loopbackURL(upstream.baseUrl));
  const sampleFeature = String(features.find((feature) => feature.id === "habit-assistant")?.id ?? features[0]?.id ?? "habit-assistant");

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

  return <>{task.environment?.kind === "development" ? <section className="lw-panel lw-stack"><div><p className="lw-kicker">Development-first path</p><h2 className="lw-section-title">{localMock ? "Local mock connection is ready." : "Start the isolated local development stack."}</h2><p>{localMock ? "This Development revision points to a loopback mock upstream. Provider cost is deterministic and no live provider account is required." : "The Admin API cannot create a mock server. Start the gateway-owned fixture, then reopen its Console."}</p></div>{!localMock ? <pre className="lw-code-block">latchway develop --browser-origin {typeof window === "undefined" ? "http://localhost:5173" : window.location.origin}</pre> : <><ol className="lw-issue-items"><li>Run the gateway-owned synthetic development client.</li><li>Exercise mock identity, challenge-bound debug attestation, DPoP, policy, quota, routing, and settlement.</li><li>Read back the exact durable request before reporting success.</li></ol><p>This loopback-only helper is a development-path verification, not production attestation or physical-device proof.</p><div className="lw-row lw-row--wrap"><button className={buttonClass({ variant: "primary" })} disabled={sampleBusy || !task.mutationAllowed} onClick={() => void runAndVerifyDevelopmentSample()} type="button">{sampleBusy ? "Running development sample…" : "Run and verify development sample"}</button><button className={buttonClass()} disabled={sampleBusy} onClick={() => void verifySample()} type="button">Check for another client request</button><Link className={buttonClass()} search={(previous) => previous} to="/requests">Open request explorer</Link></div>{verifiedRequest ? <p className="lw-note">Observed <code>{verifiedRequest.id}</code>: <strong>{verifiedRequest.status}</strong> via {verifiedRequest.selected_physical_model ?? verifiedRequest.attempts.at(-1)?.model ?? "recorded model"}.</p> : null}</>}</section> : null}</>;
}

/** The guided Add Platform flow: identity, platform proof, root component and feature grant, saved into the working draft. */
export function ClientAccessSetup({ task }: { task: ConfigurationTask }) {
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
        ...(appleSurface ? applePolicyFromForm(data) : {}),
        allowPlayTestingResponses: data.get("allow_play_testing_responses") === "on",
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

  return <div className="lw-stack">
    {document ? <>
      <form className="lw-form lw-panel" onSubmit={(event) => void stageClient(event)}>
        <div><p className="lw-kicker">Add application surface</p><h2 className="lw-section-title">Identity, proof, component, and feature grant</h2><p>Production defaults require real platform evidence. Debug signing remains confined to the isolated <code>latchway develop</code> fixture.</p></div>
        <fieldset><legend>1. Choose the exact client surface</legend><Segmented items={(["ios", "android", "web", "react_native_ios", "react_native_android"] as const).map((value) => ({ id: value, label: platformLabels[value] }))} label="Client platform" onChange={setPlatform} value={platform} /><p>React Native uses the schema-backed <code>react_native_ios</code> and <code>react_native_android</code> runtimes; it is not a separate generic server platform.</p><div className="lw-form-grid"><label>Component ID<input defaultValue={`${platform}_main`} key={`component-${platform}`} name="component_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Verification policy ID<input defaultValue={suggestedPolicyID} key={`policy-${platform}-${effectiveFeatureID}-${suggestedPolicyID}`} name="policy_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Allowed feature<select name="feature_id" onChange={(event) => setSelectedFeatureID(event.target.value)} required value={effectiveFeatureID}><option value="">Choose a feature</option>{features.map((feature) => <option key={String(feature.id)} value={String(feature.id)}>{String(feature.id)}</option>)}</select></label></div></fieldset>
        <fieldset><legend>2. User authentication</legend><label className="lw-check"><input checked={addIdentity} onChange={(event) => setAddIdentity(event.target.checked)} type="checkbox" />Add a Firebase authentication provider with this change</label>{addIdentity ? <div className="lw-form-grid"><label>Provider ID<input defaultValue="firebase" name="identity_provider_id" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>Firebase project ID<input name="firebase_project_id" required /></label></div> : <p>{identities.length ? `Existing providers remain available: ${identities.map((identity) => String(identity.id)).join(", ")}.` : "No provider exists yet. Add Firebase authentication or configure an advanced OIDC provider."}</p>}</fieldset>
        {appleSurface ? <fieldset><legend>3. Apple App Attest · {platformLabels[platform]}</legend><div className="lw-form-grid"><label>App ID prefix<input name="app_id_prefix" pattern="[A-Z0-9]{1,64}" required /></label><label>Bundle identifier<input maxLength={255} minLength={3} name="apple_bundle_id" required /></label><label>CFBundleVersion<input maxLength={128} name="apple_bundle_version" required /></label><ApplePolicyFields environmentKind={task.environment?.kind ?? "production"} /></div></fieldset> : androidSurface ? <fieldset><legend>3. Google Play Integrity · {platformLabels[platform]}</legend><PlayTestingField environmentKind={task.environment?.kind ?? "production"} /><p>Use metadata only when Latchway itself runs with an attached Google Cloud service identity. Docker Compose and other hosts require the service-account JSON option.</p><div className="lw-form-grid"><label>Package name<input maxLength={255} minLength={3} name="android_package_name" required /></label><label>Cloud project number<input min={100000} name="android_cloud_project" required type="number" /></label><label>Signing certificate SHA-256 (base64url)<input name="android_certificate_digest" pattern="[A-Za-z0-9_-]{43}=?" required /></label><label>Exact version code<input min={1} name="android_version_code" required type="number" /></label><label>Server credential source<select name="play_integrity_credential_source" onChange={(event) => setPlayCredentialSource(event.target.value as "metadata" | "service_account")} value={playCredentialSource}><option value="metadata">Attached Google Cloud service identity</option><option value="service_account">Write-only service-account JSON secret</option></select></label>{playCredentialSource === "service_account" ? <><label>Credential operation<select aria-label="Play Integrity credential operation" name="play_integrity_secret_action" onChange={(event) => setPlaySecretAction(event.target.value as WriteOnlySecretAction)} value={playSecretAction}><option value="create">Store new service-account JSON</option><option value="use_existing">Use existing named secret</option></select></label><label>Play credential secret name<input defaultValue="play_integrity_service_account" name="play_integrity_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>New service-account JSON (write-only)<input autoComplete="new-password" disabled={playSecretAction === "use_existing" || !task.canManageSecrets} name="play_integrity_secret_value" required={playSecretAction === "create"} type="password" /></label></> : null}</div>{playCredentialSource === "service_account" ? <small>Existing-secret mode confirms exact metadata in this environment and never reads or infers the service-account JSON. A successful create switches to use-existing before any draft request.</small> : null}{playCredentialSource === "service_account" && playSecretAction === "create" && !task.canManageSecrets ? <Notice title="Secret management required" tone="warning">Your session cannot store a new Play Integrity credential. Choose use-existing to verify an exact named secret, or use an administrator with <code>manage_secrets</code>.</Notice> : null}</fieldset> : <fieldset><legend>3. Browser protection</legend><div className="lw-form-grid"><label>Protection provider<select name="web_verification_provider" onChange={(event) => setWebProvider(event.target.value as WebVerificationProvider)} value={webProvider}><option value="firebase_app_check">Firebase App Check</option><option value="turnstile">Cloudflare Turnstile</option></select></label><label>Exact customer web-app origin<input name="web_origin" placeholder="https://app.example.com" required type="url" /></label></div>{webProvider === "firebase_app_check" ? <div className="lw-form-grid"><label>Firebase project number<input inputMode="numeric" pattern="[1-9][0-9]{0,19}" name="firebase_project_number" required /></label><label>Firebase web app ID<input maxLength={256} minLength={5} name="firebase_app_id" required /></label></div> : <><div className="lw-form-grid"><label>Expected widget action<input defaultValue="latchway_session" name="turnstile_expected_action" pattern="[A-Za-z0-9_-]{1,32}" required /></label><label>Credential operation<select aria-label="Turnstile credential operation" name="turnstile_secret_action" onChange={(event) => setTurnstileSecretAction(event.target.value as WriteOnlySecretAction)} value={turnstileSecretAction}><option value="create">Store new Turnstile secret</option><option value="use_existing">Use existing named secret</option></select></label><label>Secret name<input defaultValue="turnstile_secret" name="turnstile_secret_name" pattern="[a-z][a-z0-9_-]{0,62}" required /></label><label>New Turnstile secret (write-only)<input autoComplete="new-password" disabled={turnstileSecretAction === "use_existing" || !task.canManageSecrets} name="turnstile_secret_value" required={turnstileSecretAction === "create"} type="password" /></label></div><small>The hostname is derived from the exact origin. Existing-secret mode confirms exact metadata in this environment and never reads or infers the value. A successful create switches to use-existing before any draft request. The public site key stays in your web application.</small>{turnstileSecretAction === "create" && !task.canManageSecrets ? <Notice title="Secret management required" tone="warning">Your session cannot store a new Turnstile credential. Choose use-existing to verify an exact named secret, or use an administrator with <code>manage_secrets</code>.</Notice> : null}</>}</fieldset>}
        <button className={buttonClass({ variant: "primary" })} disabled={!task.canConfigure || task.busy || features.length === 0 || (platform === "web" && webProvider === "turnstile" && !task.canManageSecrets) || (androidSurface && playCredentialSource === "service_account" && !task.canManageSecrets)} type="submit">Review client-access change</button>
      </form>
      {secretResolution?.resolution.outcome === "confirmation_required" ? <Notice action={<button className={buttonClass()} onClick={() => { if (secretResolution.kind === "turnstile") setTurnstileSecretAction("use_existing"); else setPlaySecretAction("use_existing"); }} type="button">Use this existing named verification secret on next review</button>} title="Verification credential metadata needs explicit confirmation" tone="warning"><code>secret/{secretResolution.resolution.metadata.name}</code> exists in this environment. The Console did not read or infer its value.{secretResolution.resolution.operationId ? ` Preserve operation ${secretResolution.resolution.operationId} for audit correlation.` : ""}</Notice> : null}
      {secretCreated ? <Notice title="Verification secret stored" tone="success"><code>secret/{secretCreated}</code> exists server-side; its value was cleared from the form and is absent from the configuration draft.</Notice> : null}
      <DraftReview busy={task.busy} canPublish={task.canConfigure} clear={() => task.setDraft(undefined)} draft={task.activeDraft} environmentName={task.environment?.display_name} production={task.environment?.kind === "production"} publish={task.publish} title={changeLabel} />
    </> : null}
  </div>;
}

/** What each client platform has configured and still needs, read from the working configuration. */
export function PlatformReadiness({ task }: { task: ConfigurationTask }) {
  const document = task.source?.document as JSONRecord | undefined;
  const platformCards = useMemo(() => document ? clientPlatformReadiness(document) : [], [document]);
  if (!document) return null;
  return <section aria-labelledby="platform-readiness-heading" className="lw-stack">
        <div><p className="lw-kicker">Active revision {task.source?.version}</p><h2 className="lw-section-title" id="platform-readiness-heading">Platform readiness</h2><p className="lw-note lw-secondary">Each card follows an exact server platform. “Configuration ready” confirms only the active document structure: policy, root component, user authentication, and feature binding. It does not confirm environment status, secret usability, or physical-device/browser execution.</p></div>
        <div className="lw-platform-cards">
          {platformCards.map((card) => <article className="lw-platform-card" data-platform={card.key} key={card.key}>
            <div className="lw-row lw-row--spread"><strong>{card.label}</strong><Badge color={card.ready ? "success" : "warning"} dot>{card.ready ? "Configuration ready" : "Needs setup"}</Badge></div>
            <code className="lw-code-inline">{card.key}</code>
            <dl>
              <div><dt>Configured</dt><dd>{card.configured}</dd></div>
              <div><dt>Still missing</dt><dd>{card.missing.length ? card.missing.join("; ") : "No server-side prerequisite."}</dd></div>
              <div><dt>Production requires</dt><dd>{card.productionRequirement}</dd></div>
              <div><dt>How to test</dt><dd>{card.test}</dd></div>
            </dl>
            <div className="lw-row lw-row--wrap"><Link className={buttonClass({ size: "sm" })} search={(previous) => ({ ...previous, platform: card.key })} to="/requests">Inspect requests</Link><a className={buttonClass({ size: "sm", variant: "ghost" })} href={card.documentationURL} rel="noreferrer" target="_blank">Client documentation</a></div>
          </article>)}
        </div>
      </section>;
}

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, useMemo, useState } from "react";

import { adminRequest, queryPath, UsageSummarySchema } from "../../api/admin";
import { useConsoleSession } from "../../api/session";
import { FeatureRouteSearchSchema } from "../../app/route-search";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import {
  Badge,
  Button,
  buttonClass,
  Card,
  type Column,
  ConfirmDialog,
  DataTable,
  DetailPanel,
  EmptyState,
  Field,
  Input,
  Notice,
  PageHeader,
  Properties,
  Segmented
} from "../../ui";
import { formatCount } from "../analytics/usage-model";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { deleteAreaResource, type JSONRecord, upsertAreaResource } from "../configuration-slice";
import { CopyButton } from "../requests/request-detail";
import { DraftSaveNotice, StatePill } from "./collection-page";
import { useEnvironmentDraft } from "./environment-draft";
import {
  accessSummary,
  buildFeatureClientSetupSnippets,
  fallbackConditions,
  type FeatureClientSetupSnippet,
  identifierPattern,
  identifierValues,
  object,
  orderedRoutes,
  protocols,
  selectedPlan
} from "./feature-model";
import { type ResourceRow, resourceRows, restoreResource } from "./resource-diff";
import {
  connectionOfModel,
  fallbackText,
  featureOf,
  featuresCollection,
  hasSplits,
  modelsForProtocol,
  moveRoute,
  removeRoute,
  replaceFeature,
  RETRY_CONDITION_LABEL,
  RETRY_CONDITIONS,
  STICKY_LABEL,
  upsertRoute,
  whenText
} from "./routing-model";

type Draft = ReturnType<typeof useEnvironmentDraft>;
type Tab = "overview" | "access" | "routing" | "setup";

const ACCESS_PRESETS = [
  { expression: "principal.authenticated", id: "authenticated", label: "Everyone who signs in" },
  { expression: "principal.authenticated && principal.claims.plan == 'premium'", id: "premium", label: "Premium users" },
  { expression: "principal.authenticated && principal.claims.internal == true", id: "internal", label: "Internal users" }
] as const;

function presetOf(expression: string): string {
  return ACCESS_PRESETS.find((preset) => preset.expression === expression)?.id ?? "custom";
}

function protocolLabel(protocol: unknown): string {
  return String(protocol ?? "").replaceAll("_", " ");
}

/** The first route's model and its connection, as "model on connection". */
function firstChoice(document: JSONRecord | undefined, feature: JSONRecord): string {
  const route = orderedRoutes(feature)[0];
  if (!route) return "—";
  const connection = connectionOfModel(document, route.model);
  return `${String(route.model)}${connection ? ` on ${connection}` : ""}`;
}

function RouteChain({ document, feature }: { document?: JSONRecord; feature: JSONRecord }) {
  const routes = orderedRoutes(feature);
  return (
    <div className="lw-chain">
      {routes.map((route, index) => (
        <div className="lw-chain__row" key={String(route.id)}>
          <div className="lw-chain__rail"><span className="lw-chain__prio" title={`Priority ${String(route.priority)}`}>{index + 1}</span>{index < routes.length - 1 ? <span className="lw-chain__line" /> : null}</div>
          <div className="lw-chain__main">
            <div className="lw-chain__title"><span>{String(route.id)}</span>{index === 0 ? <Badge color="accent" variant="soft">First choice</Badge> : <Badge variant="soft">Backup {index}</Badge>}{route.weight && Number(route.weight) !== 1 ? <Badge variant="soft">Weight {String(route.weight)}</Badge> : null}</div>
            <div className="lw-chain__path"><strong>{connectionOfModel(document, route.model) ?? "unknown connection"}</strong><span className="lw-mono">{String(route.model)}</span></div>
            <div className="lw-chain__meta"><span>When</span><code className="lw-code-inline">{whenText(route)}</code><span>· Switch on</span><span>{fallbackText(route)}</span></div>
          </div>
        </div>
      ))}
    </div>
  );
}

function NewFeatureDrawer({ draft, onClose, onCreated }: { draft: Draft; onClose: () => void; onCreated: (id: string) => void }) {
  const document = draft.document;
  const existing = useMemo(() => (document ? identifierValues(document, "features") : []), [document]);
  const plans = document ? identifierValues(document, "limitPlans") : [];
  const policies = document ? identifierValues(document, "attestationPolicies") : [];
  const [id, setID] = useState("");
  const [protocol, setProtocol] = useState<string>("openai_responses");
  const [access, setAccess] = useState<string>("authenticated");
  const [error, setError] = useState<string>();
  const models = modelsForProtocol(document, protocol).map((model) => String(model.id));
  const idError = id && !identifierPattern.test(id) ? "Use lowercase letters, digits, - or _, starting with a letter." : existing.includes(id) ? `A feature named ${id} already exists.` : undefined;

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const primary = String(form.get("primary_model") ?? "");
    const fallback = String(form.get("fallback_model") ?? "");
    const custom = String(form.get("custom_access") ?? "").trim();
    const defaultTokens = Number(form.get("default_output_tokens"));
    const absoluteTokens = Number(form.get("absolute_output_tokens"));
    const problems = [
      !id || idError ? idError ?? "Name the feature." : undefined,
      !primary ? "Choose the first-choice model." : undefined,
      fallback && fallback === primary ? "The backup must be a different model." : undefined,
      access === "custom" && !custom ? "Write the custom access rule, or pick a preset." : undefined,
      !String(form.get("limit_plan") ?? "") ? "Choose a limit plan." : undefined,
      !String(form.get("attestation_policy") ?? "") ? "Choose an app verification policy." : undefined,
      !Number.isSafeInteger(defaultTokens) || defaultTokens < 1 || !Number.isSafeInteger(absoluteTokens) || absoluteTokens < defaultTokens ? "The output maximum must be at least the default, and both at least 1." : undefined
    ].filter(Boolean);
    if (problems.length) {
      setError(problems.join(" "));
      return;
    }
    setError(undefined);
    const feature: JSONRecord = {
      access: { expression: access === "custom" ? custom : ACCESS_PRESETS.find((preset) => preset.id === access)?.expression ?? "principal.authenticated" },
      attestationPolicy: String(form.get("attestation_policy")),
      id,
      limitPlan: { expression: `'${String(form.get("limit_plan"))}'` },
      output: { absoluteMaximumTokens: absoluteTokens, defaultMaximumTokens: defaultTokens },
      protocol,
      routes: [
        { ...(fallback ? { fallbackOn: fallbackConditions } : {}), id: "primary", model: primary, priority: 10, when: "true" },
        ...(fallback ? [{ id: "fallback", model: fallback, priority: 20, when: "true" }] : [])
      ]
    };
    const saved = await draft.save((current) => upsertAreaResource(current, featuresCollection, undefined, feature).document);
    if (saved) onCreated(id);
  }

  return (
    <DetailPanel className="lw-request-drawer" mono onClose={onClose} title="New feature">
      <form className="lw-stack" onSubmit={(event) => void submit(event)}>
        <p className="lw-secondary lw-note">A feature is what your apps call. It goes into the draft; apps can use it once the draft is published.</p>
        {error ? <Notice title="Fix these before saving" tone="danger">{error}</Notice> : null}
        <Field error={idError} hint="Apps send this ID, so it can't be renamed later." id="feature-id" label="Feature ID">
          <Input autoComplete="off" id="feature-id" invalid={Boolean(idError)} mono onChange={(event) => setID(event.target.value)} placeholder="habit-assistant" spellCheck={false} value={id} />
        </Field>
        <Field hint="The API shape apps use. It can't change after creation." id="feature-protocol" label="Protocol">
          <select className="lw-select" id="feature-protocol" onChange={(event) => setProtocol(event.target.value)} value={protocol}>{protocols.map((value) => <option key={value} value={value}>{protocolLabel(value)}</option>)}</select>
        </Field>
        <div className="lw-form-grid">
          <Field hint={models.length ? undefined : "No model supports this protocol yet. Add one in AI Connections."} id="feature-primary" label="First-choice model">
            <select className="lw-select" id="feature-primary" name="primary_model"><option value="">Choose a model</option>{models.map((model) => <option key={model} value={model}>{model} · {connectionOfModel(document, model)}</option>)}</select>
          </Field>
          <Field hint="Used when the first choice can't connect, times out, is rate limited or returns a 5xx." id="feature-fallback" label="Backup model">
            <select className="lw-select" id="feature-fallback" name="fallback_model"><option value="">No backup</option>{models.map((model) => <option key={model} value={model}>{model} · {connectionOfModel(document, model)}</option>)}</select>
          </Field>
        </div>
        <Field id="feature-access" label="Who can call it">
          <select className="lw-select" id="feature-access" onChange={(event) => setAccess(event.target.value)} value={access}>
            {ACCESS_PRESETS.map((preset) => <option key={preset.id} value={preset.id}>{preset.label}</option>)}
            <option value="custom">Custom rule (CEL)</option>
          </select>
        </Field>
        {access === "custom" ? <Field id="feature-custom-access" label="Custom access rule"><textarea className="lw-json-editor lw-json-editor--short" id="feature-custom-access" maxLength={4096} name="custom_access" placeholder="principal.authenticated && …" rows={3} spellCheck={false} /></Field> : null}
        <div className="lw-form-grid">
          <Field id="feature-plan" label="Limit plan"><select className="lw-select" id="feature-plan" name="limit_plan"><option value="">Choose a plan</option>{plans.map((plan) => <option key={plan} value={plan}>{plan}</option>)}</select></Field>
          <Field id="feature-policy" label="App verification"><select className="lw-select" id="feature-policy" name="attestation_policy"><option value="">Choose a policy</option>{policies.map((policy) => <option key={policy} value={policy}>{policy}</option>)}</select></Field>
          <Field id="feature-default-output" label="Default output tokens"><Input defaultValue={800} id="feature-default-output" min={1} name="default_output_tokens" type="number" /></Field>
          <Field id="feature-absolute-output" label="Most output tokens"><Input defaultValue={1500} id="feature-absolute-output" min={1} name="absolute_output_tokens" type="number" /></Field>
        </div>
        {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
        <div className="lw-row">
          <Button onClick={onClose}>Cancel</Button>
          <Button disabled={!draft.canConfigure} loading={draft.busy} type="submit" variant="primary">Save to Draft</Button>
        </div>
      </form>
    </DetailPanel>
  );
}

function AccessTab({ draft, feature }: { draft: Draft; feature: JSONRecord }) {
  const document = draft.document;
  const expression = object(feature.access) ? String(feature.access.expression ?? "") : "";
  const planExpression = object(feature.limitPlan) ? String(feature.limitPlan.expression ?? "") : "";
  const literalPlan = /^'([a-z][a-z0-9_-]{0,62})'$/.exec(planExpression)?.[1];
  const output = object(feature.output) ? feature.output : {};
  const [access, setAccess] = useState(presetOf(expression));
  const [custom, setCustom] = useState(presetOf(expression) === "custom" ? expression : "");
  const [planMode, setPlanMode] = useState<"plan" | "rule">(literalPlan ? "plan" : "rule");
  const [plan, setPlan] = useState(literalPlan ?? "");
  const [planRule, setPlanRule] = useState(literalPlan ? "" : planExpression);
  const [policy, setPolicy] = useState(String(feature.attestationPolicy ?? ""));
  const [defaultTokens, setDefaultTokens] = useState(String(output.defaultMaximumTokens ?? ""));
  const [absoluteTokens, setAbsoluteTokens] = useState(String(output.absoluteMaximumTokens ?? ""));
  const [error, setError] = useState<string>();
  const plans = document ? identifierValues(document, "limitPlans") : [];
  const policies = document ? identifierValues(document, "attestationPolicies") : [];

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const accessExpression = access === "custom" ? custom.trim() : ACCESS_PRESETS.find((preset) => preset.id === access)?.expression ?? "";
    const limitExpression = planMode === "plan" ? (plan ? `'${plan}'` : "") : planRule.trim();
    const hasOutput = defaultTokens !== "" || absoluteTokens !== "";
    const d = Number(defaultTokens);
    const a = Number(absoluteTokens);
    if (!accessExpression || !limitExpression || !policy) return setError("Choose who can call it, a plan or plan rule, and an app verification policy.");
    if (hasOutput && (!Number.isSafeInteger(d) || !Number.isSafeInteger(a) || d < 1 || a < d)) return setError("The output maximum must be at least the default, and both at least 1.");
    setError(undefined);
    await draft.save((current) => replaceFeature(current, String(feature.id), (value) => {
      const next: JSONRecord = { ...value, access: { expression: accessExpression }, attestationPolicy: policy, limitPlan: { expression: limitExpression } };
      if (hasOutput) next.output = { absoluteMaximumTokens: a, defaultMaximumTokens: d };
      else delete next.output;
      return next;
    }));
  }

  return (
    <form className="lw-stack" onSubmit={(event) => void save(event)}>
      <Card icon="users" title="Who can call it">
        <div className="lw-stack lw-stack--tight">
          <Field id="access-preset" label="Access"><select className="lw-select" id="access-preset" onChange={(event) => setAccess(event.target.value)} value={access}>{ACCESS_PRESETS.map((preset) => <option key={preset.id} value={preset.id}>{preset.label}</option>)}<option value="custom">Custom rule (CEL)</option></select></Field>
          {access === "custom" ? <Field hint="Evaluated with the user's kept claims; the server validates it." id="access-custom" label="Custom access rule"><textarea className="lw-json-editor lw-json-editor--short" id="access-custom" maxLength={4096} onChange={(event) => setCustom(event.target.value)} rows={3} spellCheck={false} value={custom} /></Field> : null}
          <Field hint="Which app verification this feature requires; configured in Client Trust." id="access-policy" label="App verification"><select className="lw-select" id="access-policy" onChange={(event) => setPolicy(event.target.value)} value={policy}><option value="">Choose a policy</option>{policies.map((value) => <option key={value} value={value}>{value}</option>)}</select></Field>
        </div>
      </Card>
      <Card icon="policies" title="Limits">
        <div className="lw-stack lw-stack--tight">
          <Segmented items={[{ id: "plan", label: "One plan for everyone" }, { id: "rule", label: "Plan rule (CEL)" }]} label="Limit plan" onChange={setPlanMode} value={planMode} />
          {planMode === "plan"
            ? <Field id="access-plan" label="Limit plan"><select className="lw-select" id="access-plan" onChange={(event) => setPlan(event.target.value)} value={plan}><option value="">Choose a plan</option>{plans.map((value) => <option key={value} value={value}>{value}</option>)}</select></Field>
            : <Field hint="Must evaluate to a plan ID, e.g. principal.claims.plan == 'premium' ? 'premium' : 'free'." id="access-plan-rule" label="Plan rule"><textarea className="lw-json-editor lw-json-editor--short" id="access-plan-rule" maxLength={4096} onChange={(event) => setPlanRule(event.target.value)} rows={3} spellCheck={false} value={planRule} /></Field>}
          <div className="lw-form-grid">
            <Field hint="Used when the app doesn't ask for a maximum." id="access-default-output" label="Default output tokens"><Input id="access-default-output" min={1} placeholder="Server default" onChange={(event) => setDefaultTokens(event.target.value)} type="number" value={defaultTokens} /></Field>
            <Field hint="The most the app may ask for." id="access-absolute-output" label="Most output tokens"><Input id="access-absolute-output" min={1} placeholder="Server default" onChange={(event) => setAbsoluteTokens(event.target.value)} type="number" value={absoluteTokens} /></Field>
          </div>
        </div>
      </Card>
      {error ? <Notice title="Fix this before saving" tone="danger">{error}</Notice> : null}
      <div className="lw-row"><Button disabled={!draft.canConfigure} loading={draft.busy} type="submit" variant="primary">Save to Draft</Button></div>
    </form>
  );
}

function RouteEditor({ draft, feature, onClose, route }: { draft: Draft; feature: JSONRecord; onClose: () => void; route?: JSONRecord }) {
  const document = draft.document;
  const models = modelsForProtocol(document, feature.protocol).map((model) => String(model.id));
  const [id, setID] = useState(String(route?.id ?? ""));
  const [model, setModel] = useState(String(route?.model ?? ""));
  const [when, setWhen] = useState(String(route?.when ?? "true"));
  const [weight, setWeight] = useState(String(route?.weight ?? "1"));
  const [priority, setPriority] = useState(route?.priority === undefined ? "" : String(route.priority));
  const [sticky, setSticky] = useState(String(route?.stickyBy ?? "none"));
  const [fallback, setFallback] = useState<string[]>(Array.isArray(route?.fallbackOn) ? route.fallbackOn.map(String) : []);
  const [error, setError] = useState<string>();

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const next: JSONRecord = { ...(route ?? {}), id, model, when: when.trim() || "true" };
    if (!model) return setError("Choose a model.");
    if (priority !== "") next.priority = Number(priority);
    if (weight && Number(weight) !== 1) next.weight = Number(weight);
    else delete next.weight;
    if (sticky !== "none") next.stickyBy = sticky;
    else delete next.stickyBy;
    if (fallback.length) next.fallbackOn = fallback;
    else delete next.fallbackOn;
    try {
      upsertRoute(feature, route ? String(route.id) : undefined, next);
    } catch (failure) {
      return setError(failure instanceof Error ? failure.message : "The route is invalid.");
    }
    setError(undefined);
    const saved = await draft.save((current) => replaceFeature(current, String(feature.id), (value) => upsertRoute(value, route ? String(route.id) : undefined, next)));
    if (saved) onClose();
  }

  return (
    <DetailPanel className="lw-request-drawer" mono onClose={onClose} subtitle={<span className="lw-faint">Route of {String(feature.id)}</span>} title={route ? String(route.id) : "New route"}>
      <form className="lw-stack" onSubmit={(event) => void save(event)}>
        <Field hint={route ? "Route IDs can't be renamed." : "Lowercase letters, digits, - or _."} id="route-id" label="Route ID"><Input disabled={Boolean(route)} id="route-id" mono onChange={(event) => setID(event.target.value)} placeholder="backup" value={id} /></Field>
        <Field hint={`Only models that support ${protocolLabel(feature.protocol)} are listed.`} id="route-model" label="Model"><select className="lw-select" id="route-model" onChange={(event) => setModel(event.target.value)} value={model}><option value="">Choose a model</option>{models.map((value) => <option key={value} value={value}>{value} · {connectionOfModel(document, value)}</option>)}</select></Field>
        <Field hint="true matches every request. Rules can use principal.claims.*, installation.platform, client.component.kind, installation.trust_level, request.streaming and request.estimated_input_tokens." id="route-when" label="When (CEL)"><textarea className="lw-json-editor lw-json-editor--short" id="route-when" maxLength={4096} onChange={(event) => setWhen(event.target.value)} rows={2} spellCheck={false} value={when} /></Field>
        <div className="lw-form-grid">
          <Field hint="Lower runs first. Leave empty to add after the last route." id="route-priority" label="Priority"><Input id="route-priority" max={1000000} min={0} onChange={(event) => setPriority(event.target.value)} type="number" value={priority} /></Field>
          <Field hint="Splits traffic with routes of the same priority." id="route-weight" label="Weight"><Input id="route-weight" max={10000} min={1} onChange={(event) => setWeight(event.target.value)} type="number" value={weight} /></Field>
          <Field id="route-sticky" label="Keep users on the same model"><select className="lw-select" id="route-sticky" onChange={(event) => setSticky(event.target.value)} value={sticky}>{Object.entries(STICKY_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
        </div>
        <fieldset className="lw-fieldset">
          <legend>Switch to the next route when</legend>
          <div className="lw-checklist lw-checklist--2">
            {RETRY_CONDITIONS.map((condition) => (
              <label className="lw-check" key={condition}>
                <input checked={fallback.includes(condition)} onChange={(event) => setFallback((current) => event.target.checked ? [...current, condition] : current.filter((value) => value !== condition))} type="checkbox" />
                <span>{RETRY_CONDITION_LABEL[condition]}<span className="lw-faint lw-mono lw-mono--sm"> {condition}</span></span>
              </label>
            ))}
          </div>
          <p className="lw-secondary lw-note">Latchway never switches once any output reached the app. Retry policy, timeouts and size bounds are kept as they are; edit them in the feature's JSON.</p>
        </fieldset>
        {error ? <Notice title="Fix this before saving" tone="danger">{error}</Notice> : null}
        {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!draft.canConfigure} loading={draft.busy} type="submit" variant="primary">Save to Draft</Button></div>
      </form>
    </DetailPanel>
  );
}

function RoutingTab({ draft, feature }: { draft: Draft; feature: JSONRecord }) {
  const [view, setView] = useState<"steps" | "table" | "json">("steps");
  const [editing, setEditing] = useState<{ route?: JSONRecord }>();
  const [moveError, setMoveError] = useState<string>();
  const routes = orderedRoutes(feature);
  const document = draft.document;
  const splits = hasSplits(feature);
  const json = JSON.stringify(feature.routes ?? [], null, 2);

  async function apply(change: (value: JSONRecord) => JSONRecord): Promise<void> {
    setMoveError(undefined);
    try {
      change(feature);
    } catch (failure) {
      setMoveError(failure instanceof Error ? failure.message : "That change isn't possible.");
      return;
    }
    await draft.save((current) => replaceFeature(current, String(feature.id), change));
  }

  return (
    <div className="lw-stack">
      <Card
        actions={<div className="lw-row"><Segmented items={[{ id: "steps", label: "Steps" }, { id: "table", label: "Table" }, { id: "json", label: "JSON" }]} label="Routing view" onChange={setView} value={view} />{draft.canConfigure ? <Button icon="plus" onClick={() => setEditing({})} size="sm">Add Route</Button> : null}</div>}
        flush
        icon="split"
        title="Routes"
      >
        {view === "json" ? (
          <div className="lw-card__body lw-stack lw-stack--tight">
            <pre className="lw-code-block">{json}</pre>
            <div><CopyButton className={buttonClass({ size: "sm" })} label="Copy routes JSON" value={json}>Copy JSON</CopyButton></div>
          </div>
        ) : view === "table" ? (
          <DataTable caption={`Routes of ${String(feature.id)}`} columns={[
            { header: "Route", key: "id", render: (route: JSONRecord) => <span className="lw-mono lw-mono--sm">{String(route.id)}</span> },
            { align: "right", header: "priority", key: "priority", render: (route) => String(route.priority) },
            { header: "model", key: "model", render: (route) => <span className="lw-mono lw-mono--sm">{String(route.model)}</span> },
            { header: "when", key: "when", render: (route) => <code className="lw-code-inline">{String(route.when)}</code> },
            { align: "right", header: "weight", key: "weight", render: (route) => String(route.weight ?? 1) },
            { header: "stickyBy", key: "sticky", render: (route) => String(route.stickyBy ?? "none") },
            { header: "fallbackOn", key: "fallback", render: (route) => Array.isArray(route.fallbackOn) ? route.fallbackOn.join(", ") : "—" }
          ]} rowKey={(route) => String(route.id)} rows={routes} />
        ) : (
          <ol className="lw-route-steps">
            {routes.map((route, index) => (
              <li key={String(route.id)}>
                <span className="lw-chain__prio">{index + 1}</span>
                <div className="lw-route-steps__main">
                  <div className="lw-chain__title"><strong>{String(route.id)}</strong>{index === 0 ? <Badge color="accent" variant="soft">First choice</Badge> : <Badge variant="soft">Backup {index}</Badge>}</div>
                  <div className="lw-chain__path"><strong>{connectionOfModel(document, route.model) ?? "unknown connection"}</strong><span className="lw-mono">{String(route.model)}</span></div>
                  <div className="lw-chain__meta"><span>When</span><code className="lw-code-inline">{whenText(route)}</code><span>· Switch on {fallbackText(route)}</span></div>
                </div>
                {draft.canConfigure ? (
                  <div className="lw-row lw-row--tight">
                    <Button aria-label={`Move ${String(route.id)} earlier`} disabled={index === 0 || splits || draft.busy} icon="arrowUp" onClick={() => void apply((value) => moveRoute(value, String(route.id), -1))} size="sm" variant="ghost" />
                    <Button aria-label={`Move ${String(route.id)} later`} disabled={index === routes.length - 1 || splits || draft.busy} icon="arrowDown" onClick={() => void apply((value) => moveRoute(value, String(route.id), 1))} size="sm" variant="ghost" />
                    <Button onClick={() => setEditing({ route })} size="sm">Edit</Button>
                    <Button aria-label={`Remove ${String(route.id)}`} disabled={routes.length <= 1 || draft.busy} icon="trash" onClick={() => void apply((value) => removeRoute(value, String(route.id)))} size="sm" title={routes.length <= 1 ? "A feature keeps at least one route" : undefined} variant="ghost" />
                  </div>
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </Card>
      {splits ? <Notice tone="info">Some routes share a priority to split traffic by weight, so reordering is off. Edit their priorities directly.</Notice> : null}
      {routes.length === 1 ? <Notice title="No backup route" tone="warning">If {connectionOfModel(document, routes[0]?.model) ?? "this connection"} is down, every request to {String(feature.id)} fails. Add a route on another AI connection.</Notice> : null}
      {moveError ? <Notice tone="danger">{moveError}</Notice> : null}
      <p className="lw-secondary lw-note">Also on <Link className="lw-link" search={(previous) => previous} to="/routes">Routing</Link>, which shows every feature's routes.</p>
      {editing ? <div className="lw-drawer-dock"><RouteEditor draft={draft} feature={feature} key={String(editing.route?.id ?? "new")} onClose={() => setEditing(undefined)} route={editing.route} /></div> : null}
    </div>
  );
}

function SnippetCard({ snippet }: { snippet: FeatureClientSetupSnippet }) {
  return (
    <Card actions={<div className="lw-row"><CopyButton className={buttonClass({ size: "sm" })} label={`Copy ${snippet.label} snippet`} value={snippet.code}>Copy</CopyButton><a className={buttonClass({ size: "sm", variant: "ghost" })} href={snippet.documentationURL} rel="noreferrer" target="_blank">Docs</a></div>} meta={<Badge color={snippet.available ? "success" : "warning"} dot>{snippet.available ? "Configured" : "Unavailable"}</Badge>} title={snippet.label}>
      <div className="lw-stack lw-stack--tight" data-client-surface={snippet.surface}>
        <p className="lw-secondary lw-note">{snippet.status}</p>
        <pre className="lw-code-block">{snippet.code}</pre>
        <p className="lw-note"><strong>Your app needs:</strong> {snippet.prerequisites.join(" · ")}</p>
      </div>
    </Card>
  );
}

function RemoveFeatureDialog({ draft, onClose, row }: { draft: Draft; onClose: () => void; row: ResourceRow }) {
  const workspace = useWorkspace();
  const [typed, setTyped] = useState("");
  const environmentID = workspace.environment?.id ?? "";
  const [window] = useState(() => {
    const end = Date.now();
    return { end: new Date(end).toISOString(), start: new Date(end - 86_400_000).toISOString() };
  });
  const usage = useQuery({
    enabled: row.state !== "new" && Boolean(environmentID),
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/usage/summary", { breakdown_limit: "200", end: window.end, environment_id: environmentID, start: window.start }), UsageSummarySchema)).data,
    queryKey: ["feature-remove-usage", environmentID, row.key],
    retry: false
  });
  const requests = usage.data?.analytics.by_feature.items.find((item) => item.key === row.key)?.request_count;
  const remove = () => void draft.save((current) => deleteAreaResource(current, featuresCollection, row.key)).then((saved) => { if (saved) onClose(); });
  if (row.state === "new") {
    return <ConfirmDialog confirmLabel="Remove" description="It was never published, so nothing else changes." destructive onCancel={onClose} onConfirm={remove} pending={draft.busy} title={`Remove ${row.key} from the draft?`} />;
  }
  return (
    <ConfirmDialog confirmDisabled={typed !== row.key} confirmLabel="Remove in Draft" description="Apps keep calling it until the draft is published. After that, requests for it are refused." destructive onCancel={onClose} onConfirm={remove} pending={draft.busy} title={`Remove ${row.key}?`}>
      <p className="lw-note">{usage.isPending ? "Checking recent requests…" : requests === undefined ? "No requests for it in the last 24 hours." : <><strong>{formatCount(requests)} requests</strong> in the last 24 hours would be refused once this is published.</>}</p>
      <Field id="remove-feature-confirm" label={<>Type <code className="lw-code-inline">{row.key}</code> to confirm</>}><Input autoComplete="off" id="remove-feature-confirm" mono onChange={(event) => setTyped(event.target.value)} spellCheck={false} value={typed} /></Field>
      {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
    </ConfirmDialog>
  );
}

function FeaturePageView({ draft, featureID, onBack, tab }: { draft: Draft; featureID: string; onBack: () => void; tab: Tab }) {
  const workspace = useWorkspace();
  const [removing, setRemoving] = useState(false);
  const rows = useMemo(() => resourceRows(draft.activeDocument, draft.document, featuresCollection), [draft.activeDocument, draft.document]);
  const row = rows.find((candidate) => candidate.key === featureID);
  const feature = featureOf(draft.document, featureID) ?? (row?.state === "removing" ? row.live : undefined);
  const application = workspace.application;
  const environment = workspace.environment;
  if (draft.isPending || (!draft.document && !draft.problem)) {
    return <div className="lw-page"><PageHeader title={featureID} /><p className="lw-page-status" role="status">Loading configuration…</p></div>;
  }
  if (!row || !feature) {
    return (
      <div className="lw-page"><PageHeader title={featureID} /><div className="lw-body">
        <Notice action={<Button onClick={onBack} size="sm">Back to Features</Button>} title="Feature not found" tone="danger">The configuration has no feature named <code className="lw-code-inline">{featureID}</code>. No other feature was opened instead.</Notice>
      </div></div>
    );
  }
  const snippets = application && environment && draft.document ? buildFeatureClientSetupSnippets({ applicationID: application.id, document: draft.document, environmentSlug: environment.slug, featureID, gatewayURL: typeof globalThis.window === "undefined" ? undefined : globalThis.window.location.origin }) : [];
  const setTab = (next: Tab) => workspace.updateSearch({ tab: next === "overview" ? undefined : next });
  const output = object(feature.output) ? feature.output : undefined;

  return (
    <div className="lw-page lw-feature">
      <PageHeader
        actions={draft.canConfigure ? <div className="lw-row">
          {row.state === "removing" || row.state === "edited" ? <Button onClick={() => void draft.save((current) => restoreResource(current, row, featuresCollection))} size="md">{row.state === "removing" ? "Undo Remove" : "Undo Changes"}</Button> : null}
          {row.state !== "removing" ? <Button aria-label={`Remove ${featureID}`} destructive icon="trash" onClick={() => setRemoving(true)} variant="ghost" /> : null}
          <Link className={buttonClass()} search={(previous) => ({ ...previous, feature: featureID })} to="/route-simulator">Test a Request</Link>
        </div> : undefined}
        badge={<StatePill state={row.state} />}
        description={<><button className="lw-link" onClick={onBack} type="button">Features</button> › {protocolLabel(feature.protocol)} · {accessSummary(feature)}</>}
        tabs={
          <div className="lw-tabs" role="tablist">
            {([["overview", "Overview"], ["access", "Access & limits"], ["routing", "Routing"], ["setup", "Client setup"]] as const).map(([id, label]) => (
              <button aria-selected={tab === id} className="lw-tab" key={id} onClick={() => setTab(id)} role="tab" type="button">{label}</button>
            ))}
          </div>
        }
        title={featureID}
      />
      <DraftSaveNotice draft={draft} />
      <div className="lw-body">
        {row.state === "removing" ? <Notice title="Removed in the draft" tone="danger">Apps keep calling {featureID} until the draft is published. Undo Remove keeps it.</Notice> : null}
        {tab === "overview" ? (
          <div className="lw-hgrid lw-hgrid--2">
            <Card icon="features" title="Settings">
              <Properties columns={2} items={[
                { label: "Protocol", value: protocolLabel(feature.protocol) },
                { label: "Who can call it", value: accessSummary(feature) },
                { label: "Limit plan", value: selectedPlan(feature) },
                { label: "App verification", value: String(feature.attestationPolicy ?? "—") },
                { label: "Output tokens", value: output ? `${String(output.defaultMaximumTokens)} default · ${String(output.absoluteMaximumTokens)} most` : "Server default" },
                { label: "First choice", value: firstChoice(draft.document, feature) }
              ]} />
            </Card>
            <Card icon="split" title="Routes"><RouteChain document={draft.document} feature={feature} /></Card>
          </div>
        ) : tab === "access" ? (
          row.state === "removing" ? null : <AccessTab draft={draft} feature={feature} key={JSON.stringify(feature)} />
        ) : tab === "routing" ? (
          row.state === "removing" ? <RouteChain document={draft.document} feature={feature} /> : <RoutingTab draft={draft} feature={feature} />
        ) : (
          <div className="lw-stack">
            <Card icon="code" title="What your app sends">
              <Properties columns={2} items={[
                { label: "Gateway URL", value: <code className="lw-code-inline">{typeof globalThis.window === "undefined" ? "Unavailable" : globalThis.window.location.origin}</code> },
                { label: "Application ID", value: <code className="lw-code-inline">{application?.id}</code> },
                { label: "Environment", value: <code className="lw-code-inline">{environment?.slug}</code> },
                { label: "Feature", value: <code className="lw-code-inline">{featureID}</code> }
              ]} />
              <p className="lw-secondary lw-note">Snippets contain only these public values and the sign-in provider's name. Provider keys, secret references, identity tokens and verification evidence never appear.</p>
            </Card>
            <div className="lw-hgrid lw-hgrid--2">{snippets.map((snippet) => <SnippetCard key={snippet.surface} snippet={snippet} />)}</div>
          </div>
        )}
      </div>
      {removing ? <RemoveFeatureDialog draft={draft} onClose={() => setRemoving(false)} row={row} /> : null}
    </div>
  );
}

function FeaturesView() {
  const workspace = useWorkspace();
  const draft = useEnvironmentDraft();
  const search = FeatureRouteSearchSchema.parse(workspace.search);
  const [creating, setCreating] = useState(false);
  const rows = useMemo(() => {
    try {
      return resourceRows(draft.activeDocument, draft.document, featuresCollection);
    } catch {
      return [];
    }
  }, [draft.activeDocument, draft.document]);
  const open = (featureID: string | undefined) => workspace.updateSearch({ feature: featureID, tab: undefined }, { replace: false });

  if (search.feature) return <FeaturePageView draft={draft} featureID={search.feature} onBack={() => open(undefined)} tab={search.tab ?? "overview"} />;

  const columns: Array<Column<ResourceRow>> = [
    { header: "Feature", key: "id", render: (row) => <span className="lw-name-cell"><span className={`lw-mono lw-mono--sm${row.state === "removing" ? " lw-struck" : ""}`}>{row.key}</span><StatePill state={row.state} /></span> },
    { header: "Protocol", key: "protocol", render: (row) => <Badge color="cyan" variant="soft">{protocolLabel(row.value.protocol)}</Badge> },
    { header: "Who can call it", key: "access", render: (row) => accessSummary(row.value) },
    { header: "Limit plan", key: "plan", render: (row) => selectedPlan(row.value) },
    { header: "First choice", key: "first", render: (row) => <span className="lw-mono lw-mono--sm">{firstChoice(draft.document ?? draft.activeDocument, row.value)}</span> },
    { align: "right", header: "Routes", key: "routes", render: (row) => orderedRoutes(row.value).length }
  ];

  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={draft.canConfigure ? <Button icon="plus" onClick={() => setCreating(true)} variant="primary">New Feature</Button> : undefined} description="What your apps are allowed to call. Each feature sets who can use it, their limits, and which AI connection answers." title="Features" />
      <DraftSaveNotice draft={draft} />
      {draft.isPending ? <p className="lw-page-status" role="status">Loading configuration…</p> : rows.length ? (
        <DataTable caption="Features" columns={columns} onSelect={(row) => open(row.key)} rowKey={(row) => row.key} rows={rows} />
      ) : draft.document ? (
        <div className="lw-page-empty"><EmptyState action={draft.canConfigure ? <Button icon="plus" onClick={() => setCreating(true)} variant="primary">New Feature</Button> : undefined} icon="features" orientation="horizontal" title="No features yet">Create a feature to let your apps call an AI model through Latchway.</EmptyState></div>
      ) : !draft.problem ? (
        <div className="lw-page-empty"><EmptyState action={<Link className={buttonClass({ variant: "primary" })} search={(previous) => previous} to="/setup">Continue Setup</Link>} icon="rocket" orientation="horizontal" title="No configuration yet">Finish first-run setup to publish a configuration, then add features.</EmptyState></div>
      ) : null}
      {creating ? <div className="lw-drawer-dock"><NewFeatureDrawer draft={draft} onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); open(id); }} /></div> : null}
    </div>
  );
}

function FeaturesWorkspace() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><FeaturesView /></EnvironmentRequired>;
}

/** Build → Features: the features in the working draft, each with its own page. */
export function FeaturesPage() {
  return <FeaturesWorkspace />;
}

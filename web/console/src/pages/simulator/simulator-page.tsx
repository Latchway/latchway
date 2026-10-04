import { useQueries, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, Fragment, type ReactNode, useState } from "react";

import { adminRequest, EffectiveConfigurationSchema, type EffectiveConfiguration, queryPath, type RouteSimulation } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { ConfigurationRevisionResourcePageSchema } from "../../api/resources";
import { useConsoleSession } from "../../api/session";
import { GRID_DIMENSIONS, RouteSimulatorRouteSearchSchema, type RouteSimulatorRouteSearch } from "../../app/route-search";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useOptionalWorkspace, useWorkspace, type WorkspaceSearch } from "../../app/workspace-context-value";
import { Badge, Button, buttonClass, Card, Field, Icon, Input, Notice, PageHeader, Segmented } from "../../ui";
import { type EnvironmentDraft, useEnvironmentDraft } from "../build/environment-draft";
import { identifierValues, specCollection } from "../build/feature-model";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import type { JSONRecord } from "../configuration-slice";
import { LimitSentenceText } from "../policies/limit-editor";
import { nanoToDollars } from "../policies/limit-model";
import { CopyButton } from "../requests/request-detail";
import { STAGE_LABEL as RECORDED_STAGE_LABEL } from "../requests/request-format";
import {
  changedStages,
  cliCommand,
  deniedAt,
  handlingStep,
  outcomeText,
  type Platform,
  PLATFORM_LABEL,
  type RequestSize,
  simulate,
  type SimulationInput,
  SIZE_PRESETS,
  sizePreset,
  type Stage,
  STAGE_FIX,
  STAGE_LABEL,
  STAGES,
  TRUST_LABEL,
  TRUST_ORDER,
  type TrustLevel,
  whatIfVariants
} from "./simulator-model";

type Mode = NonNullable<RouteSimulatorRouteSearch["mode"]>;
type GridDimension = (typeof GRID_DIMENSIONS)[number];

const GRID_LABEL: Readonly<Record<GridDimension, string>> = { plan: "Plan claim", platform: "Platform", size: "Request size", streaming: "Streaming", trust_level: "Trust level" };
const PLATFORMS = Object.keys(PLATFORM_LABEL) as Platform[];
const IMPOSSIBLE: ReadonlyArray<[Platform, TrustLevel, string]> = [
  ["web", "app_verified", "A web page can't prove it's a genuine app; web requests reach at most Web risk check."],
  ["web", "device_verified", "A web page can't prove a genuine device."],
  ["web", "strong_device_verified", "A web page can't prove a genuine device."],
  ["node", "app_verified", "A Node process can't prove it's a genuine app."]
];

/** Server problems as they are; a result the console refused (wrong revision or feature) says why. */
function simulationProblem(error: unknown) {
  if (error instanceof Error && !("problem" in error)) return { code: "context_mismatch", detail: error.message, retryable: true, status: 0, title: "Simulation result refused" };
  return problemFromError(error);
}

function scoped(previous: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return { application: previous.application as string | undefined, environment: previous.environment as string | undefined, organization: previous.organization as string | undefined, ...extra };
}

function number(value: string | undefined, fallback: number): number {
  return value === undefined ? fallback : Number(value);
}

function inputFromSearch(search: RouteSimulatorRouteSearch, features: readonly string[]): Omit<SimulationInput, "claims"> {
  const base = SIZE_PRESETS[0]!.size;
  return {
    appVersion: search.app_version,
    authenticated: search.authenticated ?? true,
    feature: search.feature && features.includes(search.feature) ? search.feature : features[0] ?? "",
    platform: search.platform ?? "ios",
    size: {
      expanded_schema_bytes: number(search.expanded_schema_bytes, base.expanded_schema_bytes),
      framing_unit_count: number(search.framing_unit_count, base.framing_unit_count),
      image_units: number(search.image_units, base.image_units),
      requested_input_tokens: number(search.requested_input_tokens, base.requested_input_tokens),
      requested_output_max: number(search.requested_output_max, base.requested_output_max),
      rewritten_request_bytes: number(search.rewritten_request_bytes, base.rewritten_request_bytes),
      tool_calls: number(search.tool_calls, base.tool_calls)
    },
    streaming: search.streaming ?? false,
    trustLevel: search.trust_level ?? "app_verified"
  };
}

function searchFromInput(input: SimulationInput): Partial<WorkspaceSearch> {
  return {
    app_version: input.appVersion || undefined,
    authenticated: input.authenticated ? undefined : false,
    expanded_schema_bytes: String(input.size.expanded_schema_bytes),
    feature: input.feature,
    framing_unit_count: String(input.size.framing_unit_count),
    image_units: String(input.size.image_units),
    platform: input.platform,
    requested_input_tokens: String(input.size.requested_input_tokens),
    requested_output_max: String(input.size.requested_output_max),
    rewritten_request_bytes: String(input.size.rewritten_request_bytes),
    streaming: input.streaming || undefined,
    tool_calls: String(input.size.tool_calls),
    trust_level: input.trustLevel
  };
}

/** "live", "draft" or a revision ID, resolved to the revision that runs. */
function useTargets(draft: EnvironmentDraft, environmentID: string) {
  const history = useQuery({
    enabled: Boolean(environmentID),
    queryFn: async () => (await adminRequest(queryPath(`/admin/v1/environments/${environmentID}/config-revisions`, { page_size: "20" }), ConfigurationRevisionResourcePageSchema)).data.items.filter((item) => item.environment_id === environmentID),
    queryKey: ["environment", environmentID, "configuration-revisions", "simulator"],
    retry: false
  });
  const options = [
    ...(draft.active ? [{ document: draft.activeDocument, id: "live", label: `Live (${draft.active.id})`, revision: draft.active.id }] : []),
    ...(draft.draft?.state === "valid" ? [{ document: draft.draft.document as JSONRecord, id: "draft", label: `Draft (${draft.draft.id})`, revision: draft.draft.id }] : []),
    ...(history.data ?? []).filter((item) => item.id !== draft.active?.id && item.id !== draft.draft?.id && (item.state === "valid" || item.state === "superseded" || item.state === "active")).map((item) => ({ document: item.document as JSONRecord, id: item.id, label: `Version ${item.version} (${item.id})`, revision: item.id }))
  ];
  return { draftNeedsCheck: Boolean(draft.draft && draft.draft.state !== "valid"), options };
}

/** One limit from a simulation result, read as a sentence. */
function simulatedLimit(limit: NonNullable<RouteSimulation["limits"]>[number]): JSONRecord {
  return {
    algorithm: limit.algorithm,
    capacity: limit.capacity,
    hard: limit.hard,
    maximum: limit.maximum,
    metric: limit.metric,
    perRequestMaximum: limit.per_request_maximum,
    refillPerSecond: limit.refill_per_second === undefined ? undefined : Number(limit.refill_per_second),
    scope: limit.scope,
    timezone: limit.timezone,
    window: limit.window
  };
}

function StageBody({ down, input, onToggleDown, result, stage }: { down: ReadonlySet<string>; input: SimulationInput; onToggleDown?: (connection: string) => void; result: RouteSimulation; stage: Stage }) {
  switch (stage) {
    case "signed_in": return <span className="lw-trace__detail">{input.authenticated ? "Verified sign-in" : "Not signed in"}</span>;
    case "app_verified": return <span className="lw-trace__detail">{PLATFORM_LABEL[input.platform]} · {TRUST_LABEL[input.trustLevel]}</span>;
    case "access": return <span className="lw-trace__detail">{result.matched_access_expression ? <code>{result.matched_access_expression}</code> : "—"}</span>;
    case "plan": return <span className="lw-trace__detail">{result.limit_plan ?? "—"}</span>;
    case "quota": {
      const reservation = result.reservation;
      return (
        <div className="lw-trace__detail">
          {reservation ? <span>Up to {reservation.total_token_bound.toLocaleString("en-US")} tokens (output capped at {reservation.applied_output_maximum.toLocaleString("en-US")}) · {reservation.cost_bound_known ? `at most ${nanoToDollars(reservation.cost_nano_usd_bound)}` : "cost bound unknown"}</span> : null}
          {(result.limits ?? []).length ? <ul className="lw-trace__limits">{(result.limits ?? []).map((limit, index) => <li key={index}><LimitSentenceText limit={simulatedLimit(limit)} /></li>)}</ul> : null}
          <span className="lw-faint">Nothing is reserved; remaining quota isn't simulated.</span>
        </div>
      );
    }
    case "route": {
      const sequence = result.fallback_sequence ?? [];
      const handler = handlingStep(result, down);
      if (!sequence.length) return <span className="lw-trace__detail">{result.model ? `${result.model} on ${result.upstream ?? "?"}${result.physical_model ? ` (${result.physical_model})` : ""}` : "—"}</span>;
      return (
        <div className="lw-trace__detail">
          <div className="lw-trace__route">
            {sequence.map((step, index) => (
              <Fragment key={`${step.route}-${index}`}>
                <div className={`lw-trace__model${down.has(step.upstream) ? " is-down" : ""}${handler === index && down.size ? " is-chosen" : ""}`}>
                  <div className="lw-stack lw-stack--tight"><strong>{step.model} on {step.upstream}</strong><span className="lw-mono">{step.physical_model} · route {step.route}{handler === index && down.size ? " · Handles it" : ""}</span></div>
                </div>
                {index < sequence.length - 1 ? <span className="lw-trace__trigger"><Icon name="arrowRight" size={12} />{step.fallback_on.length ? step.fallback_on.join(", ") : "never"}</span> : null}
              </Fragment>
            ))}
          </div>
          {onToggleDown && sequence.length ? (
            <div className="lw-sim-chips">
              <span className="lw-sim-note">Pretend down:</span>
              {[...new Set(sequence.map((step) => step.upstream))].map((connection) => <button aria-pressed={down.has(connection)} className="lw-pill" key={connection} onClick={() => onToggleDown(connection)} type="button">{connection}</button>)}
            </div>
          ) : null}
          {down.size && handler === undefined ? <Notice tone="warning">Allowed, but every connection is down: the app would get upstream_unavailable.</Notice> : null}
        </div>
      );
    }
  }
}

function Trace({ changed, input, label, onToggleDown, down, result }: { changed?: ReadonlySet<Stage>; down: ReadonlySet<string>; input: SimulationInput; label?: string; onToggleDown?: (connection: string) => void; result: RouteSimulation }) {
  const stopped = deniedAt(result);
  const stopIndex = stopped ? STAGES.indexOf(stopped) : result.allowed ? STAGES.length : -1;
  const fix = stopped ? STAGE_FIX[stopped] : undefined;
  const mattered = result.fact_usage.filter((usage) => usage.affects_cel).map((usage) => usage.fact);
  return (
    <div className="lw-sim-result">
      {label ? <p className="lw-sim-note">{label} · <span className="lw-mono lw-mono--sm">{result.revision_id}</span></p> : null}
      <div className={`lw-verdict lw-verdict--${result.allowed ? "ok" : "deny"}`}>
        <Icon name={result.allowed ? "check" : "ban"} size={20} />
        <div>
          <strong>{result.allowed ? "Allowed" : stopped ? `Denied at ${STAGE_LABEL[stopped]}` : "Denied"}</strong>
          {result.allowed ? <span>{result.limit_plan} · {result.model} on {result.upstream}</span> : <span>{result.explanation[0]}</span>}
        </div>
        {fix ? <Link className={buttonClass({ size: "sm" })} search={(previous) => scoped(previous, fix.to === "/features" ? { feature: input.feature, tab: "access" } : fix.to === "/plan-by-feature" ? { feature: input.feature } : {})} to={fix.to}>{fix.label}</Link> : null}
      </div>
      <ol className="lw-trace">
        {STAGES.map((stage, index) => {
          const state = index < stopIndex ? "pass" : index === stopIndex ? "deny" : "skip";
          return (
            <li className={`lw-trace__step${state === "skip" ? "" : ` lw-trace__step--${state}`}${changed?.has(stage) ? " lw-trace__step--changed" : ""}`} key={stage}>
              <span className="lw-trace__dot"><Icon name={state === "pass" ? "check" : state === "deny" ? "x" : "minus"} size={12} /></span>
              <div className="lw-trace__body">
                <div className="lw-trace__head"><strong>{STAGE_LABEL[stage]}</strong>{changed?.has(stage) ? <Badge color="orange" variant="soft">Changed</Badge> : null}{state === "skip" && !result.allowed ? <span className="lw-sim-note">Not reached</span> : null}</div>
                {state !== "skip" || result.allowed ? <StageBody down={down} input={input} onToggleDown={onToggleDown} result={result} stage={stage} /> : null}
              </div>
            </li>
          );
        })}
      </ol>
      {mattered.length ? <div className="lw-trace__used"><span>Inputs that mattered:</span>{mattered.map((fact) => <Badge key={fact} variant="soft">{fact}</Badge>)}</div> : null}
      {result.pricing_confidence === "unknown" && result.allowed ? <div className="lw-trace__warn"><div><Icon name="alert" size={14} />This model has no pricing, so spend can&apos;t be bounded.</div></div> : null}
      <details><summary className="lw-sim-note">Server notes</summary><ul className="lw-issue-list lw-note">{[...result.explanation, ...(result.warnings ?? [])].map((line) => <li key={line}>{line}</li>)}</ul></details>
    </div>
  );
}

function InputsPanel({ features, input, onChange, plans }: { features: readonly string[]; input: SimulationInput; onChange: (input: SimulationInput) => void; plans: readonly string[] }) {
  const preset = sizePreset(input.size);
  const impossible = IMPOSSIBLE.find(([platform, trust]) => platform === input.platform && trust === input.trustLevel);
  const plan = typeof input.claims.plan === "string" ? input.claims.plan : "";
  const setSize = (key: keyof RequestSize, text: string) => {
    const value = Number(text);
    if (Number.isSafeInteger(value) && value >= 0) onChange({ ...input, size: { ...input.size, [key]: value } });
  };
  return (
    <div className="lw-sim-inputs">
      <Field id="sim-feature" label="Feature">
        <select className="lw-select" id="sim-feature" onChange={(event) => onChange({ ...input, feature: event.target.value })} value={input.feature}>
          {!features.includes(input.feature) && input.feature ? <option value={input.feature}>{input.feature} (not in this revision)</option> : null}
          {features.map((feature) => <option key={feature} value={feature}>{feature}</option>)}
        </select>
      </Field>
      <fieldset className="lw-sim-group">
        <legend>Who</legend>
        <label className="lw-check"><input checked={input.authenticated} onChange={(event) => onChange({ ...input, authenticated: event.target.checked })} type="checkbox" /><span>Signed in</span></label>
        <Field hint="Claims stay in this page; they never go into the URL." id="sim-plan" label="Plan claim">
          <Input id="sim-plan" list="sim-plans" mono onChange={(event) => { const value = event.target.value.trim(); const claims = { ...input.claims }; if (value) claims.plan = value; else delete claims.plan; onChange({ ...input, claims }); }} placeholder="No plan claim" value={plan} />
          <datalist id="sim-plans">{plans.map((value) => <option key={value} value={value} />)}</datalist>
        </Field>
        <label className="lw-check"><input checked={input.claims.internal === true} onChange={(event) => { const claims = { ...input.claims }; if (event.target.checked) claims.internal = true; else delete claims.internal; onChange({ ...input, claims }); }} type="checkbox" /><span>Internal claim is true</span></label>
      </fieldset>
      <fieldset className="lw-sim-group">
        <legend>Where from</legend>
        <div className="lw-sim-row">
          <Field id="sim-platform" label="Platform"><select className="lw-select" id="sim-platform" onChange={(event) => onChange({ ...input, platform: event.target.value as Platform })} value={input.platform}>{PLATFORMS.map((value) => <option key={value} value={value}>{PLATFORM_LABEL[value]}</option>)}</select></Field>
          <Field id="sim-trust" label="Trust level"><select className="lw-select" id="sim-trust" onChange={(event) => onChange({ ...input, trustLevel: event.target.value as TrustLevel })} value={input.trustLevel}>{TRUST_ORDER.map((value) => <option key={value} value={value}>{TRUST_LABEL[value]}</option>)}</select></Field>
        </div>
        {impossible ? <p className="lw-text-warning lw-note">{impossible[2]}</p> : null}
      </fieldset>
      <fieldset className="lw-sim-group">
        <legend>Request</legend>
        <Segmented items={[...SIZE_PRESETS.map((item) => ({ id: item.id, label: item.label })), ...(preset === "custom" ? [{ id: "custom", label: "Custom" }] : [])]} label="Request size" onChange={(id) => { const chosen = SIZE_PRESETS.find((item) => item.id === id); if (chosen) onChange({ ...input, size: chosen.size }); }} value={preset} />
        <label className="lw-check"><input checked={input.streaming} onChange={(event) => onChange({ ...input, streaming: event.target.checked })} type="checkbox" /><span>Streaming</span></label>
        <details>
          <summary className="lw-note">Advanced</summary>
          <div className="lw-form-grid">
            <Field id="sim-input" label="Prompt tokens (estimate)"><Input id="sim-input" inputMode="numeric" onChange={(event) => setSize("requested_input_tokens", event.target.value)} value={String(input.size.requested_input_tokens)} /></Field>
            <Field id="sim-output" label="Requested output maximum"><Input id="sim-output" inputMode="numeric" onChange={(event) => setSize("requested_output_max", event.target.value)} value={String(input.size.requested_output_max)} /></Field>
            <Field id="sim-bytes" label="Request bytes"><Input id="sim-bytes" inputMode="numeric" onChange={(event) => setSize("rewritten_request_bytes", event.target.value)} value={String(input.size.rewritten_request_bytes)} /></Field>
            <Field id="sim-units" label="Messages and parts"><Input id="sim-units" inputMode="numeric" onChange={(event) => setSize("framing_unit_count", event.target.value)} value={String(input.size.framing_unit_count)} /></Field>
            <Field id="sim-tools" label="Tool calls"><Input id="sim-tools" inputMode="numeric" onChange={(event) => setSize("tool_calls", event.target.value)} value={String(input.size.tool_calls)} /></Field>
            <Field id="sim-images" label="Images"><Input id="sim-images" inputMode="numeric" onChange={(event) => setSize("image_units", event.target.value)} value={String(input.size.image_units)} /></Field>
            <Field id="sim-schema" label="Tool schema bytes"><Input id="sim-schema" inputMode="numeric" onChange={(event) => setSize("expanded_schema_bytes", event.target.value)} value={String(input.size.expanded_schema_bytes)} /></Field>
            <Field id="sim-version" label="App version"><Input id="sim-version" maxLength={128} onChange={(event) => onChange({ ...input, appVersion: event.target.value || undefined })} value={input.appVersion ?? ""} /></Field>
          </div>
        </details>
        <p className="lw-secondary lw-note">There's no prompt box: Latchway never sees content, and policy uses only sizes.</p>
      </fieldset>
    </div>
  );
}

function WhatIf({ input, onApply, planValues, result, revision }: { input: SimulationInput; onApply: (input: SimulationInput) => void; planValues: readonly string[]; result: RouteSimulation; revision: string }) {
  const variants = whatIfVariants(input, planValues);
  const runs = useQueries({ queries: variants.map((variant) => ({ queryFn: () => simulate(revision, variant.input), queryKey: ["simulate", revision, JSON.stringify(variant.input)], retry: false, staleTime: 60_000 })) });
  const base = outcomeText(result);
  return (
    <ul className="lw-whatif">
      {variants.map((variant, index) => {
        const run = runs[index];
        const outcome = run?.isPending ? "…" : outcomeText(run?.data, run?.error);
        return (
          <li key={variant.label}>
            <button className={`lw-whatif__row${outcome === base ? " is-same" : ""}`} onClick={() => onApply(variant.input)} type="button">
              <span>{variant.label}</span>
              <Icon name="arrowRight" size={12} />
              <span className={`lw-whatif__then${outcome.startsWith("Denied") ? " is-deny" : ""}`}>{outcome === base ? "Same result" : outcome}</span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function SampleMode({ draft, input, onInput, search, targets }: { draft: EnvironmentDraft; input: SimulationInput; onInput: (input: SimulationInput) => void; search: RouteSimulatorRouteSearch; targets: ReturnType<typeof useTargets> }) {
  const workspace = useWorkspace();
  const run = targets.options.find((option) => option.id === (search.run ?? "live")) ?? targets.options[0];
  const versus = search.versus ? targets.options.find((option) => option.id === search.versus) : undefined;
  const [submitted, setSubmitted] = useState<SimulationInput>();
  const [down, setDown] = useState<ReadonlySet<string>>(new Set());
  const [showWhatIf, setShowWhatIf] = useState(false);
  const features = run?.document ? identifierValues(run.document, "features") : [];
  const plans = draft.document ? identifierValues(draft.document, "limitPlans") : [];
  const results = useQueries({
    queries: [run, versus].map((target) => ({
      enabled: Boolean(target && submitted),
      queryFn: () => simulate(target?.revision ?? "", submitted as SimulationInput),
      queryKey: ["simulate", target?.revision, JSON.stringify(submitted)],
      retry: false,
      staleTime: 60_000
    }))
  });
  const [primary, secondary] = results;
  const changed = changedStages(primary?.data, secondary?.data);

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setSubmitted(input);
    setDown(new Set());
    setShowWhatIf(false);
    workspace.updateSearch(searchFromInput(input));
  }

  const toggleDown = (connection: string) => setDown((current) => { const next = new Set(current); if (next.has(connection)) next.delete(connection); else next.add(connection); return next; });
  return (
    <div className="lw-sim">
      <Card icon="simulator" title="Request">
        <form className="lw-sim-inputs" onSubmit={submit}>
          <InputsPanel features={features} input={input} onChange={onInput} plans={plans} />
          <div className="lw-row"><Button disabled={!run || !input.feature} icon="play" type="submit" variant="primary">Simulate</Button></div>
        </form>
      </Card>
      <div className="lw-sim-out">
        {!submitted ? <p className="lw-secondary lw-note">Set the inputs and select Simulate. Nothing is reserved and nothing is sent.</p> : null}
        {primary?.error ? <ProblemNotice problem={simulationProblem(primary.error)} /> : null}
        {submitted && primary?.isFetching && !primary.data ? <p role="status">Simulating…</p> : null}
        {primary?.data && submitted ? (
          <div className={`lw-sim-cols${versus ? " lw-sim-cols--2" : ""}`}>
            <Trace changed={versus ? changed : undefined} down={down} input={submitted} label={run?.label} onToggleDown={toggleDown} result={primary.data} />
            {versus ? (secondary?.data ? <Trace changed={changed} down={down} input={submitted} label={versus.label} result={secondary.data} /> : secondary?.error ? <ProblemNotice problem={simulationProblem(secondary.error)} /> : <p role="status">Simulating…</p>) : null}
          </div>
        ) : null}
        {primary?.data && submitted && run ? (
          <div className="lw-stack lw-stack--tight">
            <div className="lw-row">
              <Button onClick={() => setShowWhatIf((current) => !current)} size="sm">{showWhatIf ? "Hide What If" : "What If…"}</Button>
              <CopyButton className={buttonClass({ size: "sm" })} label="Copy as CLI" value={cliCommand(run.revision, submitted)}>Copy as CLI</CopyButton>
            </div>
            {showWhatIf ? <Card title="What if"><WhatIf input={submitted} onApply={(next) => { onInput(next); setSubmitted(next); setShowWhatIf(false); }} planValues={plans} result={primary.data} revision={run.revision} /></Card> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function gridValues(dimension: GridDimension, plans: readonly string[]): string[] {
  switch (dimension) {
    case "plan": return plans.slice(0, 5);
    case "platform": return ["ios", "android", "web", "react_native_ios", "react_native_android"];
    case "trust_level": return ["none", "identity_only", "web_risk_verified", "app_verified", "device_verified"];
    case "streaming": return ["off", "on"];
    case "size": return SIZE_PRESETS.map((item) => item.id);
  }
}

function applyGrid(input: SimulationInput, dimension: GridDimension, value: string): SimulationInput {
  switch (dimension) {
    case "plan": return { ...input, claims: { ...input.claims, plan: value } };
    case "platform": return { ...input, platform: value as Platform };
    case "trust_level": return { ...input, trustLevel: value as TrustLevel };
    case "streaming": return { ...input, streaming: value === "on" };
    case "size": return { ...input, size: SIZE_PRESETS.find((item) => item.id === value)?.size ?? input.size };
  }
}

function gridLabel(dimension: GridDimension, value: string): string {
  if (dimension === "platform") return PLATFORM_LABEL[value as Platform] ?? value;
  if (dimension === "trust_level") return TRUST_LABEL[value as TrustLevel] ?? value;
  if (dimension === "size") return SIZE_PRESETS.find((item) => item.id === value)?.label ?? value;
  return value;
}

function GridCell({ result, error }: { error?: unknown; result?: RouteSimulation }) {
  if (error) return <strong>Error</strong>;
  if (!result) return <span className="lw-faint">…</span>;
  if (!result.allowed) return <strong>{deniedAt(result) ? `Denied at ${STAGE_LABEL[deniedAt(result) as Stage]}` : "Denied"}</strong>;
  return <><strong>{result.model}</strong><Badge variant="soft">{result.limit_plan}</Badge></>;
}

function GridMode({ draft, input, onOpenCell, search, targets }: { draft: EnvironmentDraft; input: SimulationInput; onOpenCell: (input: SimulationInput) => void; search: RouteSimulatorRouteSearch; targets: ReturnType<typeof useTargets> }) {
  const workspace = useWorkspace();
  const run = targets.options.find((option) => option.id === (search.run ?? "live")) ?? targets.options[0];
  const versus = search.versus ? targets.options.find((option) => option.id === search.versus) : undefined;
  const x = search.grid_x ?? "plan";
  const y = search.grid_y ?? (x === "platform" ? "plan" : "platform");
  const plans = draft.document ? identifierValues(draft.document, "limitPlans") : [];
  const features = run?.document ? identifierValues(run.document, "features") : [];
  const [started, setStarted] = useState(false);
  const columns = gridValues(x, plans);
  const rows = gridValues(y, plans);
  const cells = rows.flatMap((row) => columns.map((column) => applyGrid(applyGrid(input, y, row), x, column)));
  const runCells = (target: typeof run) => cells.map((cell) => ({ enabled: Boolean(started && target), queryFn: () => simulate(target?.revision ?? "", cell), queryKey: ["simulate", target?.revision, JSON.stringify(cell)], retry: false, staleTime: 60_000 }));
  const primary = useQueries({ queries: runCells(run) });
  const secondary = useQueries({ queries: versus ? runCells(versus) : [] });
  const changedCount = versus ? cells.filter((_, index) => outcomeText(primary[index]?.data, primary[index]?.error) !== outcomeText(secondary[index]?.data, secondary[index]?.error)).length : 0;
  const pick = (key: "grid_x" | "grid_y", value: GridDimension) => { setStarted(false); workspace.updateSearch({ [key]: value }); };
  return (
    <div className="lw-sim-grid-wrap">
      <div className="lw-sim-grid-controls">
        <Field id="grid-feature" label="Feature"><select className="lw-select" id="grid-feature" onChange={(event) => { setStarted(false); onOpenCell({ ...input, feature: event.target.value }); }} value={input.feature}>{features.map((feature) => <option key={feature} value={feature}>{feature}</option>)}</select></Field>
        <Field id="grid-x" label="Columns"><select className="lw-select" id="grid-x" onChange={(event) => pick("grid_x", event.target.value as GridDimension)} value={x}>{GRID_DIMENSIONS.filter((value) => value !== y).map((value) => <option key={value} value={value}>{GRID_LABEL[value]}</option>)}</select></Field>
        <Field id="grid-y" label="Rows"><select className="lw-select" id="grid-y" onChange={(event) => pick("grid_y", event.target.value as GridDimension)} value={y}>{GRID_DIMENSIONS.filter((value) => value !== x).map((value) => <option key={value} value={value}>{GRID_LABEL[value]}</option>)}</select></Field>
      </div>
      <div className="lw-row"><Button disabled={!run || !input.feature || !columns.length} icon="play" onClick={() => setStarted(true)} variant="primary">Run {cells.length} Requests</Button></div>
      <p className="lw-secondary lw-note">Every cell is one simulated request using the rest of the Sample request inputs. The console sends one call per cell (at most 25); there's no batch endpoint yet.</p>
      {started && versus ? <p className="lw-note">{changedCount} of {cells.length} cells change from {run?.label} to {versus.label}.</p> : null}
      {started ? (
        <div className="lw-sim-grid-scroll">
          <table className="lw-sim-grid">
            <thead><tr><th>{GRID_LABEL[y]} \ {GRID_LABEL[x]}</th>{columns.map((column) => <th key={column}>{gridLabel(x, column)}</th>)}</tr></thead>
            <tbody>
              {rows.map((row, rowIndex) => (
                <tr key={row}>
                  <th>{gridLabel(y, row)}</th>
                  {columns.map((column, columnIndex) => {
                    const index = rowIndex * columns.length + columnIndex;
                    const differs = versus && outcomeText(primary[index]?.data, primary[index]?.error) !== outcomeText(secondary[index]?.data, secondary[index]?.error);
                    const denied = Boolean(primary[index]?.error) || primary[index]?.data?.allowed === false;
                    return (
                      <td key={column}>
                        <button className={`lw-sim-cell${denied ? " is-deny" : ""}${differs ? " is-changed" : ""}`} onClick={() => { const cell = cells[index]; if (cell) onOpenCell(cell); }} type="button">
                          <GridCell error={primary[index]?.error} result={primary[index]?.data} />
                          {differs ? <span className="lw-sim-cell__was">{outcomeText(secondary[index]?.data, secondary[index]?.error)}</span> : null}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

function EffectiveView({ effective, liveID }: { effective: EffectiveConfiguration; liveID?: string }) {
  const recorded = effective.evaluation_mode === "recorded_request";
  return (
    <div className="lw-stack">
      <div className={`lw-verdict lw-verdict--${effective.policy_outcome === "allowed" ? "ok" : effective.policy_outcome === "denied" ? "deny" : "warn"}`}>
        <Icon name={effective.policy_outcome === "allowed" ? "check" : "ban"} size={20} />
        <div><strong>{effective.policy_outcome === "allowed" ? "Allowed" : effective.policy_outcome === "denied" ? `Denied${effective.denial_reason ? ` · ${effective.denial_reason}` : ""}` : "Unavailable"}</strong>
        <span>{effective.limit_plan ? `${effective.limit_plan}${effective.limit_plan_source ? ` (${effective.limit_plan_source})` : ""}` : ""}{effective.selected_route ? ` · ${effective.selected_route.model} on ${effective.selected_route.upstream}` : ""}</span></div>
      </div>
      {recorded ? (
        <Notice tone={effective.revision_id === liveID ? "info" : "warning"}>
          {effective.revision_id === liveID ? "It ran on the revision that is still live." : <>It ran on <span className="lw-mono lw-mono--sm">{effective.revision_id}</span>; live is now <span className="lw-mono lw-mono--sm">{liveID ?? "nothing"}</span>. Run it as a Sample request to see today's result.</>}
        </Notice>
      ) : null}
      <Card icon="policies" title="Limits">
        {effective.limits.length ? <ul className="lw-issue-list lw-note">{effective.limits.map((limit) => <li key={limit.index}><LimitSentenceText limit={{ ...limit, perRequestMaximum: limit.per_request_maximum, refillPerSecond: limit.refill_per_second === undefined ? undefined : Number(limit.refill_per_second) }} /></li>)}</ul> : <p className="lw-faint lw-note">No limits apply.</p>}
        <p className="lw-secondary lw-note">How much of each limit is already used isn't returned by the Admin API.</p>
      </Card>
      <Card icon="split" title="Routes">
        <div className="lw-trace__route">
          {effective.routes.map((route) => <div className={`lw-trace__model${route.observed ? " is-chosen" : ""}`} key={route.order}><div className="lw-stack lw-stack--tight"><strong>{route.model} on {route.upstream}</strong><span className="lw-mono">{route.physical_model} · route {route.route}{route.observed ? " · used" : ""}</span></div></div>)}
        </div>
      </Card>
      {effective.decision_stages.length ? (
        <Card icon="requests" title="Recorded decision">
          <ol className="lw-trace">{effective.decision_stages.map((stage) => <li className={`lw-trace__step lw-trace__step--${stage.outcome === "succeeded" ? "pass" : "deny"}`} key={stage.number}><span className="lw-trace__dot"><Icon name={stage.outcome === "succeeded" ? "check" : "x"} size={12} /></span><div className="lw-trace__body"><div className="lw-trace__head"><strong>{RECORDED_STAGE_LABEL[stage.stage]}</strong></div>{stage.failure_code ? <span className="lw-trace__detail">{stage.failure_code}</span> : null}</div></li>)}</ol>
        </Card>
      ) : null}
      <Card icon="info" title="Inputs">
        <ul className="lw-issue-list lw-note">{effective.inputs.map((item) => <li key={item.fact}><strong>{item.fact}</strong> · {item.availability === "available" ? item.detail : <span className="lw-faint">{item.detail}</span>}</li>)}</ul>
      </Card>
      {effective.warnings.length ? <Notice tone="warning"><ul className="lw-issue-list">{effective.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></Notice> : null}
    </div>
  );
}

function UserMode({ draft, search }: { draft: EnvironmentDraft; search: RouteSimulatorRouteSearch }) {
  const workspace = useWorkspace();
  const environmentID = workspace.environment?.id ?? "";
  const features = draft.activeDocument ? identifierValues(draft.activeDocument, "features") : [];
  const feature = search.feature && features.includes(search.feature) ? search.feature : features[0] ?? "";
  const [typed, setTyped] = useState(search.user ?? "");
  const [error, setError] = useState<string>();
  const effective = useQuery({
    enabled: Boolean(search.user && feature && environmentID),
    queryFn: async () => (await adminRequest(queryPath(`/admin/v1/users/${search.user}/effective-configuration`, { environment_id: environmentID, feature, streaming: search.streaming ? "true" : undefined }), EffectiveConfigurationSchema)).data,
    queryKey: ["user", search.user, environmentID, "effective", feature, search.streaming ?? false],
    retry: false
  });
  function go(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!/^usr_[A-Za-z0-9_-]{16,128}$/.test(typed.trim())) return setError("Enter a user ID that starts with usr_.");
    setError(undefined);
    workspace.updateSearch({ feature, user: typed.trim() });
  }
  const denied = effective.data?.policy_outcome === "denied";
  return (
    <div className="lw-stack">
      <form className="lw-row lw-row--wrap" onSubmit={go}>
        <Field error={error} hint="Claims, platform and trust come from the user's latest installation, plus any plan override." id="sim-user" label="User ID"><Input id="sim-user" mono onChange={(event) => setTyped(event.target.value)} placeholder="usr_…" value={typed} /></Field>
        <Field id="sim-user-feature" label="Feature"><select className="lw-select" id="sim-user-feature" onChange={(event) => workspace.updateSearch({ feature: event.target.value })} value={feature}>{features.map((value) => <option key={value} value={value}>{value}</option>)}</select></Field>
        <Button icon="play" type="submit" variant="primary">Check User</Button>
      </form>
      <p className="lw-secondary lw-note">Runs against the live revision only.</p>
      {effective.error ? <ProblemNotice problem={problemFromError(effective.error)} /> : null}
      {effective.isFetching && !effective.data ? <p role="status">Checking…</p> : null}
      {effective.data ? <EffectiveView effective={effective.data} liveID={draft.active?.id} /> : null}
      {denied && !effective.data?.user_override_id && search.user ? <Link className={buttonClass()} search={(previous) => scoped(previous, { user: search.user })} to="/user-overrides">Override Plan</Link> : null}
    </div>
  );
}

function RequestMode({ draft, search }: { draft: EnvironmentDraft; search: RouteSimulatorRouteSearch }) {
  const workspace = useWorkspace();
  const [typed, setTyped] = useState(search.request ?? "");
  const [error, setError] = useState<string>();
  const effective = useQuery({
    enabled: Boolean(search.request),
    queryFn: async () => {
      const response = (await adminRequest(`/admin/v1/requests/${search.request}/effective-configuration`, EffectiveConfigurationSchema)).data;
      if (response.environment_id !== workspace.environment?.id) throw new Error("This request belongs to another environment.");
      return response;
    },
    queryKey: ["request", search.request, "effective"],
    retry: false
  });
  function go(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!/^req_[A-Za-z0-9_-]{16,128}$/.test(typed.trim())) return setError("Enter a request ID that starts with req_.");
    setError(undefined);
    workspace.updateSearch({ request: typed.trim() });
  }
  return (
    <div className="lw-stack">
      <form className="lw-row lw-row--wrap" onSubmit={go}>
        <Field error={error} hint="Explains a request from the revision it ran on and its recorded decision." id="sim-request" label="Request ID"><Input id="sim-request" mono onChange={(event) => setTyped(event.target.value)} placeholder="req_…" value={typed} /></Field>
        <Button icon="play" type="submit" variant="primary">Explain Request</Button>
      </form>
      {effective.error ? <ProblemNotice problem={effective.error instanceof Error && !("problem" in effective.error) ? { code: "context_mismatch", detail: effective.error.message, retryable: false, status: 0, title: "Request not in this environment" } : problemFromError(effective.error)} /> : null}
      {effective.isFetching && !effective.data ? <p role="status">Loading…</p> : null}
      {effective.data ? <EffectiveView effective={effective.data} liveID={draft.active?.id} /> : null}
      {effective.data ? <Link className="lw-link lw-note" search={(previous) => scoped(previous, { request: search.request })} to="/requests">Open the request</Link> : null}
    </div>
  );
}

function SimulatorView() {
  const workspace = useWorkspace();
  const draft = useEnvironmentDraft();
  const search = RouteSimulatorRouteSearchSchema.parse(workspace.search);
  const mode: Mode = search.mode ?? "sample";
  const targets = useTargets(draft, workspace.environment?.id ?? "");
  const run = targets.options.find((option) => option.id === (search.run ?? "live")) ?? targets.options[0];
  const features = run?.document ? specCollection(run.document, "features").map((feature) => String(feature.id)) : [];
  const [claims, setClaims] = useState<Record<string, string | boolean>>({ plan: "free" });
  const [override, setOverride] = useState<Omit<SimulationInput, "claims">>();
  const base = inputFromSearch(search, features);
  // An edit made before the revision loaded can't pin an empty or unknown feature.
  const input: SimulationInput = { ...(override ?? base), claims, feature: override?.feature && features.includes(override.feature) ? override.feature : base.feature };
  const setInput = (next: SimulationInput) => { const { claims: nextClaims, ...rest } = next; setClaims(nextClaims); setOverride(rest); };
  const targetPicker = (key: "run" | "versus", label: string, allowNone: boolean): ReactNode => (
    <Field id={`sim-${key}`} label={label}>
      <select className="lw-select" id={`sim-${key}`} onChange={(event) => workspace.updateSearch({ [key]: event.target.value || undefined })} value={(key === "run" ? search.run ?? "live" : search.versus) ?? ""}>
        {allowNone ? <option value="">Nothing</option> : null}
        {targets.options.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}
      </select>
    </Field>
  );
  return (
    <div className="lw-page">
      <PageHeader description="Exactly how a revision would handle a request: sign-in, app verification, access, limit plan, quota and route. Nothing is reserved and nothing is sent." title="Simulator" />
      <div className="lw-body lw-stack">
        <Segmented items={[{ id: "sample", label: "Sample request" }, { id: "user", label: "Real user" }, { id: "request", label: "Past request" }, { id: "grid", label: "Coverage grid" }]} label="Mode" onChange={(next) => workspace.updateSearch({ mode: next === "sample" ? undefined : next })} value={mode} />
        {mode === "sample" || mode === "grid" ? (
          <div className="lw-sim-runbar">
            {targetPicker("run", "Run against", false)}
            {targetPicker("versus", "Compare with", true)}
          </div>
        ) : null}
        {targets.draftNeedsCheck && (mode === "sample" || mode === "grid") ? <p className="lw-secondary lw-note">The draft can be simulated once it's checked and valid.</p> : null}
        {!targets.options.length && !draft.isPending ? <Notice tone="info">Nothing is live yet. Publish a configuration first.</Notice> : null}
        {mode === "sample" ? <SampleMode draft={draft} input={input} onInput={setInput} search={search} targets={targets} /> : null}
        {mode === "grid" ? <GridMode draft={draft} input={input} onOpenCell={(cell) => { setInput(cell); workspace.updateSearch({ ...searchFromInput(cell), mode: undefined }); }} search={search} targets={targets} /> : null}
        {mode === "user" ? <UserMode draft={draft} search={search} /> : null}
        {mode === "request" ? <RequestMode draft={draft} search={search} /> : null}
        <p className="lw-secondary lw-note">Saved scenarios aren't offered yet: the Admin API has nowhere to store them.</p>
      </div>
    </div>
  );
}

/** Operate → Simulator. */
export function SimulatorPage() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><SimulatorView key={`${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? "none"}`} /></EnvironmentRequired>;
}


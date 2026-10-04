import { useQueries, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type FormEvent, type ReactNode, useMemo, useState } from "react";
import { z } from "zod";

import { adminRequest, EffectiveConfigurationSchema, queryPath } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { UserOverrideResourceSchema, type UserOverrideResource } from "../../api/resources";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { LimitPlanRouteSearchSchema, OverrideRouteSearchSchema, PlanByFeatureRouteSearchSchema } from "../../app/route-search";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useOptionalWorkspace, useWorkspace } from "../../app/workspace-context-value";
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
  Properties
} from "../../ui";
import { DraftSaveNotice, StatePill } from "../build/collection-page";
import { type EnvironmentDraft, useEnvironmentDraft } from "../build/environment-draft";
import { accessSummary, identifierPattern, identifierValues, specCollection } from "../build/feature-model";
import { type ResourceRow, resourceRows, restoreResource } from "../build/resource-diff";
import { featuresCollection, replaceFeature } from "../build/routing-model";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { configurationAreas, deleteAreaResource, type JSONRecord, upsertAreaResource } from "../configuration-slice";
import { LimitCard, LimitSentenceText } from "./limit-editor";
import {
  featuresByPlan,
  isProtection,
  limitPlans,
  limitText,
  newLimit,
  organizationSpendLimit,
  planIssues,
  plansInExpression,
  strings,
  userSpendLimit
} from "./limit-model";
import { parseRules, replacePlanInExpression, rulesSentence } from "./plan-rules";
import { type PlanSelection, PlanRulesEditor } from "./plan-rules-editor";

const plansCollection = configurationAreas.limits.collections[0]!;

/** Signed in and scoped to an environment; local state resets when the application or environment changes. */
function PolicyScope({ children }: { children: (key: string) => ReactNode }) {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired>{children(`${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? ""}`)}</EnvironmentRequired>;
}

function CheckUserLink() {
  return <Link className={buttonClass()} search={(previous) => ({ application: previous.application, environment: previous.environment, mode: "user" as const, organization: previous.organization })} to="/route-simulator">Check a User</Link>;
}

function featureExpression(feature: JSONRecord): string {
  const plan = feature.limitPlan;
  return plan && typeof plan === "object" && !Array.isArray(plan) ? String((plan as JSONRecord).expression ?? "") : "";
}

function renameInFeatures(document: JSONRecord, from: string, to: string): JSONRecord {
  let next = document;
  for (const feature of specCollection(document, "features")) {
    const expression = featureExpression(feature);
    if (!plansInExpression(expression).includes(from)) continue;
    next = replaceFeature(next, String(feature.id), (value) => ({ ...value, limitPlan: { expression: replacePlanInExpression(expression, from, to) } }));
  }
  return next;
}

// ─── Limit plans ────────────────────────────────────────────────────────────

interface PlanDraftState {
  id: string;
  limits: JSONRecord[];
}

function PlanDrawer({ draft, onClose, onSaved, row }: { draft: EnvironmentDraft; onClose: () => void; onSaved: (id: string) => void; row?: ResourceRow }) {
  const published = Boolean(row?.live);
  const removing = row?.state === "removing";
  const [state, setState] = useState<PlanDraftState>(() => ({
    id: row?.key ?? "",
    limits: row ? (Array.isArray(row.value.limits) ? (row.value.limits as JSONRecord[]).map((limit) => ({ ...limit })) : []) : [newLimit()]
  }));
  const [copyOf, setCopyOf] = useState<string>();
  const [openIndex, setOpenIndex] = useState<number | undefined>(row ? undefined : 0);
  const [error, setError] = useState<string>();
  const [removingPlan, setRemovingPlan] = useState(false);
  const isNew = !row || Boolean(copyOf);
  const existing = draft.document ? identifierValues(draft.document, "limitPlans") : [];
  const issues = planIssues(state.limits);
  const idProblem = !identifierPattern.test(state.id) ? "Plan IDs use lowercase letters, digits, - or _, starting with a letter."
    : (isNew || state.id !== row?.key) && existing.includes(state.id) ? `A plan named ${state.id} already exists.` : undefined;
  const editable = draft.canConfigure && !removing;

  function setLimit(index: number, limit: JSONRecord): void {
    setState((current) => ({ ...current, limits: current.limits.map((value, position) => (position === index ? limit : value)) }));
  }

  function addLimit(limit: JSONRecord): void {
    setState((current) => ({ ...current, limits: [...current.limits, limit] }));
    setOpenIndex(state.limits.length);
  }

  async function save(): Promise<void> {
    if (idProblem) return setError(idProblem);
    if (issues.errors.length) {
      const first = issues.errors.find((issue) => issue.index !== undefined);
      if (first?.index !== undefined) setOpenIndex(first.index);
      return setError(`${issues.errors.length} problem${issues.errors.length === 1 ? "" : "s"} to fix first.`);
    }
    setError(undefined);
    const previous = isNew ? undefined : row?.key;
    const saved = await draft.save((document) => {
      let next = upsertAreaResource(document, plansCollection, previous, { id: state.id, limits: state.limits }).document;
      // An unpublished plan can be renamed; features that select it follow in the same draft.
      if (previous && previous !== state.id) next = renameInFeatures(next, previous, state.id);
      return next;
    });
    if (saved) onSaved(state.id);
  }

  const title = isNew ? (copyOf ? `Copy of ${copyOf}` : "New limit plan") : state.id;
  return (
    <>
      <DetailPanel
        actions={editable ? <>
          {row && !isNew && row.state !== "live" ? <Button onClick={() => void draft.save((document) => restoreResource(document, row, plansCollection)).then((saved) => { if (saved) onClose(); })} size="sm">{row.state === "new" ? "Remove from Draft" : "Undo Changes"}</Button> : null}
          {row && !isNew && row.state !== "new" ? <Button aria-label={`Remove ${row.key}`} destructive icon="trash" onClick={() => setRemovingPlan(true)} size="sm" variant="ghost" /> : null}
          {row && !isNew ? <Button onClick={() => { setCopyOf(row.key); setState((current) => ({ ...current, id: `${row.key}_copy` })); }} size="sm">Duplicate</Button> : null}
          <Button loading={draft.busy} onClick={() => void save()} size="sm" variant="primary">Save to Draft</Button>
        </> : removing && draft.canConfigure && row ? <Button onClick={() => void draft.save((document) => restoreResource(document, row, plansCollection)).then((saved) => { if (saved) onClose(); })} size="sm">Undo Remove</Button> : undefined}
        className="lw-request-drawer"
        mono
        onClose={onClose}
        subtitle={row && !isNew ? <><StatePill state={row.state} /><span className="lw-faint">{published ? "Published plan IDs are locked; features and overrides use them" : "Not published yet"}</span></> : <span className="lw-faint">Saved to the draft, not published</span>}
        title={title}
      >
        <div className="lw-stack">
          {removing ? <Notice title="Removed in the draft" tone="danger">It keeps applying until the draft is published. Undo Remove keeps it.</Notice> : null}
          {(isNew || !published) && editable ? (
            <Field error={state.id ? idProblem : undefined} hint={published ? undefined : "Features that select this plan follow a rename in the same draft."} id="plan-id" label="Plan ID">
              <Input id="plan-id" invalid={Boolean(state.id && idProblem)} mono onChange={(event) => setState((current) => ({ ...current, id: event.target.value }))} placeholder="premium" spellCheck={false} value={state.id} />
            </Field>
          ) : null}
          <div className="lw-row lw-row--spread"><strong className="lw-note">Limits</strong><span className="lw-faint lw-note">Every limit blocks the request when reached.</span></div>
          <ul className="lw-limits">
            {state.limits.map((limit, index) => (
              <LimitCard
                canRemove={state.limits.length > 1}
                editable={editable}
                index={index}
                key={index}
                limit={limit}
                onChange={(next) => setLimit(index, next)}
                onRemove={() => { setState((current) => ({ ...current, limits: current.limits.filter((_, position) => position !== index) })); setOpenIndex(undefined); }}
                onToggle={() => setOpenIndex((current) => (current === index ? undefined : index))}
                open={openIndex === index}
                problems={issues.errors.filter((issue) => issue.index === index).map((issue) => issue.message)}
              />
            ))}
          </ul>
          {editable ? <div><Button icon="plus" onClick={() => addLimit(newLimit())} size="sm">Add Limit</Button></div> : null}
          {issues.errors.filter((issue) => issue.index === undefined).map((issue) => (
            <Notice action={issue.fix && editable ? <Button onClick={() => addLimit(issue.fix === "spend" ? userSpendLimit() : organizationSpendLimit())} size="sm">Add It</Button> : undefined} key={issue.message} title="Fix before saving" tone="danger">{issue.message}</Notice>
          ))}
          {issues.warnings.map((issue) => (
            <Notice action={issue.fix && editable ? <Button onClick={() => addLimit(issue.fix === "spend" ? userSpendLimit() : organizationSpendLimit())} size="sm">Add It</Button> : undefined} key={issue.message} tone="info">{issue.message}</Notice>
          ))}
          {error ? <Notice title="Not saved" tone="danger">{error}</Notice> : null}
          {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
          <p className="lw-secondary lw-note">How many users a limit would stop isn't shown: the Admin API has no per-user usage aggregates yet.</p>
        </div>
      </DetailPanel>
      {removingPlan && row ? <RemovePlanDialog draft={draft} onClose={() => setRemovingPlan(false)} onRemoved={onClose} row={row} /> : null}
    </>
  );
}

function RemovePlanDialog({ draft, onClose, onRemoved, row }: { draft: EnvironmentDraft; onClose: () => void; onRemoved: () => void; row: ResourceRow }) {
  const users = featuresByPlan(draft.document).get(row.key) ?? [];
  const others = (draft.document ? identifierValues(draft.document, "limitPlans") : []).filter((plan) => plan !== row.key);
  const [targets, setTargets] = useState<Record<string, string>>(() => Object.fromEntries(users.map((feature) => [feature, others[0] ?? ""])));
  const [typed, setTyped] = useState("");
  const ready = typed === row.key && users.every((feature) => targets[feature]);

  async function remove(): Promise<void> {
    const saved = await draft.save((document) => {
      let next = document;
      for (const feature of users) {
        const target = targets[feature];
        if (!target) continue;
        const current = specCollection(next, "features").find((value) => value.id === feature);
        if (current) next = replaceFeature(next, feature, (value) => ({ ...value, limitPlan: { expression: replacePlanInExpression(featureExpression(current), row.key, target) } }));
      }
      return deleteAreaResource(next, plansCollection, row.key);
    });
    if (saved) { onClose(); onRemoved(); }
  }

  return (
    <ConfirmDialog confirmDisabled={!ready} confirmLabel={users.length ? "Reassign and Remove in Draft" : "Remove in Draft"} description="It keeps applying until the draft is published." destructive onCancel={onClose} onConfirm={() => void remove()} pending={draft.busy} size="wide" title={`Remove ${row.key}?`}>
      {users.length ? (
        <div className="lw-stack lw-stack--tight">
          <p className="lw-note">These features select {row.key}. Choose the plan each uses instead; the change goes into the same draft.</p>
          <ul className="lw-reassign">
            {users.map((feature) => (
              <li key={feature}>
                <span className="lw-mono lw-mono--sm">{feature}</span>
                <span aria-hidden="true">→</span>
                <select aria-label={`New plan for ${feature}`} className="lw-select lw-select--sm" onChange={(event) => setTargets((current) => ({ ...current, [feature]: event.target.value }))} value={targets[feature] ?? ""}>
                  {!others.length ? <option value="">No other plan</option> : null}
                  {others.map((plan) => <option key={plan} value={plan}>{plan}</option>)}
                </select>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <Notice tone="warning">Users with a plan override for {row.key} can't be listed: the Admin API has no override list. Check them under Overrides before publishing.</Notice>
      <Field id="remove-plan-confirm" label={<>Type <code className="lw-code-inline">{row.key}</code> to confirm</>}>
        <Input autoComplete="off" id="remove-plan-confirm" mono onChange={(event) => setTyped(event.target.value)} spellCheck={false} value={typed} />
      </Field>
      {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
    </ConfirmDialog>
  );
}

function LimitPlansView() {
  const workspace = useWorkspace();
  const draft = useEnvironmentDraft();
  const search = LimitPlanRouteSearchSchema.parse(workspace.search);
  const [creating, setCreating] = useState(false);
  const rows = useMemo(() => {
    try {
      return resourceRows(draft.activeDocument, draft.document, plansCollection);
    } catch {
      return [];
    }
  }, [draft.activeDocument, draft.document]);
  const byPlan = featuresByPlan(draft.document);
  const open = (plan: string | undefined) => workspace.updateSearch({ plan }, { replace: false });
  const openRow = search.plan ? rows.find((row) => row.key === search.plan) : undefined;
  const unused = rows.filter((row) => row.state !== "removing" && !byPlan.get(row.key)?.length);

  const columns: Array<Column<ResourceRow>> = [
    { header: "Plan", key: "plan", render: (row) => <span className="lw-name-cell"><span className={`lw-mono lw-mono--sm${row.state === "removing" ? " lw-struck" : ""}`}>{row.key}</span><StatePill state={row.state} /></span> },
    {
      header: "Limits",
      key: "limits",
      render: (row) => {
        const limits = Array.isArray(row.value.limits) ? (row.value.limits as JSONRecord[]) : [];
        return <span className="lw-stack lw-stack--tight lw-note">{limits.slice(0, 2).map((limit, index) => <LimitSentenceText key={index} limit={limit} />)}{limits.length > 2 ? <span className="lw-faint">+{limits.length - 2} more</span> : null}</span>;
      }
    },
    { header: "Used by", key: "features", render: (row) => byPlan.get(row.key)?.length ? <span className="lw-mono lw-mono--sm">{byPlan.get(row.key)?.join(", ")}</span> : <span className="lw-faint">No feature</span> },
    { align: "right", header: "Protections", key: "protections", render: (row) => (Array.isArray(row.value.limits) ? (row.value.limits as JSONRecord[]).filter(isProtection).length : 0) || <span className="lw-faint">0</span> }
  ];

  return (
    <div className="lw-page lw-collection">
      <PageHeader
        actions={<div className="lw-row"><CheckUserLink />{draft.canConfigure ? <Button icon="plus" onClick={() => { setCreating(true); open(undefined); }} variant="primary">New Plan</Button> : null}</div>}
        description="How much each user, device and feature can use. Each feature picks a plan; a user's override wins over that choice."
        title="Limit plans"
      />
      <DraftSaveNotice draft={draft} />
      {unused.length && rows.length > 1 ? <div className="lw-page-notice"><Notice tone="info">No feature selects {unused.map((row) => row.key).join(", ")}. Overrides can still use {unused.length === 1 ? "it" : "them"}.</Notice></div> : null}
      {draft.isPending ? <p className="lw-page-status" role="status">Loading configuration…</p> : rows.length ? (
        <DataTable caption="Limit plans" columns={columns} onSelect={(row) => { setCreating(false); open(row.key); }} rowKey={(row) => row.key} rows={rows} selectedKey={search.plan} />
      ) : draft.document ? <div className="lw-page-empty"><EmptyState icon="policies" orientation="horizontal" title="No limit plans yet">Every feature needs a plan. Create one to say how much each user can use.</EmptyState></div> : null}
      {!draft.canConfigure && draft.document ? <p className="lw-secondary lw-note lw-page-foot">View only: changing plans needs the <code className="lw-code-inline">activate_configuration</code> capability.</p> : null}
      {search.plan && !draft.isPending && draft.document && !openRow ? <div className="lw-page-notice"><Notice title="Plan not found" tone="danger">The configuration has no plan named <code className="lw-code-inline">{search.plan}</code>. No other plan was opened instead.</Notice></div> : null}
      {creating || openRow ? (
        <div className="lw-drawer-dock lw-drawer-dock--wide">
          <PlanDrawer draft={draft} key={creating ? "new" : openRow?.key} onClose={() => { setCreating(false); open(undefined); }} onSaved={(id) => { setCreating(false); open(id); }} row={creating ? undefined : openRow} />
        </div>
      ) : null}
    </div>
  );
}

// ─── Plan by feature ────────────────────────────────────────────────────────

function PlanSelectionDrawer({ draft, feature, onClose }: { draft: EnvironmentDraft; feature: JSONRecord; onClose: () => void }) {
  const expression = featureExpression(feature);
  const plans = draft.document ? identifierValues(draft.document, "limitPlans") : [];
  const [selection, setSelection] = useState<PlanSelection>({ expression, problems: [] });
  const [error, setError] = useState<string>();
  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!selection.expression) return setError("Choose a plan.");
    if (selection.problems.length) return setError(selection.problems.join(" "));
    setError(undefined);
    const saved = await draft.save((document) => replaceFeature(document, String(feature.id), (value) => ({ ...value, limitPlan: { expression: selection.expression } })));
    if (saved) onClose();
  }
  return (
    <DetailPanel className="lw-request-drawer" mono onClose={onClose} subtitle={<span className="lw-faint">Which plan applies to whom</span>} title={String(feature.id)}>
      <form className="lw-stack" onSubmit={(event) => void save(event)}>
        <PlanRulesEditor expression={expression} idPrefix="plan-selection" onChange={setSelection} plans={plans} />
        {error ? <Notice title="Not saved" tone="danger">{error}</Notice> : null}
        {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
        <p className="lw-secondary lw-note">Each rule's share of requests isn't shown: the Admin API has no projection of plan selection over traffic.</p>
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!draft.canConfigure} loading={draft.busy} type="submit" variant="primary">Save to Draft</Button></div>
      </form>
    </DetailPanel>
  );
}

function PlanByFeatureView() {
  const workspace = useWorkspace();
  const draft = useEnvironmentDraft();
  const search = PlanByFeatureRouteSearchSchema.parse(workspace.search);
  const rows = useMemo(() => {
    try {
      return resourceRows(draft.activeDocument, draft.document, featuresCollection);
    } catch {
      return [];
    }
  }, [draft.activeDocument, draft.document]);
  const open = (feature: string | undefined) => workspace.updateSearch({ feature }, { replace: false });
  const openRow = search.feature ? rows.find((row) => row.key === search.feature && row.state !== "removing") : undefined;
  const columns: Array<Column<ResourceRow>> = [
    { header: "Feature", key: "feature", render: (row) => <span className="lw-name-cell"><span className={`lw-mono lw-mono--sm${row.state === "removing" ? " lw-struck" : ""}`}>{row.key}</span><StatePill state={row.state} /></span> },
    { header: "Who can call it", key: "access", render: (row) => accessSummary(row.value) },
    {
      header: "Plan selection",
      key: "selection",
      render: (row) => {
        const rules = parseRules(featureExpression(row.value));
        return rules ? <span className="lw-note">{rulesSentence(rules)}</span> : <code className="lw-code-inline lw-clamp">{featureExpression(row.value) || "—"}</code>;
      }
    },
    { header: "Plans", key: "plans", render: (row) => <span className="lw-tags-inline">{plansInExpression(featureExpression(row.value)).map((plan) => <Badge key={plan} variant="soft">{plan}</Badge>)}</span> }
  ];
  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={<CheckUserLink />} description="Which plan each feature selects for whom. Rules run in order; the first match wins." title="Plan by feature" />
      <DraftSaveNotice draft={draft} />
      {draft.isPending ? <p className="lw-page-status" role="status">Loading configuration…</p> : rows.length ? (
        <DataTable caption="Plan by feature" columns={columns} onSelect={(row) => { if (row.state !== "removing") open(row.key); }} rowKey={(row) => row.key} rows={rows} selectedKey={search.feature} />
      ) : draft.document ? <div className="lw-page-empty"><EmptyState icon="features" orientation="horizontal" title="No features yet">Add a feature under Build → Features first.</EmptyState></div> : null}
      {openRow ? <div className="lw-drawer-dock lw-drawer-dock--wide"><PlanSelectionDrawer draft={draft} feature={openRow.value} key={openRow.key} onClose={() => open(undefined)} /></div> : null}
    </div>
  );
}

// ─── Overrides ──────────────────────────────────────────────────────────────

const ENDS = [["never", "No expiry"], ["1d", "24 hours"], ["7d", "7 days"], ["30d", "30 days"], ["date", "Pick a date"]] as const;
type Ends = (typeof ENDS)[number][0];
const wallClock = (): number => Date.now();

function expiry(ends: Ends, picked: string, now: number): string | undefined | null {
  if (ends === "never") return undefined;
  if (ends === "date") {
    const date = new Date(picked);
    return Number.isNaN(date.getTime()) || date.getTime() <= now ? null : date.toISOString();
  }
  return new Date(now + Number(ends.slice(0, -1)) * 86_400_000).toISOString();
}

function OverrideForm({ draft, onApplied, user }: { draft: EnvironmentDraft; onApplied: (user: UserOverrideResource, message: string) => void; user: UserOverrideResource }) {
  const workspace = useWorkspace();
  const livePlans = draft.activeDocument ? identifierValues(draft.activeDocument, "limitPlans") : [];
  const draftOnly = (draft.document ? identifierValues(draft.document, "limitPlans") : []).filter((plan) => !livePlans.includes(plan));
  const [plan, setPlan] = useState(user.limit_plan_override?.limit_plan ?? livePlans[0] ?? "");
  const [reason, setReason] = useState("");
  const [ends, setEnds] = useState<Ends>("7d");
  const [picked, setPicked] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const environmentID = workspace.environment?.id ?? "";
  const livePlan = limitPlans(draft.activeDocument).find((candidate) => candidate.id === plan);
  const features = specCollection(draft.activeDocument ?? {}, "features").slice(0, 12).map((feature) => String(feature.id));
  const now = useQueries({
    queries: features.map((feature) => ({
      queryFn: async () => (await adminRequest(queryPath(`/admin/v1/users/${user.id}/effective-configuration`, { environment_id: environmentID, feature }), EffectiveConfigurationSchema)).data,
      queryKey: ["user", user.id, environmentID, "effective", feature],
      retry: false
    }))
  });

  async function apply(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const expiresAt = expiry(ends, picked, wallClock());
    const trimmed = reason.trim();
    if (!livePlans.includes(plan)) return setError("Choose a plan from the live configuration.");
    if (!trimmed || reason.length > 500) return setError("Give a reason of 1 to 500 characters.");
    if (expiresAt === null) return setError("Pick an end date in the future.");
    setError(undefined);
    setBusy(true);
    setProblem(undefined);
    try {
      const updated = (await adminRequest(queryPath(`/admin/v1/users/${user.id}/limit-override`, { environment_id: environmentID }), UserOverrideResourceSchema, { body: { limit_plan: plan, reason: trimmed, ...(expiresAt ? { expires_at: expiresAt } : {}) }, method: "PUT" })).data;
      if (updated.id !== user.id || updated.environment_id !== environmentID) throw new Error("The server returned a different user.");
      const same = updated.limit_plan_override?.id && updated.limit_plan_override.id === user.limit_plan_override?.id;
      onApplied(updated, same ? "No change: the same override was already in place." : `Override applied. ${plan} is live for this user now.`);
      setReason("");
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="lw-stack" onSubmit={(event) => void apply(event)}>
      <Notice title="Applies immediately" tone="warning">An override skips the draft and Publish. It's live the moment you apply it, and it's written to the audit log.</Notice>
      <Field hint="Only plans in the live configuration can be used." id="override-plan" label="Plan">
        <select className="lw-select" id="override-plan" onChange={(event) => setPlan(event.target.value)} value={plan}>
          {livePlans.map((value) => <option key={value} value={value}>{value}</option>)}
          {draftOnly.map((value) => <option disabled key={value} value={value}>{value} (only in the draft; publish first)</option>)}
        </select>
      </Field>
      <div>
        <strong className="lw-note">What changes</strong>
        <table className="lw-mini-table">
          <thead><tr><th>Feature</th><th>Now</th><th>After</th></tr></thead>
          <tbody>
            {features.map((feature, index) => {
              const result = now[index];
              const current = result?.data;
              return (
                <tr key={feature}>
                  <td className="lw-mono lw-mono--sm">{feature}</td>
                  <td>{result?.isPending ? <span className="lw-faint">Loading…</span> : current ? <>{current.limit_plan ?? <span className="lw-faint">{current.policy_outcome}</span>}{current.limit_plan_source ? <span className="lw-faint"> · {current.limit_plan_source}</span> : null}</> : <span className="lw-faint">Unavailable</span>}</td>
                  <td><strong>{plan || "—"}</strong></td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {livePlan && Array.isArray(livePlan.limits) ? <ul className="lw-issue-list lw-note">{(livePlan.limits as JSONRecord[]).map((limit, index) => <li key={index}>{limitText(limit)}</li>)}</ul> : null}
      </div>
      <Field hint={<>{reason.length}/500 · Don&apos;t paste tokens, keys or anything the user wrote.</>} id="override-reason" label="Reason">
        <textarea className="lw-textarea" id="override-reason" maxLength={500} onChange={(event) => setReason(event.target.value)} rows={2} value={reason} />
      </Field>
      <Field id="override-ends" label="Ends">
        <select className="lw-select" id="override-ends" onChange={(event) => setEnds(event.target.value as Ends)} value={ends}>{ENDS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
      </Field>
      {ends === "date" ? <Field id="override-date" label="End date and time"><Input id="override-date" onChange={(event) => setPicked(event.target.value)} type="datetime-local" value={picked} /></Field> : null}
      {error ? <Notice title="Not applied" tone="danger">{error}</Notice> : null}
      {problem ? <ProblemNotice problem={problem} /> : null}
      <div className="lw-row"><Button icon="bolt" loading={busy} type="submit" variant="primary">Apply Now</Button></div>
    </form>
  );
}

function OverridesView() {
  const workspace = useWorkspace();
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const draft = useEnvironmentDraft();
  const search = OverrideRouteSearchSchema.parse(workspace.search);
  const environmentID = workspace.environment?.id ?? "";
  const capabilities = session.data?.session?.capabilities ?? [];
  const canInspect = capabilities.includes("inspect_users");
  const canApply = compatibility.mutationAllowed && capabilities.includes("activate_configuration") && workspace.application?.status !== "disabled" && workspace.environment?.status !== "disabled";
  const [typed, setTyped] = useState(search.user ?? "");
  const [goError, setGoError] = useState<string>();
  const [message, setMessage] = useState<{ text: string; userID: string }>();
  const [clearing, setClearing] = useState(false);
  const [clearProblem, setClearProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const user = useQuery({
    enabled: Boolean(search.user && environmentID && canInspect),
    queryFn: async () => {
      const response = (await adminRequest(queryPath(`/admin/v1/users/${search.user}`, { environment_id: environmentID }), UserOverrideResourceSchema)).data;
      if (response.id !== search.user || response.environment_id !== environmentID) throw new Error("The user didn't match the selected environment.");
      return response;
    },
    queryKey: ["user", search.user, environmentID, "override"],
    retry: false
  });
  const current = user.data;

  function go(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const value = typed.trim();
    if (!/^usr_[A-Za-z0-9_-]{16,128}$/.test(value)) return setGoError("Enter a user ID that starts with usr_. Emails and sign-in subjects are never stored, so they can't be searched.");
    setGoError(undefined);
    setMessage(undefined);
    workspace.updateSearch({ user: value }, { replace: false });
  }

  async function clear(): Promise<void> {
    if (!current) return;
    setBusy(true);
    setClearProblem(undefined);
    try {
      await adminRequest(queryPath(`/admin/v1/users/${current.id}/limit-override`, { environment_id: environmentID }), z.undefined(), { method: "DELETE" });
      setClearing(false);
      setMessage({ text: "Override cleared. The user's claims pick the plan again.", userID: current.id });
      await user.refetch();
    } catch (failure) {
      setClearProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  const override = current?.limit_plan_override;
  return (
    <div className="lw-page">
      <PageHeader actions={<CheckUserLink />} description="Per-user exceptions for support and incidents, such as premium until a date. Overrides are live, not drafted." title="Overrides" />
      <div className="lw-page-notice"><Notice tone="warning">Changes here apply immediately and never appear in the draft.</Notice></div>
      <div className="lw-body lw-stack">
        {!canInspect ? <Notice title="Capability required" tone="info">Looking up users needs the <code className="lw-code-inline">inspect_users</code> capability.</Notice> : (
          <form className="lw-row lw-row--wrap" onSubmit={go}>
            <Field error={goError} hint="The Admin API can't list users with overrides, so open one by ID (from Users & Installs or a request)." id="override-user" label="User ID">
              <Input id="override-user" mono onChange={(event) => setTyped(event.target.value)} placeholder="usr_…" spellCheck={false} value={typed} />
            </Field>
            <Button type="submit">Open</Button>
          </form>
        )}
        {user.error ? <ProblemNotice problem={problemFromError(user.error)} /> : null}
        {user.isFetching && !current ? <p className="lw-page-status" role="status">Loading user…</p> : null}
        {current ? (
          <div className="lw-hgrid lw-hgrid--2">
            <div className="lw-stack">
              <Card icon="users" title="User">
                <Properties columns={2} items={[
                  { label: "User", value: <span className="lw-mono lw-mono--sm">{current.id}</span> },
                  { label: "Status", value: current.status === "blocked" ? <Badge color="red" variant="soft">Blocked</Badge> : "Active" },
                  { label: "Override", value: override ? <strong>{override.limit_plan}</strong> : <span className="lw-faint">None: the user's claims pick the plan</span> },
                  { label: "Ends", value: override ? (override.expires_at ? new Date(override.expires_at).toLocaleString() : "No expiry") : "—" },
                  ...(override ? [{ label: "Reason", value: override.reason }, { label: "Set", value: new Date(override.created_at).toLocaleString() }] : [])
                ]} />
                <div className="lw-row">
                  {override && canApply ? <Button destructive onClick={() => setClearing(true)} size="sm">Clear Override</Button> : null}
                  <Link className={buttonClass({ size: "sm", variant: "ghost" })} search={(previous) => ({ application: previous.application, environment: previous.environment, organization: previous.organization, resource_id: current.id })} to="/audit">Override history in Audit Log</Link>
                </div>
              </Card>
              {message?.userID === current.id ? <Notice tone="success">{message.text}</Notice> : null}
              {current.status === "blocked" ? <Notice tone="info">An override changes limits only; it doesn't unblock the user.</Notice> : null}
            </div>
            {canApply ? <OverrideForm draft={draft} key={`${current.id}:${override?.id ?? "none"}`} onApplied={(updated, text) => { setMessage({ text, userID: updated.id }); void user.refetch(); }} user={current} /> : <Notice title="View only" tone="info">Applying an override needs the <code className="lw-code-inline">activate_configuration</code> capability and an active application and environment.</Notice>}
          </div>
        ) : null}
      </div>
      {clearing && current ? (
        <ConfirmDialog confirmLabel="Clear Override" description="The user's claims pick the plan again. Clearing doesn't bring back any earlier override." destructive onCancel={() => setClearing(false)} onConfirm={() => void clear()} pending={busy} title={`Clear the override for ${current.id}?`}>
          {clearProblem ? <ProblemNotice problem={clearProblem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

// ─── Protections ────────────────────────────────────────────────────────────

const PRESETS = [
  { amountLabel: "Requests per day", id: "installation", label: "Requests per installation", limit: (amount: number): JSONRecord => ({ algorithm: "calendar", hard: true, maximum: amount, metric: "logical_requests", scope: ["installation"], timezone: "UTC", window: "1d" }), value: 1000 },
  { amountLabel: "Tokens per day", id: "family", label: "Tokens per device family", limit: (amount: number): JSONRecord => ({ algorithm: "calendar", hard: true, maximum: amount, metric: "total_tokens", scope: ["installation_family"], timezone: "UTC", window: "1d" }), value: 500_000 },
  { amountLabel: "Burst size (refills 1 per second)", id: "trust", label: "Burst per trust source", limit: (amount: number): JSONRecord => ({ algorithm: "token_bucket", capacity: amount, hard: true, metric: "logical_requests", refillPerSecond: 1, scope: ["trust_source"] }), value: 60 }
] as const;

function AddProtectionDialog({ draft, onClose }: { draft: EnvironmentDraft; onClose: () => void }) {
  const plans = limitPlans(draft.document);
  const [preset, setPreset] = useState<(typeof PRESETS)[number]["id"]>("installation");
  const choice = PRESETS.find((candidate) => candidate.id === preset) ?? PRESETS[0];
  const [amount, setAmount] = useState(String(choice.value));
  const has = (plan: JSONRecord) => Array.isArray(plan.limits) && (plan.limits as JSONRecord[]).some(isProtection);
  const [selected, setSelected] = useState<string[]>(() => plans.filter((plan) => !has(plan)).map((plan) => String(plan.id)));
  const value = Number(amount);
  const valid = Number.isSafeInteger(value) && value > 0 && (preset !== "trust" || value <= 9_223_372);

  async function add(): Promise<void> {
    const limit = choice.limit(value);
    const saved = await draft.save((document) => {
      let next = document;
      for (const plan of limitPlans(document).filter((candidate) => selected.includes(String(candidate.id)))) {
        const limits = Array.isArray(plan.limits) ? (plan.limits as JSONRecord[]) : [];
        if (limits.some((existing) => limitText(existing) === limitText(limit))) continue;
        next = upsertAreaResource(next, plansCollection, String(plan.id), { ...plan, limits: [...limits, limit] }).document;
      }
      return next;
    });
    if (saved) onClose();
  }

  return (
    <ConfirmDialog confirmDisabled={!valid || !selected.length} confirmLabel="Add to Draft" onCancel={onClose} onConfirm={() => void add()} pending={draft.busy} size="wide" title="Add protection">
      <Field id="protection-preset" label="Protection">
        <select className="lw-select" id="protection-preset" onChange={(event) => { const next = PRESETS.find((candidate) => candidate.id === event.target.value) ?? PRESETS[0]; setPreset(next.id); setAmount(String(next.value)); }} value={preset}>
          {PRESETS.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.label}</option>)}
        </select>
      </Field>
      <Field error={amount && !valid ? "Enter a whole number above zero." : undefined} id="protection-amount" label={choice.amountLabel}><Input id="protection-amount" inputMode="numeric" onChange={(event) => setAmount(event.target.value)} value={amount} /></Field>
      {valid ? <p className="lw-note">Adds: <LimitSentenceText limit={choice.limit(value)} /></p> : null}
      <fieldset className="lw-fieldset">
        <legend>Add to plans</legend>
        {plans.map((plan) => (
          <label className="lw-check" key={String(plan.id)}>
            <input checked={selected.includes(String(plan.id))} onChange={(event) => setSelected((current) => (event.target.checked ? [...current, String(plan.id)] : current.filter((id) => id !== plan.id)))} type="checkbox" />
            <span><span className="lw-mono lw-mono--sm">{String(plan.id)}</span>{has(plan) ? <span className="lw-faint"> · already has a protection</span> : null}</span>
          </label>
        ))}
      </fieldset>
      {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
    </ConfirmDialog>
  );
}

function ProtectionsView() {
  const draft = useEnvironmentDraft();
  const [adding, setAdding] = useState(false);
  const plans = limitPlans(draft.document);
  const rows = plans.flatMap((plan) => (Array.isArray(plan.limits) ? (plan.limits as JSONRecord[]) : []).map((limit, index) => ({ index, limit, plan: String(plan.id) }))).filter((row) => isProtection(row.limit));
  const without = plans.filter((plan) => !rows.some((row) => row.plan === plan.id)).map((plan) => String(plan.id));
  const columns: Array<Column<(typeof rows)[number]>> = [
    { header: "Plan", key: "plan", render: (row) => <Link className="lw-link lw-mono lw-mono--sm" search={(previous) => ({ application: previous.application, environment: previous.environment, organization: previous.organization, plan: row.plan })} to="/limit-plans">{row.plan}</Link> },
    { header: "Limit", key: "limit", render: (row) => <LimitSentenceText limit={row.limit} /> },
    { header: "Counts", key: "scope", render: (row) => <span className="lw-faint">{strings(row.limit.scope).join(", ")}</span> }
  ];
  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={<div className="lw-row"><CheckUserLink />{draft.canConfigure && plans.length ? <Button icon="plus" onClick={() => setAdding(true)} variant="primary">Add Protection</Button> : null}</div>} description="Latchway has no hidden abuse engine. Protection is app verification, who can call each feature, and limits that count installations, device families, trust sources or components instead of users." title="Protections" />
      <DraftSaveNotice draft={draft} />
      {without.length && plans.length ? <div className="lw-page-notice"><Notice tone="warning">{without.join(", ")} {without.length === 1 ? "has" : "have"} no protection limit, so one device or installation can use a whole user's allowance many times over.</Notice></div> : null}
      {draft.isPending ? <p className="lw-page-status" role="status">Loading configuration…</p> : rows.length ? (
        <DataTable caption="Protection limits" columns={columns} rowKey={(row) => `${row.plan}/${row.index}`} rows={rows} />
      ) : draft.document ? <div className="lw-page-empty"><EmptyState icon="shield" orientation="horizontal" title="No protection limits">Add one to cap what a single installation, device family or trust source can use.</EmptyState></div> : null}
      <div className="lw-body"><p className="lw-secondary lw-note">App verification is under <Link className="lw-link" search={(previous) => ({ application: previous.application, environment: previous.environment, organization: previous.organization })} to="/attestation">Client Trust</Link>; who can call each feature is on the feature&apos;s Access &amp; limits tab.</p></div>
      {adding ? <AddProtectionDialog draft={draft} onClose={() => setAdding(false)} /> : null}
    </div>
  );
}

/** Policies & Limits → Limit plans. */
export function LimitPlansPage() { return <PolicyScope>{(key) => <LimitPlansView key={key} />}</PolicyScope>; }
/** Policies & Limits → Plan by feature. */
export function PlanByFeaturePage() { return <PolicyScope>{(key) => <PlanByFeatureView key={key} />}</PolicyScope>; }
/** Policies & Limits → Overrides. */
export function OverridesPage() { return <PolicyScope>{(key) => <OverridesView key={key} />}</PolicyScope>; }
/** Policies & Limits → Protections. */
export function ProtectionsPage() { return <PolicyScope>{(key) => <ProtectionsView key={key} />}</PolicyScope>; }

import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useRef, useState } from "react";

import { adminRequest, queryPath, type SelfTestRun, SelfTestSchema, type SelfTestSchedule, SelfTestSchedulePageSchema, SelfTestScheduleSchema } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { SelfTestRouteSearchSchema } from "../../app/route-search";
import { useAdminRefreshTopic } from "../../app/use-admin-refresh";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import { Badge, Button, Card, type Column, ConfirmDialog, DataTable, DetailPanel, EmptyState, Field, Input, Notice, PageHeader, Properties, Segmented, StatusBadge } from "../../ui";
import { useEnvironmentDraft } from "../build/environment-draft";
import { specCollection } from "../build/feature-model";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { dollarsToNano, nanoToDollars } from "../policies/limit-model";
import { OPERATIONS_HISTORY } from "../../api/operations-history";
import { SelfTestRuns } from "./operations-history";

type Kind = "local" | "upstream" | "openrouter";
const KIND_LABEL: Readonly<Record<Kind, string>> = { local: "Gateway check", openrouter: "OpenRouter conformance", upstream: "AI connection" };
const CADENCE = [["3600", "Every hour"], ["21600", "Every 6 hours"], ["86400", "Every day"], ["604800", "Every week"]] as const;

function mismatch(detail: string): AdminProblem {
  return { code: "context_mismatch", detail, retryable: true, status: 0, title: "Self-test context mismatch" };
}

function problemOf(error: unknown): AdminProblem {
  return error instanceof Error && !("problem" in error) ? mismatch(error.message) : problemFromError(error);
}

function runStatus(state: SelfTestRun["state"]) {
  return state === "passed" ? "passed" : state === "failed" ? "failed" : state === "canceled" ? "canceled" : "running";
}

/** Connections and their models in the live configuration, for choosing a test target. */
function useTargets() {
  const draft = useEnvironmentDraft();
  const document = draft.activeDocument;
  const connections = document ? specCollection(document, "upstreams").map((upstream) => String(upstream.id)) : [];
  const modelsOf = (connection: string) => (document ? specCollection(document, "models").filter((model) => model.upstream === connection).map((model) => String(model.id)) : []);
  return { active: draft.active, connections, modelsOf };
}

function TargetFields({ connection, model, onConnection, onModel, prefix }: { connection: string; model: string; onConnection: (value: string) => void; onModel: (value: string) => void; prefix: string }) {
  const targets = useTargets();
  const models = targets.modelsOf(connection);
  return (
    <div className="lw-form-grid">
      <Field id={`${prefix}-connection`} label="AI connection"><select className="lw-select" id={`${prefix}-connection`} onChange={(event) => { onConnection(event.target.value); onModel(targets.modelsOf(event.target.value)[0] ?? ""); }} required value={connection}><option value="">Choose a connection</option>{targets.connections.map((value) => <option key={value} value={value}>{value}</option>)}</select></Field>
      <Field id={`${prefix}-model`} label="Model"><select className="lw-select" id={`${prefix}-model`} onChange={(event) => onModel(event.target.value)} required value={model}><option value="">{models.length ? "Choose a model" : "No models on this connection"}</option>{models.map((value) => <option key={value} value={value}>{value}</option>)}</select></Field>
    </div>
  );
}

function RunCard({ canRun, onStarted }: { canRun: boolean; onStarted: (run: SelfTestRun) => void }) {
  const workspace = useWorkspace();
  const targets = useTargets();
  const [kind, setKind] = useState<Kind>("local");
  const [connection, setConnection] = useState("");
  const [model, setModel] = useState("");
  const [cost, setCost] = useState("0.01");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const environmentID = workspace.environment?.id ?? "";
  const maxCost = dollarsToNano(cost);

  async function start(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!canRun) return;
    setBusy(true);
    setProblem(undefined);
    try {
      const body: Record<string, string | number> = { environment_id: environmentID, kind };
      if (kind !== "local") {
        if (!targets.active) throw new Error("Nothing is live in this environment yet, so there's no connection to test.");
        if (!maxCost || maxCost > 1_000_000_000) throw new Error("Set a cost ceiling above $0 and at most $1.00.");
        Object.assign(body, { config_revision_id: targets.active.id, max_cost_nano_usd: maxCost, model, upstream: connection });
      }
      const created = (await adminRequest("/admin/v1/self-tests", SelfTestSchema, { body, method: "POST" })).data;
      if (created.environment_id !== environmentID || (kind !== "local" && created.config_revision_id !== body.config_revision_id)) throw new Error("The started self-test didn't match this environment and live revision.");
      onStarted(created);
    } catch (failure) {
      setProblem(problemOf(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card icon="selftest" title="Run a test">
      <form className="lw-stack" onSubmit={(event) => void start(event)}>
        <Segmented items={(Object.keys(KIND_LABEL) as Kind[]).map((id) => ({ id, label: KIND_LABEL[id] }))} label="Test" onChange={setKind} value={kind} />
        <p className="lw-secondary lw-note">{kind === "local" ? "Checks the gateway's own state: database, keys and jobs. Nothing is sent to a provider." : kind === "upstream" ? "Sends one bounded request through a connection in the live configuration, with its server-held key. It doesn't act as any of your users." : "Runs OpenRouter's conformance request through the live configuration."}</p>
        {kind !== "local" ? (
          <>
            <TargetFields connection={connection} model={model} onConnection={setConnection} onModel={setModel} prefix="run" />
            <Field error={cost && (!maxCost || maxCost > 1_000_000_000) ? "Between $0.000000001 and $1.00." : undefined} hint={targets.active ? `Runs against the live revision ${targets.active.id}. The server proves the ceiling before sending anything.` : "Nothing is live yet."} id="run-cost" label="Cost ceiling (USD)">
              <Input id="run-cost" inputMode="decimal" onChange={(event) => setCost(event.target.value)} value={cost} />
            </Field>
          </>
        ) : null}
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button disabled={!canRun || (kind !== "local" && (!connection || !model || !targets.active))} icon="play" loading={busy} type="submit" variant="primary">Run Test</Button></div>
        {!canRun ? <p className="lw-secondary lw-note">Running tests needs the <code className="lw-code-inline">run_self_tests</code> capability.</p> : null}
      </form>
    </Card>
  );
}

function RunDrawer({ environmentID, onClose, runID }: { environmentID: string; onClose: () => void; runID: string }) {
  const run = useQuery({
    queryFn: async () => {
      const response = (await adminRequest(queryPath(`/admin/v1/self-tests/${runID}`, { environment_id: environmentID }), SelfTestSchema)).data;
      if (response.id !== runID || response.environment_id !== environmentID) throw new Error("The self-test didn't match the selected run and environment.");
      return response;
    },
    queryKey: ["self-test", runID, environmentID],
    refetchInterval: (query) => (query.state.data && (query.state.data.state === "queued" || query.state.data.state === "running") ? 2000 : false),
    retry: false
  });
  const data = run.data;
  return (
    <DetailPanel className="lw-request-drawer" mono onClose={onClose} subtitle={data ? <><StatusBadge status={runStatus(data.state)}>{data.state}</StatusBadge><span className="lw-faint">{KIND_LABEL[data.kind]}</span></> : undefined} title={runID}>
      {run.error ? <ProblemNotice problem={problemOf(run.error)} /> : null}
      {data ? (
        <div className="lw-stack">
          <Properties columns={2} items={[
            { label: "Started", value: new Date(data.created_at).toLocaleString() },
            { label: "Finished", value: data.completed_at ? new Date(data.completed_at).toLocaleString() : "Still running" },
            ...(data.config_revision_id ? [{ label: "Revision", value: <span className="lw-mono lw-mono--sm">{data.config_revision_id}</span> }] : []),
            ...(data.schedule_id ? [{ label: "Schedule", value: <span className="lw-mono lw-mono--sm">{data.schedule_id}</span> }] : [])
          ]} />
          <table className="lw-mini-table">
            <thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
            <tbody>{data.checks.map((check, index) => <tr key={`${check.name}-${index}`}><td>{check.name}</td><td><Badge color={check.state === "passed" ? "success" : check.state === "failed" ? "red" : undefined} variant="soft">{check.state}</Badge></td><td className="lw-note">{check.safe_detail ?? "—"}</td></tr>)}</tbody>
          </table>
          <p className="lw-secondary lw-note">Details are redaction-safe: no keys, prompts or provider responses.</p>
        </div>
      ) : <p role="status">Loading…</p>}
    </DetailPanel>
  );
}

function ScheduleDrawer({ canRun, onClose, onCreated }: { canRun: boolean; onClose: () => void; onCreated: (schedule: SelfTestSchedule) => void }) {
  const workspace = useWorkspace();
  const token = useRef<HTMLInputElement>(null);
  const [kind, setKind] = useState<"upstream" | "openrouter">("upstream");
  const [connection, setConnection] = useState("");
  const [model, setModel] = useState("");
  const [perRun, setPerRun] = useState("0.01");
  const [perDay, setPerDay] = useState("0.24");
  const [cadence, setCadence] = useState("3600");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const environmentID = workspace.environment?.id ?? "";

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const bearer = token.current?.value ?? "";
    if (token.current) token.current.value = "";
    const maxCost = dollarsToNano(perRun);
    const daily = dollarsToNano(perDay);
    setProblem(undefined);
    if (!maxCost || maxCost > 1_000_000_000 || !daily || daily > 10_000_000_000 || daily < maxCost) return setProblem(mismatch("Per run is at most $1.00, per UTC day at most $10.00, and the day at least one run."));
    if (bearer.length < 32) return setProblem(mismatch("Paste an API token that can run self-tests."));
    setBusy(true);
    try {
      const created = (await adminRequest("/admin/v1/self-test-schedules", SelfTestScheduleSchema, { bearerToken: bearer, body: { daily_cost_limit_nano_usd: daily, environment_id: environmentID, interval_seconds: Number(cadence), kind, max_cost_nano_usd: maxCost, model, upstream: connection }, method: "POST" })).data;
      if (created.environment_id !== environmentID) throw new Error("The created schedule didn't match this environment.");
      onCreated(created);
    } catch (failure) {
      setProblem(problemOf(failure));
    } finally {
      if (token.current) token.current.value = "";
      setBusy(false);
    }
  }

  return (
    <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">Runs against the revision that is live when it&apos;s created</span>} title="New schedule">
      <form autoComplete="off" className="lw-stack" onSubmit={(event) => void submit(event)}>
        <Segmented items={[{ id: "upstream", label: "AI connection" }, { id: "openrouter", label: "OpenRouter conformance" }]} label="Test" onChange={setKind} value={kind} />
        <TargetFields connection={connection} model={model} onConnection={setConnection} onModel={setModel} prefix="schedule" />
        <div className="lw-form-grid">
          <Field id="schedule-run" label="Per run (USD)"><Input id="schedule-run" inputMode="decimal" onChange={(event) => setPerRun(event.target.value)} value={perRun} /></Field>
          <Field id="schedule-day" label="Per UTC day (USD)"><Input id="schedule-day" inputMode="decimal" onChange={(event) => setPerDay(event.target.value)} value={perDay} /></Field>
          <Field hint="Missed runs coalesce into one." id="schedule-cadence" label="How often"><select className="lw-select" id="schedule-cadence" onChange={(event) => setCadence(event.target.value)} value={cadence}>{CADENCE.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
        </div>
        <Field hint="A token with run_self_tests. It's sent once to bind the schedule to that token's ID, then cleared; the schedule stops if the token is revoked." id="schedule-token" label="API token">
          <div className="lw-input-box"><input autoComplete="off" className="lw-input lw-input--mono" id="schedule-token" maxLength={2048} minLength={32} name="authorization_token" ref={token} required type="password" /></div>
        </Field>
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!canRun || !connection || !model} loading={busy} type="submit" variant="primary">Create Schedule</Button></div>
      </form>
    </DetailPanel>
  );
}

function SelfTestsView() {
  const workspace = useWorkspace();
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const parsed = SelfTestRouteSearchSchema.safeParse(workspace.search);
  const search = parsed.success ? parsed.data : {};
  const environmentID = workspace.environment?.id ?? "";
  const canInspect = session.data?.session?.capabilities.includes("run_self_tests") ?? false;
  const canRun = canInspect && compatibility.mutationAllowed;
  const [creating, setCreating] = useState(false);
  const [disabling, setDisabling] = useState<SelfTestSchedule>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const scopeMismatch = Boolean(search.environment_id && search.environment_id !== environmentID);
  const schedules = useQuery({
    enabled: canInspect && Boolean(environmentID),
    queryFn: async () => {
      const page = (await adminRequest(queryPath("/admin/v1/self-test-schedules", { environment_id: environmentID }), SelfTestSchedulePageSchema)).data;
      if (page.items.some((schedule) => schedule.environment_id !== environmentID)) throw new Error("A schedule didn't belong to this environment.");
      return page.items;
    },
    queryKey: ["self-test-schedules", environmentID],
    retry: false
  });
  useAdminRefreshTopic("self_tests", () => { void schedules.refetch(); }, canInspect);
  const selectedSchedule = search.schedule_id ? schedules.data?.find((schedule) => schedule.id === search.schedule_id) : undefined;
  // A selection carries the environment it belongs to, so the link can't open it in another one.
  const open = (patch: { schedule_id?: string; self_test_id?: string }) => workspace.updateSearch({ environment_id: patch.schedule_id || patch.self_test_id ? environmentID : undefined, schedule_id: undefined, self_test_id: undefined, ...patch }, { replace: false });

  async function disable(schedule: SelfTestSchedule): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      const disabled = (await adminRequest(`/admin/v1/self-test-schedules/${schedule.id}`, SelfTestScheduleSchema, { method: "DELETE" })).data;
      if (disabled.id !== schedule.id || disabled.environment_id !== environmentID) throw new Error("The disabled schedule didn't match the selected one.");
      setDisabling(undefined);
      await schedules.refetch();
    } catch (failure) {
      setProblem(problemOf(failure));
    } finally {
      setBusy(false);
    }
  }

  const columns: Array<Column<SelfTestSchedule>> = [
    { header: "Target", key: "target", render: (schedule) => <span className="lw-rq-model"><span className="lw-mono lw-mono--sm">{schedule.model} on {schedule.upstream}</span><span className="lw-faint">{KIND_LABEL[schedule.kind]}</span></span> },
    { header: "How often", key: "cadence", render: (schedule) => <span className="lw-note">{CADENCE.find(([value]) => Number(value) === schedule.interval_seconds)?.[1] ?? `Every ${Math.round(schedule.interval_seconds / 3600)} h`}</span> },
    { header: "Cost ceiling", key: "cost", render: (schedule) => <span className="lw-note">{nanoToDollars(schedule.max_cost_nano_usd)} a run · {nanoToDollars(schedule.daily_cost_limit_nano_usd)} a day</span> },
    { header: "Next run", key: "next", render: (schedule) => <span className="lw-note">{schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleString() : "—"}</span> },
    { header: "Status", key: "status", render: (schedule) => schedule.status === "active" ? <Badge color="success" variant="soft">Active</Badge> : <Badge variant="soft">Disabled</Badge> }
  ];

  if (!canInspect) return <div className="lw-page"><PageHeader description="Bounded checks of the gateway and its AI connections." title="Self-tests" /><div className="lw-page-empty"><EmptyState icon="lock" orientation="horizontal" title="Capability needed">Self-tests need the <code className="lw-code-inline">run_self_tests</code> capability (Operator role or above).</EmptyState></div></div>;
  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={<Button disabled={!canRun} icon="plus" onClick={() => setCreating(true)} variant="primary">New Schedule</Button>} description="Bounded checks of the gateway and its AI connections in this environment, run now or on a schedule. Results never include keys, prompts or responses." title="Self-tests" />
      {scopeMismatch ? <div className="lw-page-notice"><Notice title="Different environment" tone="danger">The link is for another environment. No run or schedule was opened.</Notice></div> : null}
      {problem ? <div className="lw-page-notice"><ProblemNotice problem={problem} /></div> : null}
      <div className="lw-body"><RunCard canRun={canRun} onStarted={(run) => open({ self_test_id: run.id })} /></div>
      <div className="lw-body"><h2 className="lw-section-title">Schedules</h2></div>
      {schedules.error ? <div className="lw-page-notice"><ProblemNotice problem={problemOf(schedules.error)} /></div> : null}
      {schedules.isPending ? <p className="lw-page-status" role="status">Loading schedules…</p> : schedules.data?.length ? (
        <DataTable caption="Schedules" columns={columns} onSelect={(schedule) => open({ schedule_id: schedule.id })} rowKey={(schedule) => schedule.id} rows={schedules.data} selectedKey={search.schedule_id} />
      ) : <div className="lw-page-empty"><EmptyState icon="clock" orientation="horizontal" title="No schedules">Schedule a connection test to catch provider problems before your users do.</EmptyState></div>}
      {compatibility.status?.server_capabilities.includes(OPERATIONS_HISTORY) ? (
        <div className="lw-body lw-stack lw-stack--tight">
          <h2 className="lw-section-title">Recent runs</h2>
          <SelfTestRuns environmentID={environmentID} onOpen={(run) => open({ self_test_id: run.id })} selected={search.self_test_id} />
        </div>
      ) : <p className="lw-secondary lw-note lw-page-foot">This server returns a run only by its ID, so past runs aren&apos;t listed. Each schedule links to its latest run.</p>}
      {search.self_test_id && !scopeMismatch ? <div className="lw-drawer-dock lw-drawer-dock--wide"><RunDrawer environmentID={environmentID} key={search.self_test_id} onClose={() => open({})} runID={search.self_test_id} /></div> : null}
      {selectedSchedule && !scopeMismatch ? (
        <div className="lw-drawer-dock lw-drawer-dock--wide">
          <DetailPanel actions={canRun && selectedSchedule.status === "active" ? <Button destructive onClick={() => setDisabling(selectedSchedule)} size="sm">Disable</Button> : undefined} className="lw-request-drawer" mono onClose={() => open({})} subtitle={selectedSchedule.status === "active" ? <Badge color="success" variant="soft">Active</Badge> : <Badge variant="soft">Disabled</Badge>} title={selectedSchedule.id}>
            <div className="lw-stack">
              <Properties columns={2} items={[
                { label: "Target", value: `${KIND_LABEL[selectedSchedule.kind]}: ${selectedSchedule.model} on ${selectedSchedule.upstream}` },
                { label: "Pinned revision", value: <span className="lw-mono lw-mono--sm">{selectedSchedule.config_revision_id}</span> },
                { label: "Runs as token", value: <span className="lw-mono lw-mono--sm">{selectedSchedule.authorization_credential_id}</span> },
                { label: "Cost ceiling", value: `${nanoToDollars(selectedSchedule.max_cost_nano_usd)} a run · ${nanoToDollars(selectedSchedule.daily_cost_limit_nano_usd)} a UTC day` },
                { label: "Next run", value: selectedSchedule.next_run_at ? new Date(selectedSchedule.next_run_at).toLocaleString() : "Disabled" },
                { label: "Latest run", value: selectedSchedule.last_self_test_id ? <button className="lw-link lw-mono lw-mono--sm" onClick={() => open({ self_test_id: selectedSchedule.last_self_test_id })} type="button">{selectedSchedule.last_self_test_id}</button> : "None yet" }
              ]} />
              <p className="lw-secondary lw-note">A schedule keeps testing the revision it was created with. After publishing, create a new schedule to test the new live revision.</p>
            </div>
          </DetailPanel>
        </div>
      ) : null}
      {creating && canRun ? <div className="lw-drawer-dock lw-drawer-dock--wide"><ScheduleDrawer canRun={canRun} onClose={() => setCreating(false)} onCreated={(schedule) => { setCreating(false); void schedules.refetch(); open({ schedule_id: schedule.id }); }} /></div> : null}
      {disabling ? (
        <ConfirmDialog confirmLabel="Disable" description="It stops running. Past runs stay readable; a disabled schedule can't be turned back on, so create a new one if you need it again." destructive onCancel={() => setDisabling(undefined)} onConfirm={() => void disable(disabling)} pending={busy} title={`Disable ${disabling.model} on ${disabling.upstream}?`}>
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

/** Operate → Self-tests. */
export function SelfTestsPage() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><SelfTestsView /></EnvironmentRequired>;
}

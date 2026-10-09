import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { adminRequest, SelfTestSchema, type SelfTestRun } from "../../api/admin";
import { problemFromError, type AdminProblem } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useOptionalWorkspace } from "../../app/workspace-context-value";
import { Badge, Button, DetailPanel, Field, Notice, Properties, StatusBadge } from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { configurationAreas, type JSONRecord } from "../configuration-slice";
import { useConfigurationTask } from "../configuration-task";
import { ConnectionSetup, DevelopmentPath } from "../task-configuration-pages";
import { CollectionPage } from "./collection-page";
import { useEnvironmentDraft } from "./environment-draft";
import { specCollection } from "./feature-model";
import type { ResourceRow } from "./resource-diff";
import { routeRows } from "./routing-model";

const TYPE_LABEL: Readonly<Record<string, string>> = { anthropic: "Anthropic", generic: "Generic HTTP", openai_compatible: "OpenAI-compatible" };

function host(value: unknown): string {
  try {
    return new URL(String(value)).host;
  } catch {
    return String(value ?? "—");
  }
}

function credential(upstream: JSONRecord): string {
  const authentication = upstream.authentication;
  if (!authentication || typeof authentication !== "object") return "—";
  const auth = authentication as JSONRecord;
  if (auth.type === "none") return "No key";
  return typeof auth.secretRef === "string" ? `Key: ${auth.secretRef.replace(/^secret\//, "")}` : String(auth.type ?? "—");
}

/** A bounded live test of one connection and model against the live configuration. */
function ConnectionTest({ connectionID, models }: { connectionID: string; models: string[] }) {
  const task = useConfigurationTask();
  const [model, setModel] = useState(models[0] ?? "");
  const [result, setResult] = useState<SelfTestRun>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  async function run(): Promise<void> {
    if (!task.active || !task.environment) return;
    setBusy(true);
    setProblem(undefined);
    try {
      const response = (await adminRequest("/admin/v1/self-tests", SelfTestSchema, { body: { config_revision_id: task.active.id, environment_id: task.environment.id, kind: "upstream", max_cost_nano_usd: 10_000_000, model, upstream: connectionID }, method: "POST" })).data;
      if (response.environment_id !== task.environment.id || response.config_revision_id !== task.active.id) throw new Error("The test result didn't match the live configuration and environment.");
      setResult(response);
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      setBusy(false);
    }
  }
  if (!models.length) return <p className="lw-secondary lw-note">Add a model on this connection before testing it.</p>;
  return (
    <div className="lw-stack lw-stack--tight">
      <p className="lw-secondary lw-note">Sends a bounded request through the live configuration (at most $0.01). It doesn't act as any of your users.</p>
      <div className="lw-row">
        <Field id={`test-model-${connectionID}`} label="Model"><select className="lw-select" id={`test-model-${connectionID}`} onChange={(event) => setModel(event.target.value)} value={model}>{models.map((value) => <option key={value} value={value}>{value}</option>)}</select></Field>
        <Button disabled={!task.canRunSelfTests || !task.active} loading={busy} onClick={() => void run()} size="sm">Run Connection Test</Button>
      </div>
      {!task.canRunSelfTests ? <p className="lw-secondary lw-note">Running tests needs the <code className="lw-code-inline">run_self_tests</code> capability.</p> : null}
      {problem ? <ProblemNotice problem={problem} /> : null}
      {result ? <p className="lw-note">Test <code className="lw-code-inline">{result.id}</code>: <StatusBadge status={result.state === "passed" ? "passed" : result.state === "failed" ? "failed" : result.state === "canceled" ? "canceled" : "running"}>{result.state}</StatusBadge> <Link className="lw-link" search={(previous) => previous} to="/self-tests">Open Self-tests</Link></p> : null}
    </div>
  );
}

function ConnectionDetails({ document, row }: { document?: JSONRecord; row: ResourceRow }) {
  const models = document ? specCollection(document, "models").filter((model) => model.upstream === row.key) : [];
  const routes = routeRows(document).filter((route) => route.connection === row.key);
  return (
    <div className="lw-stack">
      <Properties columns={2} items={[
        { label: "Type", value: TYPE_LABEL[String(row.value.type)] ?? String(row.value.type) },
        { label: "Endpoint", value: <span className="lw-mono lw-mono--sm">{String(row.value.baseUrl ?? "—")}</span> },
        { label: "Credential", value: credential(row.value) },
        { label: "Models", value: models.length ? models.map((model) => `${String(model.id)} → ${String(model.upstreamModel)}`).join(", ") : <span className="lw-faint">None</span> }
      ]} />
      <div>
        <strong className="lw-note">Routes that use it</strong>
        {routes.length ? <ul className="lw-issue-list">{routes.map((route) => <li key={`${route.feature}/${String(route.route.id)}`}><span className="lw-mono lw-mono--sm">{route.feature}</span> · {route.order === 0 ? "first choice" : `backup ${route.order}`} · {route.model}</li>)}</ul> : <p className="lw-secondary lw-note">No feature routes to it yet.</p>}
      </div>
      {row.state === "live" || row.state === "edited" ? <ConnectionTest connectionID={row.key} models={models.map((model) => String(model.id))} /> : <p className="lw-secondary lw-note">It can be tested once the draft is published.</p>}
      <p className="lw-secondary lw-note">Prices and token accounting are under <Link className="lw-link" search={(previous) => previous} to="/models-pricing">Models &amp; pricing</Link>; keys under <Link className="lw-link" search={(previous) => previous} to="/secrets">Secrets</Link>.</p>
    </div>
  );
}

function ConnectionsView() {
  const draft = useEnvironmentDraft();
  const task = useConfigurationTask();
  const [adding, setAdding] = useState(false);
  const document = draft.document;
  return (
    <>
      <CollectionPage
        addAction={<Button disabled={!draft.canConfigure} icon="plus" onClick={() => setAdding(true)} variant="primary">Add Connection</Button>}
        definition={configurationAreas.upstreams}
        deleteBlockers={(row) => {
          const models = document ? specCollection(document, "models").filter((model) => model.upstream === row.key).map((model) => String(model.id)) : [];
          const routes = routeRows(document).filter((route) => route.connection === row.key);
          return [...new Set(routes.map((route) => `Feature ${route.feature} routes to ${route.model} on it`)), ...(models.length && !routes.length ? [`Models ${models.join(", ")} still point at it; remove them in Models & pricing`] : [])];
        }}
        description="Where requests go: each AI connection is a provider endpoint with a server-held key. Apps never see the key."
        draft={draft}
        drawerExtra={(row) => <ConnectionDetails document={document} row={row} />}
        extraColumns={() => [
          { header: "Type", key: "type", render: (row) => <Badge variant="soft">{TYPE_LABEL[String(row.value.type)] ?? String(row.value.type)}</Badge> },
          { header: "Endpoint", key: "endpoint", render: (row) => <span className="lw-mono lw-mono--sm">{host(row.value.baseUrl)}</span> },
          { header: "Credential", key: "credential", render: (row) => credential(row.value) },
          { align: "right", header: "Models", key: "models", render: (row) => document ? specCollection(document, "models").filter((model) => model.upstream === row.key).length : 0 },
          { align: "right", header: "Routes", key: "routes", render: (row) => routeRows(document).filter((route) => route.connection === row.key).length }
        ]}
        title="Connections"
      >
        {task.environment?.kind === "development" ? <div className="lw-page-notice"><DevelopmentPath task={task} /></div> : null}
      </CollectionPage>
      {adding ? (
        <div className="lw-drawer-dock lw-drawer-dock--wide">
          <DetailPanel className="lw-request-drawer" onClose={() => { setAdding(false); task.setDraft(undefined); }} subtitle={<span className="lw-faint">Saved to the draft; the key is stored right away and never returned</span>} title="Add connection">
            {task.problem ? <ProblemNotice problem={task.problem} /> : null}
            {!task.canConfigure ? <Notice tone="info">Adding a connection needs the activate_configuration capability and an active application and environment.</Notice> : null}
            <ConnectionSetup task={task} />
          </DetailPanel>
        </div>
      ) : null}
    </>
  );
}

function ConnectionsWorkspace() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  // Task-local state (typed values, secret resolution) resets whenever the application or environment changes.
  return <EnvironmentRequired><ConnectionsView key={`${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? "none"}`} /></EnvironmentRequired>;
}

/** Build → AI Connections → Connections. */
export function ConnectionWorkspacePage() {
  return <ConnectionsWorkspace />;
}

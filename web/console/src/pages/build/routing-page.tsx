import { useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";

import { useConsoleSession } from "../../api/session";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import { Badge, Card, type Column, DataTable, EmptyState, Notice, PageHeader, ProportionBar, Segmented, Toolbar } from "../../ui";
import { AccessRequired } from "../control-plane-pages";
import { DraftSaveNotice } from "./collection-page";
import { useEnvironmentDraft } from "./environment-draft";
import { fallbackText, type RouteRow, routeRows, whenText } from "./routing-model";

const COLORS = ["var(--accent-primary)", "var(--accent-subtle)", "var(--orange)", "var(--success)", "var(--grey)"];

function RoutingView() {
  const workspace = useWorkspace();
  const navigate = useNavigate();
  const draft = useEnvironmentDraft();
  const [order, setOrder] = useState<"all" | "first" | "backup">("all");
  const [connection, setConnection] = useState<string>();
  const rows = useMemo(() => routeRows(draft.document), [draft.document]);
  const connections = [...new Set(rows.map((row) => row.connection ?? "unknown"))].sort();
  const shown = rows.filter((row) => (order === "all" || (order === "first" ? row.order === 0 : row.order > 0)) && (!connection || (row.connection ?? "unknown") === connection));
  const firstChoices = rows.filter((row) => row.order === 0);
  const byConnection = new Map<string, number>();
  for (const row of firstChoices) byConnection.set(row.connection ?? "unknown", (byConnection.get(row.connection ?? "unknown") ?? 0) + 1);
  const features = [...new Set(rows.map((row) => row.feature))];
  const withoutBackup = features.filter((feature) => rows.filter((row) => row.feature === feature).length === 1);
  const openFeature = (feature: string) => void navigate({ search: { application: workspace.search.application, environment: workspace.search.environment, feature, organization: workspace.search.organization, tab: "routing" }, to: "/features" });

  const columns: Array<Column<RouteRow>> = [
    { header: "Feature", key: "feature", render: (row) => <span className="lw-mono lw-mono--sm">{row.feature}</span> },
    { header: "Order", key: "order", render: (row) => row.order === 0 ? <Badge color="accent" variant="soft">First choice</Badge> : <Badge variant="soft">Backup {row.order}</Badge> },
    { header: "Route", key: "route", render: (row) => <span className="lw-mono lw-mono--sm">{String(row.route.id)}</span> },
    { header: "Model on connection", key: "model", render: (row) => <span className="lw-rq-model"><span className="lw-mono">{row.model}</span><span className="lw-faint">{row.connection ?? "unknown connection"}</span></span> },
    { header: "When", key: "when", render: (row) => <code className="lw-code-inline">{whenText(row.route)}</code> },
    { header: "Switch on", key: "fallback", render: (row) => <span className="lw-secondary lw-note">{fallbackText(row.route)}</span> }
  ];

  return (
    <div className="lw-page lw-collection">
      <PageHeader description="Every feature's routes in one place. Routes are edited on each feature's Routing tab; select a row to open it." title="Routing" />
      <DraftSaveNotice draft={draft} />
      <div className="lw-body">
        {rows.length ? (
          <div className="lw-hgrid lw-hgrid--2">
            <Card icon="connections" meta="Counts features, not traffic" title="First choice by AI connection">
              <ProportionBar segments={[...byConnection.entries()].map(([name, count], index) => ({ color: COLORS[index % COLORS.length] ?? "var(--grey)", display: `${count} feature${count === 1 ? "" : "s"}`, key: name, label: name, value: count }))} showValues />
              <p className="lw-secondary lw-note">Request volume per connection is on Analytics, broken down by model.</p>
            </Card>
            <Card icon="alert" title="Features without a backup">
              {withoutBackup.length ? (
                <div className="lw-stack lw-stack--tight">
                  <p className="lw-note">If their only connection is down, every request to these features fails:</p>
                  <ul className="lw-tags-list">{withoutBackup.map((feature) => <li key={feature}><button className="lw-link lw-mono lw-mono--sm" onClick={() => openFeature(feature)} type="button">{feature}</button></li>)}</ul>
                </div>
              ) : <p className="lw-secondary lw-note">Every feature has at least one backup route.</p>}
            </Card>
          </div>
        ) : null}
      </div>
      <Toolbar className="lw-toolbar--wrap">
        <Segmented items={[{ id: "all", label: "All routes" }, { id: "first", label: "First choice" }, { id: "backup", label: "Backups" }]} label="Order" onChange={setOrder} value={order} />
        {connections.length > 1 ? <select aria-label="AI connection" className="lw-select lw-select--sm lw-select--inline" onChange={(event) => setConnection(event.target.value || undefined)} value={connection ?? ""}><option value="">Any AI connection</option>{connections.map((name) => <option key={name} value={name}>{name}</option>)}</select> : null}
      </Toolbar>
      {draft.isPending ? <p className="lw-page-status" role="status">Loading configuration…</p> : shown.length ? (
        <DataTable caption="Routes" columns={columns} onSelect={(row) => openFeature(row.feature)} rowKey={(row) => `${row.feature}/${String(row.route.id)}`} rows={shown} />
      ) : draft.document ? <div className="lw-page-empty"><EmptyState icon="split" orientation="horizontal" title="No routes match">Add a feature, or change the filters.</EmptyState></div> : null}
      {draft.document && rows.length ? <div className="lw-page-notice"><Notice tone="info">Latchway routes exactly as configured; it has no automatic ordering by price or latency.</Notice></div> : null}
    </div>
  );
}

function RoutingWorkspace() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><RoutingView /></EnvironmentRequired>;
}

/** Build → Routing: all features' routes, read from the working draft. */
export function RoutingPage() {
  return <RoutingWorkspace />;
}

import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCapabilities } from "../../app/permissions";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import {
  adminRequest,
  type ClientComponent,
  ClientComponentSchema,
  type InstallationFamily,
  InstallationFamilyPageSchema,
  InstallationFamilySchema,
  queryPath
} from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { InstallationFamilyRouteSearchSchema } from "../../app/route-search";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import {
  Badge,
  Button,
  type Column,
  DataTable,
  DetailPanel,
  EmptyState,
  FilterChip,
  ImpactDialog,
  Notice,
  PageHeader,
  Properties,
  Segmented,
  StatusBadge,
  Toolbar
} from "../../ui";
import { formatCount, formatMoney, recorded } from "../analytics/usage-model";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { capitalize, formatClock, formatUtc, PLATFORM_LABEL, shortId, TRUST_LABEL, words } from "../requests/request-format";
import { GoToForm } from "./go-to-form";
import { COMPONENT_STATUS_WORDS, componentSignals, DAY_MS, familySignals, KEY_STORAGE_LABEL, orderedParts, type Signal, signalBadgeColor } from "./users-model";

class FamilyContextMismatch extends Error {}

const FAMILY_MISMATCH: AdminProblem = { code: "invalid_response", detail: "The installation did not match the selected environment and identifiers.", retryable: true, status: 0, title: "Installation detail mismatch" };
const COMPONENT_MISMATCH: AdminProblem = { code: "invalid_response", detail: "The part did not belong to the selected installation and environment.", retryable: true, status: 0, title: "Component detail mismatch" };

type Operation =
  | { kind: "family-renewal" | "family-revoke" }
  | { component: ClientComponent; kind: "component-reverify" | "component-revoke" };

function familyStatus(status: InstallationFamily["status"]) {
  return status === "active" ? "active" : status === "revoked" ? "revoked" : "disabled";
}

function TrustCell({ family, now }: { family: InstallationFamily; now: number }) {
  const debug = family.root_trust_source === "debug";
  const expires = family.root_trust_expires_at ? Date.parse(family.root_trust_expires_at) : undefined;
  const soon = expires !== undefined && expires - now <= 7 * DAY_MS;
  return (
    <span className="lw-an-key">
      <span className={debug ? "lw-text-danger" : undefined}>{debug ? "Debug provider" : TRUST_LABEL[family.root_trust_source] ?? words(family.root_trust_source)}</span>
      {family.root_trust_expires_at ? <span className={soon ? "lw-text-warning" : "lw-faint"} title={formatUtc(family.root_trust_expires_at)}>expires {formatClock(family.root_trust_expires_at, now)}</span> : <span className="lw-faint">No expiry recorded</span>}
    </span>
  );
}

function SignalList({ canMutate, onAct, signals }: { canMutate: boolean; onAct: (signal: Signal) => void; signals: readonly Signal[] }) {
  if (!signals.length) return <p className="lw-secondary lw-note">No signals on this installation.</p>;
  return (
    <ul className="lw-intents">
      {signals.map((signal) => (
        <li key={signal.id}>
          <div><strong><Badge color={signalBadgeColor(signal.severity)} variant="soft">{signal.label}</Badge></strong><span>{signal.text}</span></div>
          {signal.action && canMutate ? <Button onClick={() => onAct(signal)} size="sm">{signal.action === "reverify-component" ? "Re-verify" : signal.action === "revoke-component" ? "Revoke Part" : "Revoke Installation"}</Button> : null}
        </li>
      ))}
    </ul>
  );
}

function PartCard({ canMutate, component, depth, familyActive, highlighted, now, onOperate }: { canMutate: boolean; component: ClientComponent; depth: number; familyActive: boolean; highlighted: boolean; now: number; onOperate: (operation: Operation) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (highlighted) ref.current?.scrollIntoView?.({ block: "nearest" });
  }, [highlighted]);
  const terminal = component.status === "revoked" || component.status === "replaced";
  const weak = componentSignals(component).some((signal) => signal.id.startsWith("storage-"));
  return (
    <div className={`lw-part${highlighted ? " is-highlighted" : ""}${depth ? " is-delegated" : ""}`} ref={ref} style={{ marginLeft: depth * 20 }}>
      <div className="lw-attempt__head">
        <strong>{component.definition_id}</strong>
        <span className="lw-mono">{component.id} · {words(component.kind)}{component.is_root ? " · root" : ""}</span>
        <StatusBadge status={component.status === "active" ? "active" : terminal ? "revoked" : "disabled"}>{COMPONENT_STATUS_WORDS[component.status]}</StatusBadge>
      </div>
      <Properties columns={2} items={[
        { label: "Key storage", value: <span className={weak ? "lw-text-warning" : undefined}>{KEY_STORAGE_LABEL[component.key_storage_claim]}</span> },
        { label: "App · SDK", value: `${component.app_version ?? "—"} · ${component.sdk_version ?? "—"}` },
        { label: "Trust", value: <span title={component.trust_expires_at ? formatUtc(component.trust_expires_at) : undefined}>{component.trust_source === "debug" ? <span className="lw-text-danger">Debug provider</span> : TRUST_LABEL[component.trust_source] ?? words(component.trust_source)}{component.trust_expires_at ? ` · until ${formatClock(component.trust_expires_at, now)}` : ""}</span> },
        { label: "Session", value: component.session_status ? `${capitalize(component.session_status)}${component.session_expires_at ? ` · until ${formatClock(component.session_expires_at, now)}` : ""}` : <span className="lw-faint">No session</span> },
        { label: "Delegated for", value: component.is_root ? "All of the app's features (root)" : component.granted_features.join(", ") || <span className="lw-faint">No features</span> },
        { label: "Failed sessions", value: component.session_failure_count.toLocaleString() },
        { label: "Refresh reused", value: component.refresh_reuse_count ? <span className="lw-text-danger">×{component.refresh_reuse_count}</span> : "Never" },
        { label: "Usage", value: `${formatCount(component.request_count)} requests · ${formatMoney(recorded(component.usage, "cost_nano_usd"))}` },
        ...(component.revocation_reason ? [{ label: "Revoked because", value: component.revocation_reason }] : [])
      ]} />
      {canMutate && !terminal ? (
        <div className="lw-row">
          <Button disabled={!familyActive || component.status !== "active"} onClick={() => onOperate({ component, kind: "component-reverify" })} size="sm">Re-verify</Button>
          <Button destructive onClick={() => onOperate({ component, kind: "component-revoke" })} size="sm">{component.is_root ? "Revoke Installation" : "Revoke"}</Button>
        </div>
      ) : null}
    </div>
  );
}

interface ReviewProps {
  environmentID: string;
  family: InstallationFamily;
  onClose: () => void;
  onDone: (family: InstallationFamily, message: string) => void;
  operation: Operation;
}

/** Installation and component actions have no server preview, so the counts come from the record as loaded. */
function OperationReview({ environmentID, family, onClose, onDone, operation }: ReviewProps) {
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const components = family.components ?? [];
  const descendants = (root: ClientComponent): ClientComponent[] => {
    const children = components.filter((candidate) => candidate.parent_component_id === root.id);
    return [root, ...children.flatMap(descendants)];
  };
  // Revoking a root part is revoking the installation.
  const target = "component" in operation && operation.component.is_root && operation.kind === "component-revoke" ? { kind: "family-revoke" as const } : operation;
  const reach = "component" in target ? descendants(target.component) : components;
  const live = reach.filter((component) => component.status === "active");
  const sessions = reach.filter((component) => component.session_status === "active").length;
  const copy = {
    "component-reverify": { ack: "I understand this part and its delegated parts must verify again before they can refresh.", confirm: "Require Re-verification", description: "Expires trust and refresh credentials for this part and the parts it delegated to. Access already issued lives only to its current expiry.", title: "Require re-verification", undo: "Nothing to undo: the app re-verifies on its next launch." },
    "component-revoke": { ack: "I understand this permanently revokes this part and the parts it delegated to.", confirm: "Revoke Part", description: "Revokes this part's key, its delegated parts, and their sessions and refresh tokens.", title: "Revoke this part", undo: "None. The app must provision a new part." },
    "family-renewal": { ack: "I understand the app must establish fresh trust before it can refresh or provision parts.", confirm: "Require Renewal", description: "Expires the installation's trust and refresh credentials. Access already issued lives only to its current expiry.", title: "Require renewal", undo: "Nothing to undo: the containing app renews its trust on its next launch." },
    "family-revoke": { ack: "I understand this permanently revokes the whole installation and every part of it.", confirm: "Revoke Installation", description: "Revokes the root, every delegated part, and every session and refresh token in this installation.", title: "Revoke this installation", undo: "None. The app must start a new installation." }
  }[target.kind];
  const targetID = "component" in target ? target.component.id : family.id;

  async function confirm(reason: string): Promise<void> {
    setPending(true);
    setProblem(undefined);
    try {
      const path = "component" in target
        ? `/admin/v1/client-components/${target.component.id}/${target.kind === "component-revoke" ? "revoke" : "require-reattestation"}`
        : `/admin/v1/installation-families/${family.id}/${target.kind === "family-revoke" ? "revoke" : "require-renewal"}`;
      if ("component" in target) {
        const result = await adminRequest(path, ClientComponentSchema, { body: { reason }, method: "POST" });
        if (result.data.id !== target.component.id || result.data.installation_family_id !== family.id || result.data.environment_id !== environmentID) throw new FamilyContextMismatch("component_context");
      } else {
        const result = await adminRequest(path, InstallationFamilySchema, { body: { reason }, method: "POST" });
        if (result.data.id !== family.id || result.data.environment_id !== environmentID) throw new FamilyContextMismatch("family_context");
      }
      const exact = await adminRequest(`/admin/v1/installation-families/${family.id}`, InstallationFamilySchema);
      if (exact.data.id !== family.id || exact.data.environment_id !== environmentID || !exact.data.components) throw new FamilyContextMismatch("family_context");
      onDone(exact.data, `${copy.title.replace("this ", "")} completed for ${targetID}.`);
    } catch (error) {
      const failure = error instanceof FamilyContextMismatch ? FAMILY_MISMATCH : problemFromError(error);
      setProblem(failure.code === "operation_indeterminate" ? { ...failure, detail: `${failure.detail} Check the audit log before retrying.` } : failure);
    } finally {
      setPending(false);
    }
  }

  return (
    <ImpactDialog
      acknowledgement={copy.ack}
      confirmLabel={copy.confirm}
      description={copy.description}
      facts={[["Takes effect", "Immediately after the server accepts it"], ["Undo", copy.undo]]}
      impacts={[{ count: reach.length, label: "parts" }, { count: live.length, label: "active parts" }, { count: sessions, label: "active sessions" }]}
      maxReason={100}
      minReason={1}
      onCancel={onClose}
      onConfirm={({ reason }) => void confirm(reason)}
      pending={pending}
      preserved={"component" in target ? "the root and any sibling parts" : "the user's other installations"}
      reasonHint="Stored on the record as its revocation reason (100 characters). Don't paste tokens or personal data."
      scope={<>Reach: <code className="lw-code-inline">{targetID}</code>{"component" in target ? " and the parts it delegated to" : " and every part of it"}</>}
      targetId={targetID}
      title={`${copy.title}?`}
    >
      <Notice title="Counts are from this installation as loaded" tone="info">The server has no preview for installation actions, so they aren't checked again before it runs.</Notice>
      {problem ? <ProblemNotice problem={problem} /> : null}
    </ImpactDialog>
  );
}

function FamilyDrawer({ canMutate, componentID, environmentKind, family, linkSearch, now, onClose, onOperate, outcome }: { canMutate: boolean; componentID?: string; environmentKind?: string; family: InstallationFamily; linkSearch: Record<string, string | undefined>; now: number; onClose: () => void; onOperate: (operation: Operation) => void; outcome?: string }) {
  const components = family.components ?? [];
  const signals = [...familySignals(family, environmentKind, now), ...components.flatMap(componentSignals)];
  const reused = components.filter((component) => component.refresh_reuse_count > 0);
  const active = family.status === "active";
  const act = (signal: Signal) => {
    const component = components.find((candidate) => candidate.id === signal.componentID);
    if (signal.action === "revoke-installation") onOperate({ kind: "family-revoke" });
    else if (component && signal.action === "revoke-component") onOperate({ component, kind: "component-revoke" });
    else if (component && signal.action === "reverify-component") onOperate({ component, kind: "component-reverify" });
  };
  return (
    <DetailPanel
      actions={canMutate && family.status !== "revoked" ? <>
        <Button disabled={!active} onClick={() => onOperate({ kind: "family-renewal" })} size="sm">Require Renewal</Button>
        <Button destructive onClick={() => onOperate({ kind: "family-revoke" })} size="sm">Revoke Installation</Button>
      </> : undefined}
      className="lw-request-drawer"
      mono
      onClose={onClose}
      sections={[
        ...(outcome ? [{ content: <Notice title="Done" tone="success">{outcome}</Notice> }] : []),
        { content: <SignalList canMutate={canMutate} onAct={act} signals={signals} />, title: "Signals" },
        {
          content: <>
            <Properties columns={2} items={[
              { label: "User", value: <Link className="lw-link lw-mono lw-mono--sm" search={{ ...linkSearch, user_id: family.user_id }} to="/users">{family.user_id}</Link> },
              { label: "Platform", value: PLATFORM_LABEL[family.platform] ?? words(family.platform) },
              { label: "Verified by", value: family.root_trust_source === "debug" ? <span className="lw-text-danger">Debug provider</span> : TRUST_LABEL[family.root_trust_source] ?? words(family.root_trust_source) },
              { label: "Trust expires", value: family.root_trust_expires_at ? <span title={formatUtc(family.root_trust_expires_at)}>{formatClock(family.root_trust_expires_at, now)}</span> : <span className="lw-faint">Not recorded</span> },
              { label: "Usage", value: `${formatCount(family.request_count)} requests · ${formatMoney(recorded(family.usage, "cost_nano_usd"))} recorded` },
              { label: "Installed", value: <span title={formatUtc(family.created_at)}>{formatClock(family.created_at, now)}</span> },
              { label: "Last seen", value: <span title={formatUtc(family.last_seen_at)}>{formatClock(family.last_seen_at, now)}</span> },
              ...(family.revocation_reason ? [{ label: "Revoked because", value: family.revocation_reason }] : [])
            ]} />
            <div><Link className="lw-link" search={{ ...linkSearch, user_id: family.user_id }} to="/requests">See this user's requests</Link></div>
          </>,
          title: "Installation"
        },
        {
          content: components.length ? <div className="lw-attempts">{orderedParts(components).map(({ component, depth }) => <PartCard canMutate={canMutate} component={component} depth={depth} familyActive={active} highlighted={component.id === componentID} key={component.id} now={now} onOperate={onOperate} />)}</div> : <p className="lw-secondary lw-note">The server returned no parts for this installation.</p>,
          title: `Parts of this installation (${family.component_count})`
        },
        {
          content: reused.length ? (
            <div className="lw-stack lw-stack--tight">
              <p className="lw-secondary lw-note">Latchway rotates refresh tokens on every use and never stores the token itself. A reused token means an old copy was presented again.</p>
              <ul className="lw-rank">
                {reused.map((component) => (
                  <li key={component.id}>
                    <span className="lw-an-key"><strong>{component.definition_id}</strong><span className="lw-faint lw-mono">{component.session_family_id ?? "No session family"}</span></span>
                    <span className="lw-text-danger">×{component.refresh_reuse_count}</span>
                    <Link className="lw-link" search={{ ...linkSearch, environment_id: family.environment_id, resource_id: component.id }} to="/audit">Events</Link>
                  </li>
                ))}
              </ul>
            </div>
          ) : <p className="lw-secondary lw-note">No refresh-token reuse recorded.</p>,
          title: "Refresh-token reuse"
        }
      ]}
      subtitle={<><StatusBadge status={familyStatus(family.status)}>{capitalize(family.status)}</StatusBadge><span>{PLATFORM_LABEL[family.platform] ?? words(family.platform)} · {family.component_count} part{family.component_count === 1 ? "" : "s"}</span></>}
      title={family.id}
    />
  );
}

function InstallationsView() {
  const compatibility = useConsoleCompatibility();
  const workspace = useWorkspace();
  const queryClient = useQueryClient();
  const environment = workspace.environment;
  const environmentID = environment?.id ?? "";
  const search = InstallationFamilyRouteSearchSchema.parse(workspace.search);
  const linkSearch = { application: search.application, environment: search.environment, organization: search.organization };
  const { can } = useCapabilities();
  const canMutate = compatibility.mutationAllowed && can("revoke_installations");
  const [view, setView] = useState<"all" | "signals">("all");
  const [operation, setOperation] = useState<Operation>();
  const [outcome, setOutcome] = useState<{ familyID: string; message: string }>();
  const [now] = useState(() => Date.now());
  const scopeMismatch = Boolean(search.environment_id && search.environment_id !== environmentID);

  const list = useInfiniteQuery({
    enabled: Boolean(environmentID) && !scopeMismatch,
    getNextPageParam: (last: { page: { has_more: boolean; next_cursor?: string } }) => (last.page.has_more ? last.page.next_cursor : undefined),
    initialPageParam: search.cursor as string | undefined,
    queryFn: async ({ pageParam }) => {
      const page = (await adminRequest(queryPath("/admin/v1/installation-families", { cursor: pageParam, environment_id: environmentID, page_size: "50", user_id: search.user_id }), InstallationFamilyPageSchema)).data;
      if (page.items.some((item) => item.environment_id !== environmentID || (search.user_id && item.user_id !== search.user_id))) throw new FamilyContextMismatch("family_context");
      return page;
    },
    queryKey: ["families", environmentID, search.user_id ?? "", search.cursor ?? ""],
    refetchOnWindowFocus: false
  });
  const families = list.data?.pages.flatMap((page) => page.items) ?? [];
  const detail = useQuery({
    enabled: Boolean(environmentID && search.family_id) && !scopeMismatch,
    queryFn: async () => {
      const response = await adminRequest(`/admin/v1/installation-families/${search.family_id}`, InstallationFamilySchema);
      if (response.data.id !== search.family_id || response.data.environment_id !== environmentID || !response.data.components) throw new FamilyContextMismatch("family_context");
      return response.data;
    },
    queryKey: ["family", environmentID, search.family_id],
    refetchOnWindowFocus: false,
    retry: false
  });
  const family = detail.data && detail.data.id === search.family_id ? detail.data : undefined;
  const componentMismatch = Boolean(family && search.component_id && !family.components?.some((component) => component.id === search.component_id));
  const problem = scopeMismatch
    ? { ...FAMILY_MISMATCH, detail: "This link names a different environment than the one selected. Choose that environment in the header." }
    : list.error ? (list.error instanceof FamilyContextMismatch ? FAMILY_MISMATCH : problemFromError(list.error)) : undefined;

  const withSignals = families.filter((item) => familySignals(item, environment?.kind, now).length > 0);
  const shown = view === "signals" ? withSignals : families;

  function open(familyID: string | undefined, componentID?: string): void {
    setOutcome(undefined);
    workspace.updateSearch({ component_id: componentID, environment_id: familyID ? environmentID : search.user_id ? environmentID : undefined, family_id: familyID }, { replace: false });
  }

  function done(updated: InstallationFamily, message: string): void {
    queryClient.setQueryData(["family", environmentID, updated.id], updated);
    void queryClient.invalidateQueries({ queryKey: ["families", environmentID] });
    setOperation(undefined);
    setOutcome({ familyID: updated.id, message });
  }

  const columns: Array<Column<InstallationFamily>> = [
    {
      header: "Installation",
      key: "installation",
      render: (item) => (
        <span className="lw-an-key">
          <span>{PLATFORM_LABEL[item.platform] ?? words(item.platform)} · {item.component_count} part{item.component_count === 1 ? "" : "s"}</span>
          <span className="lw-row lw-row--tight">
            <span className="lw-faint lw-mono" title={item.id}>{shortId(item.id)}</span>
            {familySignals(item, environment?.kind, now).map((signal) => <Badge color={signalBadgeColor(signal.severity)} key={signal.id} variant="soft">{signal.label}</Badge>)}
          </span>
        </span>
      )
    },
    { header: "User", key: "user", render: (item) => <span className="lw-mono lw-mono--sm" title={item.user_id}>{shortId(item.user_id)}</span> },
    { header: "Root trust", key: "trust", render: (item) => <TrustCell family={item} now={now} /> },
    { header: "Status", key: "status", render: (item) => <StatusBadge status={familyStatus(item.status)}>{capitalize(item.status)}</StatusBadge> },
    { align: "right", header: "Requests", key: "requests", render: (item) => formatCount(item.request_count) },
    { align: "right", header: "Cost", key: "cost", render: (item) => formatMoney(recorded(item.usage, "cost_nano_usd")) },
    { header: "Last seen", key: "last", render: (item) => <span className="lw-secondary lw-num" title={formatUtc(item.last_seen_at)}>{formatClock(item.last_seen_at, now)}</span> }
  ];

  return (
    <div className="lw-page lw-installations">
      <PageHeader description="Each installation is one app on one device: its root app and the widgets or extensions it delegated to. They appear when the app first verifies; change them through reviewed actions." title="Installations" />
      <Toolbar className="lw-toolbar--wrap" search={<GoToForm />}>
        <Segmented items={[{ id: "all", label: "All" }, { id: "signals", label: "With signals" }]} label="View" onChange={setView} value={view} />
        {search.user_id ? <FilterChip label="User" onClear={() => workspace.updateSearch({ cursor: undefined, environment_id: search.family_id ? environmentID : undefined, user_id: undefined })} value={shortId(search.user_id)} /> : null}
      </Toolbar>
      {view === "signals" ? <div className="lw-page-notice"><Notice tone="info">Showing signals in the {families.length} loaded installations. Load more to check more; the server can't filter by them yet. Token reuse, weak key storage and failed sessions are per part, so they show once an installation is opened.</Notice></div> : null}
      {problem ? <div className="lw-page-notice"><ProblemNotice problem={problem} /></div> : null}
      {list.isPending && !scopeMismatch ? <p className="lw-page-status" role="status">Loading installations…</p> : shown.length ? (
        <DataTable caption="Installations" columns={columns} onSelect={(item) => open(item.id)} rowKey={(item) => item.id} rows={shown} selectedKey={search.family_id} />
      ) : list.isSuccess ? (
        <div className="lw-page-empty"><EmptyState icon="mobile" orientation="horizontal" title={view === "signals" ? "No signals in the loaded installations" : "No installations yet"}>{view === "signals" ? "Load more installations to check them too." : "Installations appear the first time an app verifies through Latchway."}</EmptyState></div>
      ) : null}
      <div className="lw-rq-foot">
        <span>{families.length ? `${families.length} shown${list.hasNextPage ? " · more available" : " · that's all"}` : ""}</span>
        {list.hasNextPage ? <Button loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()} size="sm">Load More</Button> : null}
        <span className="lw-spacer" />
        <span className="lw-faint">Older installs from before installation families are under <Link className="lw-link" search={linkSearch} to="/installations">Older installs</Link>.</span>
      </div>

      {search.family_id ? (
        <div className="lw-drawer-dock">
          {family && !componentMismatch ? (
            <FamilyDrawer canMutate={canMutate} componentID={search.component_id} environmentKind={environment?.kind} family={family} key={family.id} linkSearch={linkSearch} now={now} onClose={() => open(undefined)} onOperate={setOperation} outcome={outcome?.familyID === family.id ? outcome.message : undefined} />
          ) : (
            <DetailPanel mono onClose={() => open(undefined)} title={search.family_id}>
              {componentMismatch ? <ProblemNotice problem={COMPONENT_MISMATCH} /> : detail.error ? <ProblemNotice problem={detail.error instanceof FamilyContextMismatch ? FAMILY_MISMATCH : problemFromError(detail.error)} /> : <p role="status">Loading installation…</p>}
            </DetailPanel>
          )}
        </div>
      ) : null}
      {operation && family ? <OperationReview environmentID={environmentID} family={family} key={JSON.stringify("component" in operation ? [operation.kind, operation.component.id] : [operation.kind])} onClose={() => setOperation(undefined)} onDone={done} operation={operation} /> : null}
    </div>
  );
}

function InstallationsWorkspace() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><InstallationsView /></EnvironmentRequired>;
}

/** Users & Installs → Installations, from GET /admin/v1/installation-families. */
export function InstallationFamiliesPage() {
  return <InstallationsWorkspace />;
}

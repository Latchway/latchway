import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactNode, useMemo, useState } from "react";

import { adminRequest, queryPath, RevisionSchema } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { type ConfigurationRevisionResource, type ConfigurationRevisionResourcePage, ConfigurationRevisionResourcePageSchema } from "../../api/resources";
import { useConsoleSession } from "../../api/session";
import { CompareRouteSearchSchema, RevisionRouteSearchSchema } from "../../app/route-search";
import { useDirtyEditProtection } from "../../app/use-dirty-edit-protection";
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
  Icon,
  ImpactDialog,
  Notice,
  PageHeader,
  Properties,
  Segmented
} from "../../ui";
import { draftSummary } from "../build/draft-summary";
import { DRAFT_STATES, draftProblem, type EnvironmentDraft, useEnvironmentDraft } from "../build/environment-draft";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { cloneConfigurationDocument, type JSONRecord, validStrongETag } from "../configuration-slice";
import { changeSetSummary, configurationDiff, discardEntry, fixTarget } from "./config-diff";
import { DiffGroups } from "./diff-view";
import { TransferDrawer } from "./transfer-drawer";

function when(value: string | undefined): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function ChangesScope({ children }: { children: (key: string) => ReactNode }) {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired>{children(`${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? "none"}`)}</EnvironmentRequired>;
}

function scoped(previous: Record<string, unknown>, extra: Record<string, string | undefined> = {}) {
  return { application: previous.application as string | undefined, environment: previous.environment as string | undefined, organization: previous.organization as string | undefined, ...extra };
}

/** "Started by adm_… on …"; console-created drafts show the administrator ID, API tokens their token ID. */
function author(createdBy: string): ReactNode {
  return <><span className="lw-mono lw-mono--sm">{createdBy}</span>{createdBy.startsWith("tok_") ? <> <Badge variant="soft">API</Badge></> : null}</>;
}

// ─── Draft ──────────────────────────────────────────────────────────────────

function DraftView() {
  const draft = useEnvironmentDraft();
  const [discarding, setDiscarding] = useState(false);
  const [transfer, setTransfer] = useState(false);
  const revision = draft.draft;
  const entries = useMemo(() => (revision ? configurationDiff(draft.activeDocument, revision.document as JSONRecord) : []), [draft.activeDocument, revision]);
  const summary = draftSummary(draft);
  const report = draft.lastSave?.report ?? revision?.validation;
  const errors = report?.issues.filter((issue) => issue.severity === "error") ?? [];
  const warnings = report?.issues.filter((issue) => issue.severity === "warning") ?? [];

  async function discardAll(): Promise<void> {
    const live = draft.activeDocument;
    if (!live) return;
    const saved = await draft.save(() => cloneConfigurationDocument(live), undefined, "Discard all changes");
    if (saved) setDiscarding(false);
  }

  return (
    <div className="lw-page">
      <PageHeader
        actions={<div className="lw-row">
          <Button icon="upload" onClick={() => setTransfer(true)}>Import / Export</Button>
          {entries.length ? <Link className={buttonClass()} search={(previous) => scoped(previous)} to="/configuration">Edit as JSON</Link> : null}
          {entries.length && draft.canConfigure ? <Button destructive onClick={() => setDiscarding(true)}>Discard All</Button> : null}
        </div>}
        description="Every unpublished change in this environment, by resource. Requests keep using the live configuration until the draft is published."
        title="Draft"
      />
      {draft.problem ? <div className="lw-page-notice"><ProblemNotice problem={draft.problem} /></div> : null}
      <div className="lw-body lw-stack">
        {draft.isPending ? <p className="lw-page-status" role="status">Loading the draft…</p> : !revision || !entries.length ? (
          <EmptyState icon="changes" orientation="horizontal" title="No unpublished changes">Saving on any Build or Policies page starts a draft here. Everyone on the team sees the same draft.</EmptyState>
        ) : (
          <>
            <p className="lw-note">
              <strong>{summary?.chip}</strong> · {entries.length} change{entries.length === 1 ? "" : "s"} ({changeSetSummary(entries)}) · draft <span className="lw-mono lw-mono--sm">{revision.id}</span> started by {author(revision.created_by)} {when(revision.created_at)}
              {draft.active ? <> · compared with <span className="lw-mono lw-mono--sm">{draft.active.id}</span> (live)</> : null}
            </p>
            {errors.length || warnings.length ? (
              <Card icon="alert" meta={`${errors.length} problem${errors.length === 1 ? "" : "s"} · ${warnings.length} warning${warnings.length === 1 ? "" : "s"}`} title="Problems">
                <ul className="lw-issues">
                  {[...errors, ...warnings].map((issue, index) => {
                    const target = fixTarget(issue.path, revision.document as JSONRecord);
                    return (
                      <li className={`lw-issue lw-issue--${issue.severity}`} key={`${issue.code}-${issue.path}-${index}`}>
                        <Icon name="alert" size={16} />
                        <div className="lw-issue__text"><span>{issue.message}</span><code>{issue.code} · {issue.path}</code></div>
                        <Link className={buttonClass({ size: "sm" })} search={(previous) => scoped(previous, target.search)} to={target.to}>Fix</Link>
                      </li>
                    );
                  })}
                </ul>
                <p className="lw-secondary lw-note">Problems block publishing; warnings are acknowledged when you publish.</p>
              </Card>
            ) : null}
            <DiffGroups busy={draft.busy || !draft.canConfigure} entries={entries} onDiscard={draft.canConfigure && draft.activeDocument ? (entry) => { const live = draft.activeDocument; if (live) void draft.save((document) => discardEntry(document, live, entry)); } : undefined} />
            <p className="lw-secondary lw-note">Who made each change isn't shown: the server records the draft's author, not each edit.</p>
          </>
        )}
      </div>
      {transfer ? <div className="lw-drawer-dock lw-drawer-dock--wide"><TransferDrawer draft={draft} onClose={() => setTransfer(false)} /></div> : null}
      {discarding ? (
        <ConfirmDialog confirmLabel="Discard All" description="The draft goes back to exactly the live configuration. Nothing live changes. This can't be undone, but the draft's history stays under History." destructive onCancel={() => setDiscarding(false)} onConfirm={() => void discardAll()} pending={draft.busy} title={`Discard all ${entries.length} changes?`}>
          {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

// ─── History ────────────────────────────────────────────────────────────────

type RevisionStatus = "Live" | "Draft" | "Superseded" | "Invalid" | "Checked";

function statusOf(revision: ConfigurationRevisionResource, activeID: string | undefined): RevisionStatus {
  if (revision.id === activeID) return "Live";
  if (revision.state === "invalid") return "Invalid";
  if (DRAFT_STATES.has(revision.state) && !revision.activated_at) return revision.state === "valid" ? "Checked" : "Draft";
  return "Superseded";
}

const STATUS_BADGE: Readonly<Record<RevisionStatus, ReactNode>> = {
  Checked: <Badge variant="soft">Not published</Badge>,
  Draft: <Badge color="orange" variant="soft">Draft</Badge>,
  Invalid: <Badge color="red" variant="soft">Invalid</Badge>,
  Live: <Badge color="success" variant="soft">Live</Badge>,
  Superseded: <Badge variant="soft">Superseded</Badge>
};

function useRevisionHistory(environmentID: string) {
  return useInfiniteQuery({
    enabled: Boolean(environmentID),
    getNextPageParam: (page: ConfigurationRevisionResourcePage) => (page.page.has_more ? page.page.next_cursor : undefined),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }): Promise<ConfigurationRevisionResourcePage> => {
      const page = (await adminRequest(queryPath(`/admin/v1/environments/${environmentID}/config-revisions`, { cursor: pageParam, page_size: "20" }), ConfigurationRevisionResourcePageSchema)).data;
      if (page.items.some((item) => item.environment_id !== environmentID)) throw new Error("A revision didn't belong to the selected environment.");
      return page;
    },
    queryKey: ["environment", environmentID, "configuration-revisions", "history"],
    retry: false
  });
}

function RollbackDialog({ draft, onClose, onDone, target }: { draft: EnvironmentDraft; onClose: () => void; onDone: () => void; target: ConfigurationRevisionResource }) {
  const workspace = useWorkspace();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const environmentID = workspace.environment?.id ?? "";
  const undone = configurationDiff(target.document as JSONRecord, draft.activeDocument);
  const features = new Set(undone.filter((entry) => entry.collection.startsWith("features")).map((entry) => entry.id));

  async function rollback(reason: string): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      const current = await adminRequest(`/admin/v1/environments/${environmentID}/config`, RevisionSchema);
      if (!validStrongETag(current.etag)) throw new Error("The server omitted the strong ETag needed for a safe rollback.");
      const restored = (await adminRequest(`/admin/v1/environments/${environmentID}/rollback`, RevisionSchema, { body: { reason, revision_id: target.id }, etag: current.etag, method: "POST" })).data;
      if (restored.id !== target.id || restored.environment_id !== environmentID) throw new Error("The server reactivated a different revision.");
      await draft.refetch();
      onDone();
    } catch (failure) {
      setProblem(failure instanceof Error && !("problem" in failure) ? { code: "invalid_response", detail: failure.message, retryable: true, status: 0, title: "Rollback not confirmed" } : draftProblem(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ImpactDialog
      acknowledgement="I understand every new request uses this revision as soon as I confirm."
      confirmLabel="Roll Back"
      facts={[["When", "Immediately, for every new request. Requests already running finish on the current revision."], ["Undo", "Roll back again to the current live revision. Newer revisions stay in History; a pending draft is kept."]]}
      impacts={[{ count: undone.length, label: "changes undone" }, { count: features.size, label: "features affected" }]}
      onCancel={onClose}
      onConfirm={({ reason }) => void rollback(reason)}
      pending={busy}
      reasonHint="Required by the server; it records that a reason was given, not the text."
      scope={`Every new request in ${workspace.environment?.display_name ?? "this environment"}.`}
      targetId={target.id}
      title={`Roll back to version ${target.version}?`}
    >
      {undone.length ? <DiffGroups entries={undone} /> : <p className="lw-note">This revision's document matches live; only the revision changes.</p>}
      {problem ? <ProblemNotice problem={problem} /> : null}
    </ImpactDialog>
  );
}

function RevisionDrawer({ draft, onClose, previous, revision }: { draft: EnvironmentDraft; onClose: () => void; previous?: ConfigurationRevisionResource; revision: ConfigurationRevisionResource }) {
  const [against, setAgainst] = useState<"previous" | "live">(previous ? "previous" : "live");
  const [rollingBack, setRollingBack] = useState(false);
  const [copying, setCopying] = useState(false);
  const [done, setDone] = useState<string>();
  const status = statusOf(revision, draft.active?.id);
  const base = against === "previous" ? (previous?.document as JSONRecord | undefined) : draft.activeDocument;
  const entries = configurationDiff(base, revision.document as JSONRecord);
  const errors = revision.validation?.issues.filter((issue) => issue.severity === "error") ?? [];
  const canRollBack = draft.canConfigure && Boolean(revision.activated_at) && status !== "Live" && revision.state !== "invalid";
  const draftEntries = draft.draft ? configurationDiff(draft.activeDocument, draft.draft.document as JSONRecord) : [];

  async function startDraft(): Promise<void> {
    const saved = await draft.save(() => cloneConfigurationDocument(revision.document as JSONRecord), undefined, `Draft from ${revision.id}`);
    if (saved) {
      setCopying(false);
      setDone(`The draft now holds ${revision.id}'s document. Review it under Draft.`);
    }
  }

  return (
    <>
      <DetailPanel
        actions={draft.canConfigure ? <>
          {canRollBack ? <Button destructive icon="undo" onClick={() => setRollingBack(true)} size="sm">Roll Back to This</Button> : null}
          {status !== "Live" ? <Button onClick={() => (draftEntries.length ? setCopying(true) : void startDraft())} size="sm">Start a Draft From This</Button> : null}
        </> : undefined}
        className="lw-request-drawer"
        mono
        onClose={onClose}
        subtitle={<>{STATUS_BADGE[status]}<span className="lw-faint">Version {revision.version}</span></>}
        title={revision.id}
      >
        <div className="lw-stack">
          <Properties columns={2} items={[
            { label: "Summary", value: previous ? changeSetSummary(configurationDiff(previous.document as JSONRecord, revision.document as JSONRecord)) : "First revision" },
            { label: "Created by", value: author(revision.created_by) },
            { label: "Created", value: when(revision.created_at) },
            { label: "Went live", value: revision.activated_at ? when(revision.activated_at) : "Never" }
          ]} />
          {done ? <Notice tone="success">{done}</Notice> : null}
          {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
          {errors.length ? <Notice title={`${errors.length} validation problem${errors.length === 1 ? "" : "s"}`} tone="danger"><ul className="lw-issue-list">{errors.slice(0, 10).map((issue, index) => <li key={index}><code className="lw-code-inline">{issue.path}</code> {issue.message}</li>)}</ul></Notice> : null}
          <div className="lw-row lw-row--spread">
            <strong className="lw-note">Changes</strong>
            <Segmented items={[...(previous ? [{ id: "previous" as const, label: "Vs previous" }] : []), { id: "live" as const, label: "Vs live" }]} label="Compare with" onChange={setAgainst} value={against} />
          </div>
          {entries.length ? <DiffGroups entries={entries} /> : <p className="lw-secondary lw-note">No differences.</p>}
          <details><summary className="lw-note">Document (secrets appear only as references)</summary><pre className="lw-code-block">{JSON.stringify(revision.document, null, 2)}</pre></details>
          <Link className="lw-link lw-note" search={(previousSearch) => scoped(previousSearch, { resource_id: revision.id })} to="/audit">Audit events for this revision</Link>
        </div>
      </DetailPanel>
      {rollingBack ? <RollbackDialog draft={draft} onClose={() => setRollingBack(false)} onDone={() => { setRollingBack(false); setDone(`${revision.id} is live again.`); }} target={revision} /> : null}
      {copying ? (
        <ConfirmDialog confirmLabel="Replace the Draft" description={`The current draft has ${draftEntries.length} unpublished change${draftEntries.length === 1 ? "" : "s"}, started by ${draft.draft?.created_by ?? "an administrator"}. They are replaced by this revision's document.`} destructive onCancel={() => setCopying(false)} onConfirm={() => void startDraft()} pending={draft.busy} title="Replace the draft?">
          {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </>
  );
}

function HistoryView() {
  const workspace = useWorkspace();
  const draft = useEnvironmentDraft();
  const search = RevisionRouteSearchSchema.parse(workspace.search);
  const history = useRevisionHistory(workspace.environment?.id ?? "");
  const items = useMemo(() => history.data?.pages.flatMap((page) => page.items) ?? [], [history.data]);
  const open = (revision: string | undefined) => workspace.updateSearch({ revision }, { replace: false });
  const selectedIndex = items.findIndex((item) => item.id === search.revision);
  const selected = selectedIndex >= 0 ? items[selectedIndex] : undefined;
  const directRevision = useQuery({
    enabled: Boolean(search.revision && !history.isPending && selectedIndex < 0),
    queryFn: async () => {
      const response = (await adminRequest(`/admin/v1/config-revisions/${search.revision}`, RevisionSchema)).data;
      if (response.environment_id !== workspace.environment?.id) throw new Error("This revision belongs to another environment.");
      return response as ConfigurationRevisionResource;
    },
    queryKey: ["revision", search.revision],
    retry: false
  });
  const revision = selected ?? directRevision.data;
  const columns: Array<Column<ConfigurationRevisionResource>> = [
    { header: "Revision", key: "id", render: (item) => <span className="lw-rq-model"><span className="lw-mono lw-mono--sm">{item.id}</span><span className="lw-faint">Version {item.version}</span></span> },
    { header: "Status", key: "status", render: (item) => STATUS_BADGE[statusOf(item, draft.active?.id)] },
    { header: "Changes", key: "summary", render: (item) => { const older = items[items.indexOf(item) + 1]; return older ? <span className="lw-note">{changeSetSummary(configurationDiff(older.document as JSONRecord, item.document as JSONRecord))}</span> : <span className="lw-faint">{history.hasNextPage ? "Load older to compare" : "First revision"}</span>; } },
    { header: "By", key: "by", render: (item) => author(item.created_by) },
    { header: "Went live", key: "live", render: (item) => item.activated_at ? when(item.activated_at) : <span className="lw-faint">Never</span> }
  ];
  return (
    <div className="lw-page lw-collection">
      <PageHeader description="Every revision of this environment. Rolling back reactivates an earlier revision; history is never rewritten." title="History" />
      {history.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(history.error)} /></div> : null}
      {history.isPending ? <p className="lw-page-status" role="status">Loading history…</p> : items.length ? (
        <>
          <DataTable caption="Revisions" columns={columns} onSelect={(item) => open(item.id)} rowKey={(item) => item.id} rows={items} selectedKey={search.revision} />
          {history.hasNextPage ? <div className="lw-page-foot"><Button loading={history.isFetchingNextPage} onClick={() => void history.fetchNextPage()} size="sm">Load Older Revisions</Button></div> : null}
        </>
      ) : <div className="lw-page-empty"><EmptyState icon="history" orientation="horizontal" title="No revisions yet">Finish Setup or save on a Build page to create the first one.</EmptyState></div>}
      {search.revision && directRevision.error ? <div className="lw-page-notice"><Notice title="Revision not found" tone="danger">{directRevision.error instanceof Error ? directRevision.error.message : "It couldn't be loaded."} No other revision was opened instead.</Notice></div> : null}
      {revision ? <div className="lw-drawer-dock lw-drawer-dock--wide"><RevisionDrawer draft={draft} key={revision.id} onClose={() => open(undefined)} previous={selectedIndex >= 0 ? items[selectedIndex + 1] : undefined} revision={revision} /></div> : null}
    </div>
  );
}

// ─── Compare ────────────────────────────────────────────────────────────────

function CompareView() {
  const workspace = useWorkspace();
  const draft = useEnvironmentDraft();
  const search = CompareRouteSearchSchema.parse(workspace.search);
  const history = useRevisionHistory(workspace.environment?.id ?? "");
  const items = history.data?.pages.flatMap((page) => page.items) ?? [];
  const others = workspace.environments.filter((environment) => environment.id !== workspace.environment?.id && environment.application_id === workspace.application?.id);
  const otherLive = useQuery({
    enabled: others.length > 0,
    queryFn: async () => Promise.all(others.map(async (environment) => {
      try {
        const response = (await adminRequest(`/admin/v1/environments/${environment.id}/config`, RevisionSchema)).data;
        return response.environment_id === environment.id ? { environment, revision: response } : undefined;
      } catch {
        return undefined;
      }
    })),
    queryKey: ["application", workspace.application?.id, "other-live"],
    retry: false
  });
  const from = search.from ?? "live";
  const to = search.to ?? (draft.draft ? "draft" : items.find((item) => item.id !== draft.active?.id)?.id ?? "live");
  const options: Array<{ id: string; label: string }> = [
    { id: "live", label: `${workspace.environment?.display_name ?? "This environment"} live${draft.active ? ` (${draft.active.id})` : ""}` },
    ...(draft.draft ? [{ id: "draft", label: `${workspace.environment?.display_name ?? "This environment"} draft (${draft.draft.id})` }] : []),
    ...(otherLive.data ?? []).flatMap((entry) => (entry ? [{ id: entry.revision.id, label: `${entry.environment.display_name} live (${entry.revision.id})` }] : [])),
    ...items.filter((item) => item.id !== draft.active?.id && item.id !== draft.draft?.id).map((item) => ({ id: item.id, label: `Version ${item.version} (${item.id})` }))
  ];
  const resolveLocal = (id: string): JSONRecord | undefined => id === "live" ? draft.activeDocument : id === "draft" ? (draft.draft?.document as JSONRecord | undefined) : (items.find((item) => item.id === id)?.document ?? otherLive.data?.find((entry) => entry?.revision.id === id)?.revision.document) as JSONRecord | undefined;
  const remote = useQuery({
    enabled: [from, to].some((id) => id.startsWith("rev_") && !resolveLocal(id)) && !history.isPending,
    queryFn: async () => {
      const missing = [from, to].filter((id) => id.startsWith("rev_") && !resolveLocal(id));
      return Object.fromEntries(await Promise.all(missing.map(async (id) => [id, (await adminRequest(`/admin/v1/config-revisions/${id}`, RevisionSchema)).data.document as JSONRecord] as const)));
    },
    queryKey: ["compare", from, to],
    retry: false
  });
  const resolve = (id: string) => resolveLocal(id) ?? remote.data?.[id];
  const left = resolve(from);
  const right = resolve(to);
  const entries = left && right ? configurationDiff(left, right) : [];
  const select = (key: "from" | "to", id: string) => workspace.updateSearch({ [key]: id });
  const picker = (key: "from" | "to", current: string) => (
    <select aria-label={key === "from" ? "Compare from" : "Compare to"} className="lw-select" onChange={(event) => select(key, event.target.value)} value={current}>
      {!options.some((option) => option.id === current) ? <option value={current}>{current}</option> : null}
      {options.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}
    </select>
  );
  return (
    <div className="lw-page">
      <PageHeader description="Compare any two configurations: live, the draft, another environment's live revision, or any revision." title="Compare" />
      <div className="lw-body lw-stack">
        <div className="lw-compare">
          {picker("from", from)}
          <Button aria-label="Swap" icon="sort" onClick={() => workspace.updateSearch({ from: to, to: from })} variant="ghost" />
          {picker("to", to)}
        </div>
        {remote.error ? <ProblemNotice problem={problemFromError(remote.error)} /> : null}
        {!left || !right ? <p className="lw-page-status" role="status">Loading…</p> : entries.length ? (
          <>
            <p className="lw-note">{changeSetSummary(entries)}</p>
            <DiffGroups entries={entries} />
          </>
        ) : <p className="lw-note">These two configurations are the same.</p>}
        <p className="lw-secondary lw-note">Copying one environment into another's draft isn't offered yet: environment-specific values (sign-in projects, app identifiers, base URLs and secret references) need a reviewed promote the Admin API doesn't have.</p>
      </div>
    </div>
  );
}

// ─── Edit as JSON ───────────────────────────────────────────────────────────

/** A short, stable fingerprint of a document, so the editor resets when the draft it shows changes. */
function fingerprint(text: string): string {
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) hash = (hash * 31 + text.charCodeAt(index)) | 0;
  return `${text.length}:${hash}`;
}

function JsonEditorForm({ basis, draft }: { basis: JSONRecord; draft: EnvironmentDraft }) {
  const initial = JSON.stringify(basis, null, 2);
  const [text, setText] = useState(initial);
  const [error, setError] = useState<string>();
  const dirty = text !== initial;
  useDirtyEditProtection(dirty);

  async function save(): Promise<void> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (failure) {
      const position = failure instanceof SyntaxError ? /position (\d+)/.exec(failure.message)?.[1] : undefined;
      const line = position ? text.slice(0, Number(position)).split("\n").length : undefined;
      return setError(`This isn't valid JSON${line ? ` (line ${line})` : ""}.`);
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !("spec" in parsed) || (parsed as JSONRecord).kind !== "EnvironmentConfig") return setError("The document must be one EnvironmentConfig object with apiVersion, kind, metadata and spec.");
    setError(undefined);
    await draft.save(() => parsed as JSONRecord, basis, "Edited as JSON");
  }

  return (
    <>
      <div className="lw-row"><Button disabled={!dirty} onClick={() => { setText(initial); setError(undefined); }}>Revert</Button><Button disabled={!draft.canConfigure || !dirty} loading={draft.busy} onClick={() => void save()} variant="primary">Save to Draft</Button></div>
      <textarea aria-label="Configuration document JSON" className="lw-json-editor lw-json-editor--full" onChange={(event) => setText(event.target.value)} rows={32} spellCheck={false} value={text} />
      {error ? <Notice title="Not saved" tone="danger">{error}</Notice> : null}
    </>
  );
}

function JsonEditorView() {
  const draft = useEnvironmentDraft();
  const basis = draft.document;
  const report = draft.lastSave?.report;
  return (
    <div className="lw-page">
      <PageHeader description="The whole draft document. Secrets appear only as references. Saving replaces the draft; the changes show up under Draft." title="Edit as JSON" />
      <div className="lw-body lw-stack">
        {draft.isPending ? <p className="lw-page-status" role="status">Loading the draft…</p> : !basis ? <Notice tone="info">There's no configuration yet. Finish Setup first.</Notice> : (
          <>
            <JsonEditorForm basis={basis} draft={draft} key={fingerprint(JSON.stringify(basis))} />
            {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
            {report ? (report.valid ? <Notice title="Saved to draft" tone="success">The document is valid. Review and publish it under Draft.</Notice> : <Notice title="Saved to draft with problems" tone="warning"><ul className="lw-issue-list">{report.issues.filter((issue) => issue.severity === "error").slice(0, 10).map((issue, index) => <li key={index}><code className="lw-code-inline">{issue.path}</code> {issue.message}</li>)}</ul></Notice>) : null}
            {!draft.canConfigure ? <p className="lw-secondary lw-note">View only: saving needs the <code className="lw-code-inline">activate_configuration</code> capability.</p> : null}
          </>
        )}
      </div>
    </div>
  );
}

/** Changes → Draft. */
export function DraftChangesPage() { return <ChangesScope>{(key) => <DraftView key={key} />}</ChangesScope>; }
/** Changes → History. */
export function RevisionHistoryPage() { return <ChangesScope>{(key) => <HistoryView key={key} />}</ChangesScope>; }
/** Changes → Compare. */
export function ComparePage() { return <ChangesScope>{(key) => <CompareView key={key} />}</ChangesScope>; }
/** Changes → Edit as JSON. */
export function JsonEditorPage() { return <ChangesScope>{(key) => <JsonEditorView key={key} />}</ChangesScope>; }

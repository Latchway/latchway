import { type ReactNode, useMemo, useState } from "react";

import { useDirtyEditProtection } from "../../app/use-dirty-edit-protection";
import {
  Badge,
  Button,
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
import { ProblemNotice } from "../control-plane-pages";
import {
  type AreaCollectionDefinition,
  type ConfigurationAreaDefinition,
  deleteAreaResource,
  type JSONRecord,
  upsertAreaResource
} from "../configuration-slice";
import type { EnvironmentDraft } from "./environment-draft";
import { type ResourceRow, resourceRows, restoreResource } from "./resource-diff";

export function StatePill({ state }: { state: ResourceRow["state"] }) {
  if (state === "live") return null;
  return state === "new" ? <Badge color="orange" variant="soft">New</Badge>
    : state === "edited" ? <Badge color="accent" variant="soft">Edited</Badge>
      : <Badge color="red" variant="soft">Removing</Badge>;
}

function compact(value: unknown): ReactNode {
  if (value === undefined || value === null) return <span className="lw-faint">—</span>;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value) && value.every((item) => typeof item === "string" || typeof item === "number")) return value.join(", ") || <span className="lw-faint">None</span>;
  return <code className="lw-mono lw-mono--sm lw-clamp">{JSON.stringify(value)}</code>;
}

/** The outcome of the latest save, shown under the page header: problems from the server's validation, or a confirmation. */
export function DraftSaveNotice({ draft }: { draft: EnvironmentDraft }) {
  const report = draft.lastSave?.report;
  if (draft.problem) return <div className="lw-page-notice"><ProblemNotice problem={draft.problem} /></div>;
  if (!report) return null;
  const errors = report.issues.filter((issue) => issue.severity === "error");
  if (!errors.length) return <div className="lw-page-notice"><Notice title="Saved to draft" tone="success">The draft is checked and ready to publish from the bar above. Requests keep using the live configuration until then.</Notice></div>;
  return (
    <div className="lw-page-notice">
      <Notice title={`Saved to draft with ${errors.length} problem${errors.length === 1 ? "" : "s"} to fix before publishing`} tone="warning">
        <ul className="lw-issue-list">{errors.slice(0, 8).map((issue, index) => <li key={`${issue.path}-${index}`}><code className="lw-code-inline">{issue.path}</code> {issue.message}</li>)}</ul>
      </Notice>
    </div>
  );
}

interface ResourceDrawerProps {
  collection: AreaCollectionDefinition;
  draft: EnvironmentDraft;
  extra?: ReactNode;
  initialEditing: boolean;
  onClose: () => void;
  onDelete: () => void;
  row?: ResourceRow;
}

function ResourceDrawer({ collection, draft, extra, initialEditing, onClose, onDelete, row }: ResourceDrawerProps) {
  const initial = JSON.stringify(row ? row.value : collection.template, null, 2);
  const [editing, setEditing] = useState(initialEditing);
  const [text, setText] = useState(initial);
  const [error, setError] = useState<string>();
  const dirty = editing && text !== initial;
  useDirtyEditProtection(dirty);
  const removing = row?.state === "removing";
  const value = row?.value ?? {};

  async function save(): Promise<void> {
    setError(undefined);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setError("This isn't valid JSON.");
      return;
    }
    try {
      // Check locally first so a malformed resource never reaches the server.
      upsertAreaResource(draft.document ?? {}, collection, row?.key, parsed);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The resource is invalid.");
      return;
    }
    const saved = await draft.save((document) => upsertAreaResource(document, collection, row?.key, parsed).document);
    if (saved) onClose();
  }

  return (
    <DetailPanel
      actions={draft.canConfigure ? <>
        {row && row.state !== "live" ? <Button onClick={() => void draft.save((document) => restoreResource(document, row, collection)).then((saved) => { if (saved) onClose(); })} size="sm">{row.state === "removing" ? "Undo Remove" : row.state === "new" ? "Remove from Draft" : "Undo Changes"}</Button> : null}
        {row && collection.deletable && !removing && row.state !== "new" ? <Button aria-label={`Remove ${row.label}`} destructive icon="trash" onClick={onDelete} size="sm" variant="ghost" /> : null}
        {!removing && !editing ? <Button onClick={() => setEditing(true)} size="sm">Edit as JSON</Button> : null}
        {editing ? <Button loading={draft.busy} onClick={() => void save()} size="sm" variant="primary">Save to Draft</Button> : null}
      </> : undefined}
      className="lw-request-drawer"
      mono
      onClose={onClose}
      sections={[
        ...(removing ? [{ content: <Notice title="Removed in the draft" tone="danger">It keeps working until the draft is published. Undo Remove puts it back.</Notice> }] : []),
        // A page-specific summary replaces the generic property list rather than repeating it.
        ...(!editing && !extra ? [{
          content: <Properties columns={2} items={Object.entries(value).map(([key, item]) => ({ label: key, value: compact(item) }))} />,
          title: "Settings"
        }] : []),
        ...(extra ? [{ content: extra }] : []),
        {
          content: editing ? (
            <div className="lw-stack lw-stack--tight">
              <p className="lw-secondary lw-note">{collection.description} Saving writes only this resource into the draft; the server validates the whole configuration.</p>
              <textarea aria-label="Resource JSON" className="lw-json-editor" onChange={(event) => setText(event.target.value)} rows={18} spellCheck={false} value={text} />
              {error ? <p className="lw-field__error" role="alert">{error}</p> : null}
              {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
              <div className="lw-row"><Button onClick={() => (row ? (setEditing(false), setText(initial), setError(undefined)) : onClose())} size="sm">Cancel</Button></div>
            </div>
          ) : <pre className="lw-code-block">{JSON.stringify(value, null, 2)}</pre>,
          title: editing ? (row ? "Edit as JSON" : `New ${collection.label.toLowerCase()}`) : "JSON"
        }
      ]}
      subtitle={row ? <><StatePill state={row.state} /><span className="lw-faint">{collection.canonicalPath}</span></> : <span className="lw-faint">Saved to the draft, not published</span>}
      title={row?.label ?? `New ${collection.label.toLowerCase()}`}
    />
  );
}

export interface CollectionView {
  /** Extra columns after the name, for this collection. */
  columns?: (row: ResourceRow) => Array<Column<ResourceRow>>;
  extraColumns?: Array<Column<ResourceRow>>;
}

interface CollectionPageProps {
  /** Replaces the default "add from a JSON template" with a guided flow. */
  addAction?: ReactNode;
  addLabel?: string;
  /** Shown below the list. */
  after?: ReactNode;
  /** Shown above the list. */
  children?: ReactNode;
  /** Resources that still depend on this one; a non-empty list blocks removal and explains what to change first. */
  deleteBlockers?: (row: ResourceRow) => string[];
  definition: ConfigurationAreaDefinition;
  description: string;
  draft: EnvironmentDraft;
  drawerExtra?: (row: ResourceRow, collection: AreaCollectionDefinition) => ReactNode;
  emptyText?: string;
  extraColumns?: (collection: AreaCollectionDefinition) => Array<Column<ResourceRow>>;
  title: string;
}

/**
 * A configuration collection as a list. Rows show their draft state; a row opens a drawer with its settings and a
 * JSON editor, and every save, removal and undo goes into the environment's working draft.
 */
export function CollectionPage({ addAction, addLabel, after, children, definition, deleteBlockers, description, draft, drawerExtra, emptyText, extraColumns, title }: CollectionPageProps) {
  const [collectionKey, setCollectionKey] = useState(definition.collections[0]?.key ?? "");
  const [open, setOpen] = useState<{ key?: string; new?: boolean }>();
  const [removing, setRemoving] = useState<ResourceRow>();
  const [typed, setTyped] = useState("");
  const collection = definition.collections.find((candidate) => candidate.key === collectionKey) ?? definition.collections[0];
  const rows = useMemo(() => {
    if (!collection) return [];
    try {
      return resourceRows(draft.activeDocument, draft.document, collection);
    } catch {
      return [];
    }
  }, [collection, draft.activeDocument, draft.document]);
  const listError = useMemo(() => {
    if (!collection || !draft.document) return undefined;
    try {
      resourceRows(draft.activeDocument, draft.document, collection);
      return undefined;
    } catch (error) {
      return error instanceof Error ? error.message : "The configuration couldn't be read.";
    }
  }, [collection, draft.activeDocument, draft.document]);
  if (!collection) return null;
  const openRow = open?.key ? rows.find((row) => row.key === open.key) : undefined;
  const canAdd = collection.kind !== "feature-fields";

  const columns: Array<Column<ResourceRow>> = [
    { header: collection.kind === "feature-fields" ? "Feature" : "Name", key: "name", render: (row) => <span className="lw-name-cell"><span className={`lw-mono lw-mono--sm${row.state === "removing" ? " lw-struck" : ""}`}>{row.label}</span><StatePill state={row.state} /></span> },
    ...(extraColumns ? extraColumns(collection) : [])
  ];

  return (
    <div className="lw-page lw-collection">
      <PageHeader
        actions={canAdd ? (addAction ?? <Button disabled={!draft.canConfigure} icon="plus" onClick={() => setOpen({ new: true })} variant="primary">{addLabel ?? `Add ${collection.label}`}</Button>) : undefined}
        description={description}
        title={title}
      />
      {definition.collections.length > 1 ? (
        <div className="lw-rq-views">
          <Segmented items={definition.collections.map((candidate) => ({ id: candidate.key, label: candidate.label }))} label="Collection" onChange={(key) => { setCollectionKey(key); setOpen(undefined); }} value={collection.key} />
        </div>
      ) : null}
      <DraftSaveNotice draft={draft} />
      {listError ? <div className="lw-page-notice"><Notice title="This part of the configuration couldn't be read" tone="danger">{listError}</Notice></div> : null}
      {children}
      {draft.isPending ? <p className="lw-page-status" role="status">Loading configuration…</p> : rows.length ? (
        <DataTable caption={collection.label} columns={columns} onSelect={(row) => setOpen({ key: row.key })} rowKey={(row) => row.key} rows={rows} selectedKey={open?.key} />
      ) : draft.document ? (
        <div className="lw-page-empty"><EmptyState icon="plus" orientation="horizontal" title={`No ${collection.label.toLowerCase()} yet`}>{emptyText ?? collection.description}</EmptyState></div>
      ) : null}
      {after}
      {!draft.canConfigure && draft.document ? <p className="lw-secondary lw-note lw-page-foot">View only: changing configuration needs the <code className="lw-code-inline">activate_configuration</code> capability, an active application and environment, and verified console compatibility.</p> : null}

      {open && (open.new || openRow) ? (
        <div className="lw-drawer-dock">
          <ResourceDrawer
            collection={collection}
            draft={draft}
            extra={openRow && drawerExtra ? drawerExtra(openRow, collection) : undefined}
            initialEditing={Boolean(open.new)}
            key={open.key ?? "new"}
            onClose={() => setOpen(undefined)}
            onDelete={() => { if (openRow) { setRemoving(openRow); setTyped(""); } }}
            row={openRow}
          />
        </div>
      ) : null}
      {removing && deleteBlockers && deleteBlockers(removing).length ? (
        <ConfirmDialog confirmLabel="Close" description="Change these first, then remove it." onCancel={() => setRemoving(undefined)} onConfirm={() => setRemoving(undefined)} title={`${removing.label} is still in use`}>
          <ul className="lw-issue-list">{deleteBlockers(removing).map((blocker) => <li key={blocker}>{blocker}</li>)}</ul>
        </ConfirmDialog>
      ) : removing ? (
        <ConfirmDialog
          confirmDisabled={typed !== removing.key}
          confirmLabel="Remove in Draft"
          description="It keeps working until the draft is published. Publishing removes it; until then, Undo Remove puts it back."
          destructive
          onCancel={() => setRemoving(undefined)}
          onConfirm={() => void draft.save((document: JSONRecord) => deleteAreaResource(document, collection, removing.key)).then((saved) => { if (saved) { setRemoving(undefined); setOpen(undefined); } })}
          pending={draft.busy}
          title={`Remove ${removing.label}?`}
        >
          <Field id="remove-confirm" label={<>Type <code className="lw-code-inline">{removing.key}</code> to confirm</>}>
            <Input autoComplete="off" id="remove-confirm" mono onChange={(event) => setTyped(event.target.value)} spellCheck={false} value={typed} />
          </Field>
          {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

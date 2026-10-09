import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { adminRequest, type MergePreview, RevisionSchema } from "../../api/admin";
import { ConfirmDialog, Notice } from "../../ui";
import { valueAtPath } from "../changes/merge-paths";
import type { JSONRecord } from "../configuration-slice";
import { ProblemNotice } from "../control-plane-pages";
import { draftProblem, type EnvironmentDraft } from "./environment-draft";

function shown(value: unknown): string {
  if (value === undefined) return "(removed)";
  const text = JSON.stringify(value, null, 2);
  return text.length > 1_200 ? `${text.slice(0, 1_200)}\n…` : text;
}

interface Loaded {
  base?: JSONRecord;
  preview: MergePreview;
}

async function loadMerge(draft: EnvironmentDraft): Promise<Loaded> {
  const preview = await draft.previewRebase();
  const base = preview.base_revision_id ? (await adminRequest(`/admin/v1/config-revisions/${preview.base_revision_id}`, RevisionSchema)).data.document as JSONRecord : undefined;
  return { base, preview };
}

/**
 * Brings a stale draft up to date: lists what the live configuration and the draft each changed since the draft
 * started, and asks for a side on every path both changed. The server merges; nothing is merged in the browser.
 */
export function MergeDialog({ draft, onClose }: { draft: EnvironmentDraft; onClose: () => void }) {
  const [choices, setChoices] = useState<Record<string, "draft" | "live">>({});
  const merge = useQuery({
    gcTime: 0,
    queryFn: () => loadMerge(draft),
    queryKey: ["rebase-preview", draft.draft?.id, draft.draft?.updated_at, draft.active?.id],
    refetchOnWindowFocus: false,
    retry: false
  });
  const loaded = merge.data;
  const loadError = merge.error;
  const preview = loaded?.preview;
  const unresolved = preview ? preview.conflicts.filter((path) => !choices[path]).length : 0;
  const draftDocument = draft.draft?.document;
  const liveDocument = draft.activeDocument;
  const liveMoved = Boolean(preview && draft.active && preview.live_revision_id !== draft.active.id);

  return (
    <ConfirmDialog
      confirmDisabled={!preview || preview.up_to_date || unresolved > 0 || liveMoved || draft.busy}
      confirmLabel="Bring Up to Date"
      description="Something else was published after this draft started. Bringing it up to date keeps your draft's changes and adds what changed live. Nothing is published."
      onCancel={onClose}
      onConfirm={() => { if (preview) void draft.rebase(preview.live_revision_id, choices).then((done) => { if (done) onClose(); }); }}
      pending={draft.busy}
      size="xl"
      title="Bring the draft up to date?"
    >
      {loadError ? <ProblemNotice problem={draftProblem(loadError)} /> : null}
      {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
      {!preview ? (loadError ? null : <p role="status">Comparing the draft with the live configuration…</p>) : preview.up_to_date ? (
        <Notice tone="success">The draft already starts from the live configuration.</Notice>
      ) : (
        <div className="lw-stack lw-stack--tight">
          {liveMoved ? <Notice tone="warning">The live configuration changed again while this was open. Close and reopen to compare with it.</Notice> : null}
          <p className="lw-note">
            Started from <span className="lw-mono lw-mono--sm">{preview.base_revision_id ?? "nothing live"}</span>; live is now <span className="lw-mono lw-mono--sm">{preview.live_revision_id}</span>.
            {" "}Your draft changed {preview.draft_changes.length} path{preview.draft_changes.length === 1 ? "" : "s"}; live changed {preview.live_changes.length}.
          </p>
          {preview.live_changes.length ? (
            <details>
              <summary className="lw-note">Changes that come from live</summary>
              <ul className="lw-plan-list">{preview.live_changes.map((change, index) => <li key={`${change.path}-${index}`}><span className={`lw-plan-op is-${change.operation}`}>{change.operation}</span><code className="lw-mono lw-mono--sm">{change.path}</code></li>)}</ul>
            </details>
          ) : null}
          {preview.conflicts.length ? (
            <>
              <strong className="lw-note">{preview.conflicts.length} conflict{preview.conflicts.length === 1 ? "" : "s"}: both changed the same thing. Choose which to keep.</strong>
              <ul className="lw-merge-list">
                {preview.conflicts.map((path) => (
                  <li className="lw-merge" key={path}>
                    <code className="lw-mono lw-mono--sm lw-merge__path">{path}</code>
                    <fieldset className="lw-merge__sides">
                      <legend className="lw-sr">Keep for {path}</legend>
                      {(["draft", "live"] as const).map((side) => (
                        <label className={`lw-merge__side${choices[path] === side ? " is-chosen" : ""}`} key={side}>
                          <span className="lw-merge__head"><input checked={choices[path] === side} name={`merge-${path}`} onChange={() => setChoices((current) => ({ ...current, [path]: side }))} type="radio" />{side === "draft" ? "Keep the draft's" : "Take live's"}</span>
                          <pre className="lw-code-block lw-merge__value">{shown(valueAtPath(side === "draft" ? draftDocument : liveDocument, path))}</pre>
                        </label>
                      ))}
                    </fieldset>
                    {loaded?.base ? <details><summary className="lw-faint lw-note">When the draft started</summary><pre className="lw-code-block lw-merge__value">{shown(valueAtPath(loaded.base, path))}</pre></details> : null}
                  </li>
                ))}
              </ul>
              {unresolved ? <p className="lw-secondary lw-note">{unresolved} still to choose.</p> : null}
            </>
          ) : <Notice tone="info">No conflicts: every change combines cleanly.</Notice>}
          <p className="lw-secondary lw-note">Afterwards the draft needs checking again before it can be published.</p>
        </div>
      )}
    </ConfirmDialog>
  );
}

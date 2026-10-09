import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { adminRequest, type RevisionEdits, RevisionEditsSchema } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { Badge } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";

const KIND_LABEL: Readonly<Record<RevisionEdits["items"][number]["kind"], string>> = {
  created: "Started",
  edited: "Edited",
  promoted: "Copied from another environment",
  rebased: "Brought up to date"
};

function by(adminID: string): ReactNode {
  return <><span className="lw-mono lw-mono--sm">{adminID}</span>{adminID.startsWith("tok_") ? <> <Badge variant="soft">API</Badge></> : null}</>;
}

/** Who changed one revision, when, and which paths. Values are never recorded, so none are shown. */
export function EditHistory({ revisionID, updatedAt }: { revisionID: string; updatedAt?: string }) {
  const edits = useQuery({
    queryFn: async () => {
      const response = (await adminRequest(`/admin/v1/config-revisions/${revisionID}/edits`, RevisionEditsSchema)).data;
      if (response.revision_id !== revisionID) throw new Error("The edit history belonged to another revision.");
      return response;
    },
    queryKey: ["revision", revisionID, "edits", updatedAt],
    retry: false
  });
  if (edits.error) return <ProblemNotice problem={problemFromError(edits.error)} />;
  if (!edits.data) return <p className="lw-page-status" role="status">Loading the edit history…</p>;
  if (!edits.data.items.length) return <p className="lw-secondary lw-note">No edits were recorded. Revisions saved before this server version don&apos;t have a history.</p>;
  return (
    <>
      <ol aria-label="Edit history" className="lw-edit-history">
        {edits.data.items.map((edit) => (
          <li className="lw-edit" key={edit.version}>
            <div className="lw-edit__head">
              <strong>{KIND_LABEL[edit.kind]}</strong>
              <span className="lw-faint">by {by(edit.edited_by)} · {new Date(edit.edited_at).toLocaleString()}</span>
            </div>
            {edit.changes.length ? (
              <ul className="lw-plan-list">
                {edit.changes.slice(0, 8).map((change, index) => <li key={`${change.path}-${index}`}><span className={`lw-plan-op is-${change.operation}`}>{change.operation}</span><code className="lw-mono lw-mono--sm">{change.path}</code></li>)}
              </ul>
            ) : <span className="lw-faint lw-note">{edit.kind === "created" ? "Started from the live configuration." : "No paths changed."}</span>}
            {edit.change_count > Math.min(edit.changes.length, 8) ? <span className="lw-faint lw-note">and {edit.change_count - Math.min(edit.changes.length, 8)} more</span> : null}
          </li>
        ))}
      </ol>
      {edits.data.truncated ? <p className="lw-secondary lw-note">Only the newest 200 edits are shown.</p> : null}
    </>
  );
}

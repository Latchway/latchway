import { useId, useState } from "react";

import { problemFromError } from "../../api/auth";
import { ConfirmDialog, Field, Input } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";

/** Changes a display name. Slugs stay as they are, because configuration, URLs and the CLI use them. */
export function RenameDialog({ current, kind, onClose, onRename, slug }: { current: string; kind: string; onClose: () => void; onRename: (name: string) => Promise<void>; slug: string }) {
  const [name, setName] = useState(current);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<unknown>();
  const inputID = useId();
  const trimmed = name.trim();
  const valid = trimmed.length > 0 && trimmed.length <= 200 && trimmed !== current;

  async function rename(): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      await onRename(trimmed);
    } catch (error) {
      setProblem(error);
      setBusy(false);
    }
  }

  return (
    <ConfirmDialog confirmDisabled={!valid || busy} confirmLabel="Rename" description={`Only the display name changes. The slug ${slug} stays, so configuration, links and CLI commands keep working.`} onCancel={onClose} onConfirm={() => void rename()} pending={busy} title={`Rename ${kind}`}>
      <Field id={inputID} label="Display name">
        <Input id={inputID} maxLength={200} onChange={(event) => setName(event.target.value)} value={name} />
      </Field>
      {problem ? <ProblemNotice problem={problemFromError(problem)} /> : null}
    </ConfirmDialog>
  );
}

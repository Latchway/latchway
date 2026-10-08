import { useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";

import { adminRequest, type Promotion, PromotionSchema } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useWorkspace } from "../../app/workspace-context-value";
import { Button, ConfirmDialog, Field, Notice } from "../../ui";
import { validStrongETag } from "../configuration-slice";
import { ProblemNotice } from "../control-plane-pages";
import { promotionPath } from "./merge-paths";

/**
 * Starts this environment's draft from another environment's live configuration. The server keeps this
 * environment's own sign-in providers, app checks, components and AI connections, and lists entries that only the
 * source has so they can be reviewed before publishing.
 */
export function PromoteDialog({ onClose, onDone }: { onClose: () => void; onDone: (promotion: Promotion) => void }) {
  const workspace = useWorkspace();
  const queryClient = useQueryClient();
  const target = workspace.environment;
  const sources = workspace.environments.filter((environment) => environment.id !== target?.id && environment.application_id === workspace.application?.id);
  const [source, setSource] = useState(sources[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const sourceID = useId();
  const descriptionID = useId();
  const sourceName = sources.find((environment) => environment.id === source)?.display_name ?? "the other environment";
  const formRef = useRef<HTMLFormElement>(null);

  async function promote(form: HTMLFormElement | null): Promise<void> {
    if (!target || !source) return;
    const description = form ? String(new FormData(form).get("description") ?? "").trim() : "";
    setBusy(true);
    setProblem(undefined);
    try {
      const response = await adminRequest(`/admin/v1/environments/${target.id}/config-revisions/promote`, PromotionSchema, {
        body: { source_environment_id: source, ...(description ? { description } : {}) },
        method: "POST"
      });
      if (response.data.revision.environment_id !== target.id || response.data.promotion.source_environment_id !== source || !validStrongETag(response.etag)) {
        throw new Error("The server's promotion didn't match the environments asked for.");
      }
      await queryClient.invalidateQueries({ queryKey: ["environment", target.id] });
      onDone(response.data);
    } catch (error) {
      const failure = problemFromError(error);
      setProblem(failure.status === 409
        ? { ...failure, detail: `${target.display_name} already has an unpublished draft. Publish or discard it first.`, title: "There's already a draft" }
        : failure.status === 404 ? { ...failure, detail: `Nothing is live in ${sourceName} yet, so there's nothing to copy.`, title: "Nothing to copy" } : failure);
    } finally {
      setBusy(false);
    }
  }

  return (
    <ConfirmDialog
      confirmDisabled={!source || busy}
      confirmLabel="Start Draft"
      description={`Starts ${target?.display_name ?? "this environment"}'s draft from ${sourceName}'s live configuration. Nothing is published.`}
      onCancel={onClose}
      onConfirm={() => void promote(formRef.current)}
      pending={busy}
      size="wide"
      title="Copy from another environment?"
    >
      <form className="lw-stack lw-stack--tight" onSubmit={(event) => { event.preventDefault(); void promote(event.currentTarget); }} ref={formRef}>
        <Field id={sourceID} label="Copy from">
          <select className="lw-select" id={sourceID} onChange={(event) => setSource(event.target.value)} value={source}>
            {sources.map((environment) => <option key={environment.id} value={environment.id}>{environment.display_name}</option>)}
          </select>
        </Field>
        <Field hint="Optional. Saved with the draft." id={descriptionID} label="Description">
          <input className="lw-input" defaultValue={`From ${sourceName}`} id={descriptionID} maxLength={512} name="description" />
        </Field>
        <ul className="lw-issue-list lw-note">
          <li>Features, models, limit plans, pricing, session and privacy settings come from {sourceName}.</li>
          <li>Sign-in providers, app checks, components and AI connections that {target?.display_name ?? "this environment"} already has stay as they are.</li>
          <li>Ones only {sourceName} has are copied and listed for review: they may point at its projects, app identifiers, base URLs or secrets.</li>
        </ul>
      </form>
      {!sources.length ? <Notice tone="info">This application has no other environment to copy from.</Notice> : null}
      {problem ? <ProblemNotice problem={problem} /> : null}
    </ConfirmDialog>
  );
}

/** What a promotion copied and kept, and what needs a look before publishing. */
export function PromotionSummary({ onDismiss, promotion }: { onDismiss: () => void; promotion: Promotion }) {
  return (
    <Notice action={<Button onClick={onDismiss} size="sm">Dismiss</Button>} title={`Draft started from ${promotion.promotion.source_revision_id}`} tone={promotion.promotion.review.length ? "warning" : "success"}>
      <p className="lw-note">Copied: {promotion.promotion.copied.map(promotionPath).join(", ") || "nothing"}. Kept: {promotion.promotion.kept.map(promotionPath).join(", ")}.</p>
      {promotion.promotion.review.length ? (
        <>
          <p className="lw-note">Review before publishing; these came from the other environment:</p>
          <ul className="lw-issue-list">{promotion.promotion.review.map((path) => <li key={path}>{promotionPath(path)}</li>)}</ul>
        </>
      ) : null}
    </Notice>
  );
}

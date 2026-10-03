import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { adminRequest, ConfigurationPlanSchema, type ConfigurationPlan } from "../../api/admin";
import { Button, buttonClass, ConfirmDialog } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";
import { draftProblem, type EnvironmentDraft } from "./environment-draft";

/** The status rail's change-set actions: review the draft, check it, or publish it after a final look at the plan. */
export function DraftActions({ draft }: { draft: EnvironmentDraft }) {
  const [plan, setPlan] = useState<ConfigurationPlan>();
  const [confirming, setConfirming] = useState(false);
  const [planError, setPlanError] = useState<unknown>();
  const revision = draft.draft;
  if (!revision) return null;
  const production = draft.environment?.kind === "production";
  const target = production ? "Production" : draft.environment?.display_name ?? "this environment";

  async function openPublish(): Promise<void> {
    setPlanError(undefined);
    setPlan(undefined);
    setConfirming(true);
    try {
      setPlan((await adminRequest(`/admin/v1/config-revisions/${revision?.id}/plan`, ConfigurationPlanSchema, { method: "POST" })).data);
    } catch (error) {
      setPlanError(error);
    }
  }

  return (
    <>
      <Link className={buttonClass({ size: "sm" })} search={(previous) => previous} to="/configuration-revisions">Review Changes</Link>
      {revision.state === "valid" ? (
        <Button disabled={!draft.canConfigure} icon="rocket" onClick={() => void openPublish()} size="sm" variant="primary">Publish{production ? " to Production" : ""}</Button>
      ) : (
        <Button disabled={!draft.canConfigure} loading={draft.busy} onClick={() => void draft.validate()} size="sm" variant="primary">{revision.state === "invalid" ? "Check Again" : "Validate"}</Button>
      )}
      {confirming ? (
        <ConfirmDialog
          confirmDisabled={!plan || draft.busy}
          confirmLabel={`Publish to ${target}`}
          description={`New requests in ${target} use this configuration as soon as it's published. Requests already running keep the current one. Rolling back later creates a new revision.`}
          onCancel={() => setConfirming(false)}
          onConfirm={() => void draft.publish().then((published) => { if (published) setConfirming(false); })}
          pending={draft.busy}
          size="wide"
          title={`Publish ${revision.id} to ${target}?`}
        >
          {planError ? <ProblemNotice problem={draftProblem(planError)} /> : null}
          {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
          {plan ? (
            <div className="lw-stack lw-stack--tight">
              <p className="lw-note"><strong>{plan.changes.length} change{plan.changes.length === 1 ? "" : "s"}</strong>{plan.warnings.length ? ` · ${plan.warnings.length} warning${plan.warnings.length === 1 ? "" : "s"}` : " · no warnings"}</p>
              <ul className="lw-plan-list">
                {plan.changes.slice(0, 12).map((change, index) => <li key={`${change.path}-${index}`}><span className={`lw-plan-op is-${change.operation}`}>{change.operation}</span><code className="lw-mono lw-mono--sm">{change.path}</code>{change.summary ? <span className="lw-faint">{change.summary}</span> : null}</li>)}
              </ul>
              {plan.changes.length > 12 ? <p className="lw-secondary lw-note">and {plan.changes.length - 12} more. Review Changes lists them all.</p> : null}
              {plan.warnings.map((warning, index) => <p className="lw-text-warning lw-note" key={`${warning.code}-${index}`}>{warning.code}: {warning.message}</p>)}
            </div>
          ) : planError ? null : <p role="status">Loading the server's plan…</p>}
        </ConfirmDialog>
      ) : null}
    </>
  );
}

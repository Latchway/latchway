import { useState } from "react";

import type { AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { useCapabilities } from "../app/permissions";
import { useConsoleCompatibility } from "../app/console-compatibility-context";
import { type DraftSaveResult, useEnvironmentDraft } from "./build/environment-draft";
import type { JSONRecord } from "./configuration-slice";

export interface TaskConfigurationDraft extends DraftSaveResult {
  etag?: string;
}

export function localTaskProblem(detail: string, title = "Configuration task is incomplete"): AdminProblem {
  return { code: "request_invalid", detail, retryable: false, status: 0, title };
}

/**
 * A guided configuration task. Its changes land in the environment's shared working draft (see environment-draft),
 * computed from the working document so other unpublished edits are kept; a draft that changed meanwhile is refused.
 */
export function useConfigurationTask() {
  const session = useConsoleSession();
  const consoleCompatibility = useConsoleCompatibility();
  const shared = useEnvironmentDraft();
  const [review, setReview] = useState<TaskConfigurationDraft>();
  const [localProblem, setLocalProblem] = useState<AdminProblem>();
  const source = shared.draft ?? shared.active;
  const { can } = useCapabilities();
  const signedIn = session.data?.mode === "configured";
  const canManageSecrets = consoleCompatibility.mutationAllowed && signedIn && can("manage_secrets");
  const canRunSelfTests = consoleCompatibility.mutationAllowed && signedIn && can("run_self_tests");
  const activeDraft = review && review.revision.environment_id === shared.environment?.id && review.revision.id === shared.draft?.id ? review : undefined;

  async function stage(document: JSONRecord, description: string): Promise<TaskConfigurationDraft | undefined> {
    if (!source) return undefined;
    setLocalProblem(undefined);
    // The description names the draft only when this change starts it; later changes join the same draft.
    const result = await shared.save(() => document, source.document as JSONRecord, description);
    setReview(result);
    return result;
  }

  async function publish() {
    const revision = await shared.publish();
    if (revision) setReview(undefined);
    return revision;
  }

  return {
    /** The live revision; self-tests and samples run against it, never against a draft. */
    active: shared.active,
    activeDraft,
    application: shared.application,
    busy: shared.busy,
    canConfigure: shared.canConfigure,
    canManageSecrets,
    canRunSelfTests,
    configuration: { error: shared.activeError, isFetching: shared.busy, isPending: shared.isPending, refetch: shared.refetch },
    environment: shared.environment,
    mutationAllowed: consoleCompatibility.mutationAllowed,
    problem: localProblem ?? shared.problem,
    publish,
    setDraft: (next: TaskConfigurationDraft | undefined) => setReview(next),
    setProblem: (problem: AdminProblem | undefined) => { setLocalProblem(problem); if (!problem) shared.setProblem(undefined); },
    /** The working configuration: the draft when one exists, otherwise the live revision. */
    source,
    sourceETag: shared.activeETag,
    stage
  };
}

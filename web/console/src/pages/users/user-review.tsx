import { useEffect, useRef, useState } from "react";

import {
  type ApplicationUser,
  getUserOperationImpact,
  requireApplicationUserAppReverification,
  requireApplicationUserReauthentication,
  setApplicationUserBlocked,
  type UserOperationAction,
  type UserOperationImpact
} from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { applyUserBatch, previewUserBatch, type UserBatchImpact } from "../../api/user-insights";
import { ConfirmDialog, type Impact, ImpactDialog } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";
import { ACTION_TITLE } from "./users-model";


const ACTION_COPY: Record<UserOperationAction, { acknowledgement: string; confirm: string; description: string; undo: string }> = {
  block: {
    acknowledgement: "I understand this signs the user out everywhere now, and unblocking never restores revoked sessions.",
    confirm: "Block User",
    description: "Refuses every request from this user and revokes their sessions and refresh tokens across the application.",
    undo: "Unblock lets them sign in again; revoked sessions stay revoked."
  },
  require_app_reverification: {
    acknowledgement: "I understand each installation must verify again before it can refresh its sessions.",
    confirm: "Require Re-verification",
    description: "Every installation of this user must prove it's a genuine app again before it can refresh.",
    undo: "Nothing to undo: the app re-verifies on its next launch."
  },
  require_reauthentication: {
    acknowledgement: "I understand the user must sign in again on every installation.",
    confirm: "Require Sign-in",
    description: "Ends this user's sessions so their apps ask them to sign in again, picking up changed claims or plans.",
    undo: "Nothing to undo: they sign in again and continue."
  },
  unblock: {
    acknowledgement: "I understand the user can sign in and call features again immediately.",
    confirm: "Unblock User",
    description: "Lets this user sign in and make requests again. Sessions revoked by the block are not restored.",
    undo: "Block again at any time."
  }
};

function impactsOf(impact: UserOperationImpact, before?: UserOperationImpact): Impact[] {
  const rows: Array<[keyof UserOperationImpact["counts"], string]> = [
    ["active_installation_families", "installations"],
    ["active_client_components", "app parts"],
    ["active_session_grants", "user sessions"],
    ["active_refresh_tokens", "user refresh tokens"],
    ["active_component_sessions", "component sessions"],
    ["active_component_refresh_tokens", "component refresh tokens"]
  ];
  return rows.map(([key, label]) => ({ before: before?.counts[key], count: impact.counts[key], label }));
}

export interface OperationOutcome {
  message: string;
  user: ApplicationUser;
}

interface UserOperationReviewProps {
  action: UserOperationAction;
  environmentID: string;
  onClose: () => void;
  onDone: (outcome: OperationOutcome) => void;
  user: ApplicationUser;
}

/** Runs one user operation through its server preview. Counts that change before confirming are shown and re-acknowledged. */
export function UserOperationReview({ action, environmentID, onClose, onDone, user }: UserOperationReviewProps) {
  const [impact, setImpact] = useState<UserOperationImpact>();
  const [previous, setPrevious] = useState<UserOperationImpact>();
  const [revision, setRevision] = useState(0);
  const [problem, setProblem] = useState<AdminProblem>();
  const [pending, setPending] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    getUserOperationImpact(user.id, environmentID, action).then(
      (response) => setImpact(response.data),
      (error: unknown) => setProblem(problemFromError(error))
    );
  }, [action, environmentID, user.id]);

  async function confirm(reason: string): Promise<void> {
    if (!impact) return;
    setPending(true);
    setProblem(undefined);
    const confirmation = { acknowledge_immediate_effect: true as const, impact_token: impact.impact_token, reason };
    try {
      const result = action === "block" || action === "unblock"
        ? await setApplicationUserBlocked(user.id, environmentID, action === "block", confirmation)
        : action === "require_reauthentication"
          ? await requireApplicationUserReauthentication(user.id, environmentID, confirmation)
          : await requireApplicationUserAppReverification(user.id, environmentID, confirmation);
      const updated = "operation_id" in result.data ? result.data.user : result.data;
      const operation = "operation_id" in result.data ? ` Operation ${result.data.operation_id}.` : "";
      onDone({ message: `${ACTION_TITLE[action]} completed.${operation}`, user: updated });
    } catch (error) {
      const failure = problemFromError(error);
      if (failure.code === "conflict") {
        // The user changed since the preview: reload it, show what moved and ask again.
        try {
          const refreshed = await getUserOperationImpact(user.id, environmentID, action);
          setPrevious(impact);
          setImpact(refreshed.data);
          setRevision((current) => current + 1);
        } catch (reloadError) {
          setProblem(problemFromError(reloadError));
        }
      } else {
        setProblem(failure.code === "operation_indeterminate"
          ? { ...failure, detail: `${failure.detail} Check the audit log before retrying.` }
          : failure);
      }
    } finally {
      setPending(false);
    }
  }

  if (!impact) {
    return (
      <ConfirmDialog confirmDisabled confirmLabel="Review" onCancel={onClose} onConfirm={onClose} title={ACTION_TITLE[action]}>
        {problem ? <ProblemNotice problem={problem} /> : <p role="status">Loading the server's impact preview…</p>}
      </ConfirmDialog>
    );
  }

  if (!impact.applicable) {
    return (
      <ConfirmDialog confirmLabel="Close" description={impact.summary} onCancel={onClose} onConfirm={onClose} title={`${ACTION_TITLE[action]} doesn't apply`}>
        <p className="lw-secondary lw-note">The user is {impact.current_status}, so this action would change nothing. Choose a different action.</p>
      </ConfirmDialog>
    );
  }

  const copy = ACTION_COPY[action];
  return (
    <ImpactDialog
      acknowledgement={copy.acknowledgement}
      confirmLabel={copy.confirm}
      description={copy.description}
      facts={[
        ["Takes effect", impact.immediate ? "Immediately" : "On the next refresh"],
        ["Undo", copy.undo],
        ["Access", impact.access_effect],
        ["Server summary", impact.summary]
      ]}
      impacts={impactsOf(impact, previous)}
      onCancel={onClose}
      onConfirm={({ reason }) => void confirm(reason)}
      pending={pending}
      reasonHint="Only that a reason was given reaches the audit log; its text isn't stored. Don't paste tokens or personal data."
      revision={String(revision)}
      scope={<>Reach: <code className="lw-code-inline">{user.id}</code> across every installation in this application</>}
      stale={previous ? "Counts changed since you opened this. Review the new numbers and acknowledge again." : undefined}
      targetId={user.id}
      title={`${ACTION_TITLE[action]}?`}
    >
      {problem ? <ProblemNotice problem={problem} /> : null}
    </ImpactDialog>
  );
}

interface BulkResult {
  id: string;
  outcome: "done" | "skipped" | "unknown" | "failed";
  text: string;
}

/**
 * Requires sign-in for several users. The API has no batch endpoint, so each user runs as its own reviewed operation
 * with its own preview token, and the result is reported per user.
 */
export function BulkSignInReview({ environmentID, onClose, onFinished, users }: { environmentID: string; onClose: () => void; onFinished: (updated: ApplicationUser[]) => void; users: readonly ApplicationUser[] }) {
  const [impacts, setImpacts] = useState<Map<string, UserOperationImpact>>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [results, setResults] = useState<BulkResult[]>();
  const [pending, setPending] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    Promise.all(users.map(async (user) => [user.id, (await getUserOperationImpact(user.id, environmentID, "require_reauthentication")).data] as const)).then(
      (entries) => setImpacts(new Map(entries)),
      (error: unknown) => setProblem(problemFromError(error))
    );
  }, [environmentID, users]);

  async function run(reason: string): Promise<void> {
    if (!impacts) return;
    setPending(true);
    const outcomes: BulkResult[] = [];
    const updated: ApplicationUser[] = [];
    for (const user of users) {
      const impact = impacts.get(user.id);
      if (!impact?.applicable) {
        outcomes.push({ id: user.id, outcome: "skipped", text: "Doesn't apply to this user's current state." });
        continue;
      }
      try {
        const result = await requireApplicationUserReauthentication(user.id, environmentID, { acknowledge_immediate_effect: true, impact_token: impact.impact_token, reason });
        updated.push(result.data.user);
        outcomes.push({ id: user.id, outcome: "done", text: `Operation ${result.data.operation_id}.` });
      } catch (error) {
        const failure = problemFromError(error);
        outcomes.push(failure.code === "operation_indeterminate"
          ? { id: user.id, outcome: "unknown", text: `Outcome unknown${failure.operationId ? ` (operation ${failure.operationId})` : ""}. Check the audit log before retrying.` }
          : failure.code === "conflict"
            ? { id: user.id, outcome: "skipped", text: "The user changed after the preview; review them on their own." }
            : { id: user.id, outcome: "failed", text: failure.detail });
      }
    }
    setPending(false);
    setResults(outcomes);
    onFinished(updated);
  }

  if (results) {
    const count = (outcome: BulkResult["outcome"]) => results.filter((result) => result.outcome === outcome).length;
    return (
      <ConfirmDialog confirmLabel="Done" description={`${count("done")} done · ${count("skipped")} skipped · ${count("unknown")} unknown · ${count("failed")} failed`} onCancel={onClose} onConfirm={onClose} size="wide" title="Require sign-in finished">
        <ul className="lw-bulk-results">
          {results.map((result) => <li className={`is-${result.outcome}`} key={result.id}><code className="lw-mono lw-mono--sm">{result.id}</code><strong>{result.outcome === "done" ? "Done" : result.outcome === "skipped" ? "Skipped" : result.outcome === "unknown" ? "Unknown" : "Failed"}</strong><span>{result.text}</span></li>)}
        </ul>
      </ConfirmDialog>
    );
  }
  if (!impacts) {
    return (
      <ConfirmDialog confirmDisabled confirmLabel="Review" onCancel={onClose} onConfirm={onClose} title={`Require sign-in for ${users.length} users`}>
        {problem ? <ProblemNotice problem={problem} /> : <p role="status">Loading a preview for each user…</p>}
      </ConfirmDialog>
    );
  }
  const totals = [...impacts.values()].reduce((sum, impact) => ({
    families: sum.families + impact.counts.active_installation_families,
    refresh: sum.refresh + impact.counts.active_refresh_tokens + impact.counts.active_component_refresh_tokens,
    sessions: sum.sessions + impact.counts.active_session_grants + impact.counts.active_component_sessions
  }), { families: 0, refresh: 0, sessions: 0 });
  const applicable = [...impacts.values()].filter((impact) => impact.applicable).length;
  const target = `${users.length} users`;
  return (
    <ImpactDialog
      acknowledgement="I understand each selected user must sign in again on every installation."
      confirmLabel={`Require Sign-in for ${applicable}`}
      description="Each user runs as a separate reviewed operation with its own preview. Results are reported per user."
      facts={[["Applies to", `${applicable} of ${users.length} selected users`], ["Undo", "Nothing to undo: they sign in again and continue."]]}
      impacts={[{ count: totals.families, label: "installations" }, { count: totals.sessions, label: "sessions" }, { count: totals.refresh, label: "refresh tokens" }]}
      onCancel={onClose}
      onConfirm={({ reason }) => void run(reason)}
      pending={pending}
      reasonHint="Only that a reason was given reaches the audit log; its text isn't stored."
      targetId={target}
      title={`Require sign-in for ${users.length} users?`}
    >
      {applicable < users.length ? <p className="lw-secondary lw-note">{users.length - applicable} selected users wouldn't change and will be skipped.</p> : null}
    </ImpactDialog>
  );
}

const BATCH_OUTCOME_TEXT = {
  changed: "The user changed after the preview; review them on their own.",
  done: "Done.",
  failed: "The server couldn't apply it; check the audit log before retrying.",
  forbidden: "Your role can't act on this user.",
  not_found: "The user no longer exists in this environment."
} as const;

/**
 * One reviewed action for up to 100 users through the server's batch: a preview gives each user's impact and token,
 * and the batch skips anyone who changed since, reporting each outcome.
 */
export function BulkUserReview({ action, environmentID, onClose, onFinished, users }: { action: UserOperationAction; environmentID: string; onClose: () => void; onFinished: () => void; users: readonly ApplicationUser[] }) {
  const [preview, setPreview] = useState<UserBatchImpact>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [results, setResults] = useState<BulkResult[]>();
  const [pending, setPending] = useState(false);
  const started = useRef(false);
  const copy = ACTION_COPY[action];

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    previewUserBatch(environmentID, action, users.map((user) => user.id)).then(setPreview, (error: unknown) => setProblem(problemFromError(error)));
  }, [action, environmentID, users]);

  async function run(reason: string): Promise<void> {
    if (!preview) return;
    setPending(true);
    setProblem(undefined);
    const items = preview.items.flatMap((item) => item.impact?.applicable ? [{ impact_token: item.impact.impact_token, user_id: item.user_id }] : []);
    const skipped: BulkResult[] = preview.items.filter((item) => !item.impact?.applicable).map((item) => ({ id: item.user_id, outcome: "skipped", text: item.outcome === "not_found" ? BATCH_OUTCOME_TEXT.not_found : "Doesn't apply to this user's current state." }));
    try {
      const applied = items.length ? await applyUserBatch(environmentID, action, reason, items) : undefined;
      const outcomes: BulkResult[] = (applied?.results ?? []).map((result) => ({
        id: result.user_id,
        outcome: result.outcome === "done" ? "done" : result.outcome === "failed" ? "failed" : "skipped",
        text: result.outcome === "done" ? `Operation ${result.operation_id ?? ""}.` : BATCH_OUTCOME_TEXT[result.outcome]
      }));
      setResults([...outcomes, ...skipped]);
      onFinished();
    } catch (error) {
      const failure = problemFromError(error);
      if (failure.code === "operation_indeterminate") {
        setResults(items.map((item) => ({ id: item.user_id, outcome: "unknown", text: "Outcome unknown. Check the audit log before retrying." })));
        onFinished();
      } else {
        setProblem(failure);
      }
    } finally {
      setPending(false);
    }
  }

  if (results) {
    const count = (outcome: BulkResult["outcome"]) => results.filter((result) => result.outcome === outcome).length;
    return (
      <ConfirmDialog confirmLabel="Done" description={`${count("done")} done · ${count("skipped")} skipped · ${count("unknown")} unknown · ${count("failed")} failed`} onCancel={onClose} onConfirm={onClose} size="wide" title={`${ACTION_TITLE[action]} finished`}>
        <ul className="lw-bulk-results">
          {results.map((result) => <li className={`is-${result.outcome}`} key={result.id}><code className="lw-mono lw-mono--sm">{result.id}</code><strong>{result.outcome === "done" ? "Done" : result.outcome === "skipped" ? "Skipped" : result.outcome === "unknown" ? "Unknown" : "Failed"}</strong><span>{result.text}</span></li>)}
        </ul>
      </ConfirmDialog>
    );
  }
  if (!preview) {
    return (
      <ConfirmDialog confirmDisabled confirmLabel="Review" onCancel={onClose} onConfirm={onClose} title={`${ACTION_TITLE[action]} for ${users.length} users`}>
        {problem ? <ProblemNotice problem={problem} /> : <p role="status">Previewing each user…</p>}
      </ConfirmDialog>
    );
  }
  const totals = preview.totals;
  return (
    <ImpactDialog
      acknowledgement={copy.acknowledgement}
      confirmLabel={`${copy.confirm} for ${preview.applicable}`}
      description={`${copy.description} Each user is changed and audited separately.`}
      facts={[["Applies to", `${preview.applicable} of ${users.length} selected users`], ["Undo", copy.undo]]}
      impacts={[
        { count: totals.active_installation_families, label: "installations" },
        { count: totals.active_session_grants + totals.active_component_sessions, label: "sessions" },
        { count: totals.active_refresh_tokens + totals.active_component_refresh_tokens, label: "refresh tokens" }
      ]}
      onCancel={onClose}
      onConfirm={({ reason }) => void run(reason)}
      pending={pending}
      reasonHint="Only that a reason was given reaches the audit log; its text isn't stored."
      targetId={`${users.length} users`}
      title={`${ACTION_TITLE[action]} for ${users.length} users?`}
    >
      {preview.applicable < users.length ? <p className="lw-secondary lw-note">{users.length - preview.applicable} selected users wouldn&apos;t change and will be skipped.</p> : null}
      {problem ? <ProblemNotice problem={problem} /> : null}
    </ImpactDialog>
  );
}

export function ViewOnlyNotice() {
  return <p className="lw-secondary lw-note">View only: changing users needs the <code className="lw-code-inline">revoke_installations</code> capability. An organization owner can grant it in Team &amp; Access.</p>;
}


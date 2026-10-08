import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCapabilities } from "../../app/permissions";
import { useState } from "react";

import {
  adminRequest,
  ConfigurationPlanSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation,
  type MergePreview,
  MergePreviewSchema,
  queryPath,
  RevisionSchema,
  ValidationSchema
} from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { ConfigurationRevisionResourcePageSchema } from "../../api/resources";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { useOptionalWorkspace } from "../../app/workspace-context-value";
import { cloneConfigurationDocument, type JSONRecord, validStrongETag } from "../configuration-slice";

/**
 * One working draft per environment, shared by every Build page.
 *
 * The draft is the newest revision that is still a draft (draft, valid or invalid) and newer than the active one.
 * Revision versions only grow, so a draft created before the current active revision is older than it and is no
 * longer the working draft. The server is authoritative either way: activating a draft whose base is no longer
 * active is refused with a conflict.
 */
export const DRAFT_STATES = new Set(["draft", "valid", "invalid"]);

export function activeConfigurationQueryKey(environmentID: string) {
  return ["environment", environmentID, "active-configuration", "shared"] as const;
}

export function workingDraftQueryKey(environmentID: string) {
  return ["environment", environmentID, "working-draft"] as const;
}

export interface DraftSaveResult {
  plan?: ConfigurationPlan;
  report: ConfigurationValidation;
  revision: ConfigurationRevision;
}

class DraftContextMismatch extends Error {}
class DraftChangedElsewhere extends Error {}

const MISMATCH_PROBLEM: AdminProblem = { code: "invalid_response", detail: "A configuration revision did not belong to the selected environment.", retryable: true, status: 0, title: "Configuration context mismatch" };

export function draftProblem(error: unknown): AdminProblem {
  if (error instanceof DraftContextMismatch) return MISMATCH_PROBLEM;
  if (error instanceof DraftChangedElsewhere) {
    return { code: "etag_mismatch", detail: "The draft changed since this page loaded it, so your change wasn't saved. Refresh to see the current draft, then make the change again.", retryable: true, status: 412, title: "The draft changed" };
  }
  const problem = problemFromError(error);
  if (problem.code === "etag_mismatch" || problem.status === 412) {
    return { ...problem, detail: "The draft changed in another tab or by another administrator since this page loaded it. Your change wasn't saved; review the current draft and try again.", title: "The draft changed" };
  }
  if (problem.code === "conflict" || problem.status === 409) {
    return { ...problem, detail: "This draft started from a configuration that's no longer live, so it can't be published as it is. Review it under Changes → Draft.", title: "The draft is out of date" };
  }
  return problem;
}

function requireETag(etag: string | undefined, what: string): string {
  if (!validStrongETag(etag)) throw new Error(`The Admin API omitted the strong ETag for ${what}.`);
  return etag;
}

export function useEnvironmentDraft() {
  const { can } = useCapabilities();
  const queryClient = useQueryClient();
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const workspace = useOptionalWorkspace();
  const environment = workspace?.environment;
  const environmentID = environment?.id ?? "";
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  const [lastSave, setLastSave] = useState<DraftSaveResult & { environmentID: string }>();
  /** Servers with the draft lifecycle (ADR 0048) keep a validated draft editable, discard drafts and keep publish notes. */
  const lifecycle = compatibility.status?.server_capabilities.includes("admin_configuration_drafts") ?? false;

  const active = useQuery({
    enabled: Boolean(environmentID),
    queryFn: async () => {
      const response = await adminRequest(`/admin/v1/environments/${environmentID}/config`, RevisionSchema);
      if (response.data.environment_id !== environmentID) throw new DraftContextMismatch("active");
      return response;
    },
    queryKey: activeConfigurationQueryKey(environmentID),
    retry: false
  });

  const working = useQuery({
    enabled: Boolean(environmentID) && active.isSuccess,
    queryFn: async () => {
      const newest = (await adminRequest(queryPath(`/admin/v1/environments/${environmentID}/config-revisions`, { page_size: "1" }), ConfigurationRevisionResourcePageSchema)).data.items[0];
      const activeVersion = active.data?.data.version ?? 0;
      if (!newest || !DRAFT_STATES.has(newest.state) || newest.version <= activeVersion) return null;
      const draft = await adminRequest(`/admin/v1/config-revisions/${newest.id}`, RevisionSchema);
      if (draft.data.environment_id !== environmentID) throw new DraftContextMismatch("draft");
      return draft;
    },
    queryKey: [...workingDraftQueryKey(environmentID), active.data?.data.id ?? "none"],
    retry: false
  });

  const draft = working.data ?? undefined;
  const activeRevision = active.data?.data;
  const document = (draft?.data.document ?? activeRevision?.document) as JSONRecord | undefined;
  const canConfigure = session.data?.mode === "configured"
    && compatibility.mutationAllowed
    && can("activate_configuration")
    && workspace?.application?.status !== "disabled"
    && environment?.status !== "disabled";

  async function refresh(): Promise<void> {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: workingDraftQueryKey(environmentID) }),
      queryClient.invalidateQueries({ queryKey: ["environment", environmentID, "configuration-revisions"] })
    ]);
  }

  /** Loads the newest draft with its ETag, or starts one from the live configuration. */
  async function openDraft(description = "Admin console draft"): Promise<{ etag: string; revision: ConfigurationRevision }> {
    const activeNow = await adminRequest(`/admin/v1/environments/${environmentID}/config`, RevisionSchema);
    if (activeNow.data.environment_id !== environmentID) throw new DraftContextMismatch("active");
    const newest = (await adminRequest(queryPath(`/admin/v1/environments/${environmentID}/config-revisions`, { page_size: "1" }), ConfigurationRevisionResourcePageSchema)).data.items[0];
    if (newest && DRAFT_STATES.has(newest.state) && newest.version > activeNow.data.version) {
      const existing = await adminRequest(`/admin/v1/config-revisions/${newest.id}`, RevisionSchema);
      if (existing.data.environment_id !== environmentID) throw new DraftContextMismatch("draft");
      if (existing.data.state !== "valid" || lifecycle) return { etag: requireETag(existing.etag, "the working draft"), revision: existing.data };
      // Older servers freeze a draft once it validates; carry its content into a fresh draft instead.
      const carried = await adminRequest(`/admin/v1/environments/${environmentID}/config-revisions`, RevisionSchema, {
        body: { description, document: existing.data.document },
        method: "POST"
      });
      if (carried.data.environment_id !== environmentID) throw new DraftContextMismatch("draft");
      return { etag: requireETag(carried.etag, "the new draft"), revision: carried.data };
    }
    const created = await adminRequest(`/admin/v1/environments/${environmentID}/config-revisions`, RevisionSchema, {
      body: { base_revision_id: activeNow.data.id, description },
      method: "POST"
    });
    if (created.data.environment_id !== environmentID) throw new DraftContextMismatch("draft");
    return { etag: requireETag(created.etag, "the new draft"), revision: created.data };
  }

  /**
   * Applies one change to the working draft. The change is a function of the current document, so it always lands on
   * the newest draft content; the replace uses the draft's strong ETag, and a concurrent edit is reported, not merged.
   */
  async function save(change: (document: JSONRecord) => JSONRecord, basis?: JSONRecord, description?: string): Promise<DraftSaveResult | undefined> {
    if (!canConfigure || !environmentID) return undefined;
    setBusy(true);
    setProblem(undefined);
    try {
      const opened = await openDraft(description);
      // A whole-document change computed from an earlier copy must not overwrite edits made since.
      if (basis && JSON.stringify(opened.revision.document) !== JSON.stringify(basis)) throw new DraftChangedElsewhere("basis");
      const next = change(cloneConfigurationDocument(opened.revision.document as JSONRecord));
      const replaced = await adminRequest(`/admin/v1/config-revisions/${opened.revision.id}`, RevisionSchema, { body: next, etag: opened.etag, method: "PATCH" });
      requireETag(replaced.etag, "the replaced draft");
      const report = (await adminRequest(`/admin/v1/config-revisions/${opened.revision.id}/validate`, ValidationSchema, { method: "POST" })).data;
      const plan = report.valid ? (await adminRequest(`/admin/v1/config-revisions/${opened.revision.id}/plan`, ConfigurationPlanSchema, { method: "POST" })).data : undefined;
      const result = { report, revision: replaced.data, ...(plan ? { plan } : {}) };
      setLastSave({ ...result, environmentID });
      await refresh();
      return result;
    } catch (error) {
      setProblem(draftProblem(error));
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  /** Publishes the working draft with its current ETag, with a publish note when the server keeps one. */
  async function publish(note?: string): Promise<ConfigurationRevision | undefined> {
    if (!canConfigure || !draft) return undefined;
    setBusy(true);
    setProblem(undefined);
    try {
      const current = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}`, RevisionSchema);
      const trimmed = note?.trim();
      const activated = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/activate`, RevisionSchema, {
        ...(lifecycle && trimmed ? { body: { note: trimmed } } : {}),
        etag: requireETag(current.etag, "the working draft"),
        method: "POST"
      });
      if (activated.data.environment_id !== environmentID) throw new DraftContextMismatch("activated");
      setLastSave(undefined);
      await Promise.all([queryClient.invalidateQueries({ queryKey: ["environment", environmentID] })]);
      return activated.data;
    } catch (error) {
      setProblem(draftProblem(error));
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  /** Discards the working draft: it stays in History as discarded and the environment has no draft. */
  async function discard(): Promise<boolean> {
    if (!canConfigure || !draft || !lifecycle) return false;
    setBusy(true);
    setProblem(undefined);
    try {
      const current = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}`, RevisionSchema);
      const discarded = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/discard`, RevisionSchema, { etag: requireETag(current.etag, "the working draft"), method: "POST" });
      if (discarded.data.id !== draft.data.id || discarded.data.state !== "discarded") throw new DraftContextMismatch("discarded");
      setLastSave(undefined);
      await refresh();
      return true;
    } catch (error) {
      setProblem(draftProblem(error));
      return false;
    } finally {
      setBusy(false);
    }
  }

  /** What bringing the stale working draft up to date would combine, by path. */
  async function previewRebase(): Promise<MergePreview> {
    if (!draft) throw new Error("There is no working draft.");
    const preview = (await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/rebase-preview`, MergePreviewSchema)).data;
    if (preview.revision_id !== draft.data.id) throw new DraftContextMismatch("rebase");
    return preview;
  }

  /** Moves the working draft onto the live revision, with a side chosen for every conflicting path. */
  async function rebase(liveRevisionID: string, resolutions: Record<string, "draft" | "live">): Promise<boolean> {
    if (!canConfigure || !draft || !lifecycle) return false;
    setBusy(true);
    setProblem(undefined);
    try {
      const current = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}`, RevisionSchema);
      const rebased = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/rebase`, RevisionSchema, {
        body: { live_revision_id: liveRevisionID, resolutions },
        etag: requireETag(current.etag, "the working draft"),
        method: "POST"
      });
      if (rebased.data.id !== draft.data.id || rebased.data.base_revision_id !== liveRevisionID) throw new DraftContextMismatch("rebased");
      setLastSave(undefined);
      await refresh();
      return true;
    } catch (error) {
      setProblem(draftProblem(error));
      return false;
    } finally {
      setBusy(false);
    }
  }

  /** Validates the working draft again, e.g. after referenced secrets were added. */
  async function validate(): Promise<ConfigurationValidation | undefined> {
    if (!canConfigure || !draft) return undefined;
    setBusy(true);
    setProblem(undefined);
    try {
      const report = (await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/validate`, ValidationSchema, { method: "POST" })).data;
      await refresh();
      return report;
    } catch (error) {
      setProblem(draftProblem(error));
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  const base = draft?.data.base_revision_id;
  return {
    active: activeRevision,
    activeDocument: activeRevision?.document as JSONRecord | undefined,
    activeError: active.error,
    activeETag: active.data?.etag,
    application: workspace?.application,
    busy,
    canConfigure,
    discard,
    document,
    draft: draft?.data,
    environment,
    isPending: active.isPending || (active.isSuccess && working.isPending),
    lastSave: lastSave?.environmentID === environmentID && lastSave.revision.id === draft?.data.id ? lastSave : undefined,
    problem: problem ?? (active.error ? draftProblem(active.error) : working.error ? draftProblem(working.error) : undefined),
    lifecycle,
    previewRebase,
    publish,
    rebase,
    refetch: () => Promise.all([active.refetch(), working.refetch()]),
    save,
    setProblem,
    /** The draft started from a revision that is no longer live, so it can't be published until it's brought up to date. */
    stale: Boolean(lifecycle && base && activeRevision && base !== activeRevision.id),
    validate
  };
}

export type EnvironmentDraft = ReturnType<typeof useEnvironmentDraft>;

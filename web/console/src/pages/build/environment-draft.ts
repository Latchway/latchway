import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCapabilities } from "../../app/permissions";
import { useState } from "react";

import {
  adminRequest,
  ConfigurationPlanSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation,
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
    return { ...problem, detail: "This draft was started from a configuration that is no longer live, so it can't be published. Make the change again: it will start a new draft from the live configuration.", title: "The draft is out of date" };
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
      return { etag: requireETag(existing.etag, "the working draft"), revision: existing.data };
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

  /** Publishes the working draft with its current ETag. */
  async function publish(): Promise<ConfigurationRevision | undefined> {
    if (!canConfigure || !draft) return undefined;
    setBusy(true);
    setProblem(undefined);
    try {
      const current = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}`, RevisionSchema);
      const activated = await adminRequest(`/admin/v1/config-revisions/${draft.data.id}/activate`, RevisionSchema, { etag: requireETag(current.etag, "the working draft"), method: "POST" });
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

  return {
    active: activeRevision,
    activeDocument: activeRevision?.document as JSONRecord | undefined,
    activeError: active.error,
    activeETag: active.data?.etag,
    application: workspace?.application,
    busy,
    canConfigure,
    document,
    draft: draft?.data,
    environment,
    isPending: active.isPending || (active.isSuccess && working.isPending),
    lastSave: lastSave?.environmentID === environmentID && lastSave.revision.id === draft?.data.id ? lastSave : undefined,
    problem: problem ?? (active.error ? draftProblem(active.error) : working.error ? draftProblem(working.error) : undefined),
    publish,
    refetch: () => Promise.all([active.refetch(), working.refetch()]),
    save,
    setProblem,
    validate
  };
}

export type EnvironmentDraft = ReturnType<typeof useEnvironmentDraft>;

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  adminRequest,
  RevisionSchema,
  type ConfigurationPlan,
  type ConfigurationRevision,
  type ConfigurationValidation
} from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";
import { latestConfigurationRevisionQueryOptions } from "../api/workspace";
import { useOptionalWorkspace } from "../app/workspace-context-value";
import { applyConfigurationSliceChange, type JSONRecord } from "./configuration-slice";

export interface TaskConfigurationDraft {
  etag: string;
  plan?: ConfigurationPlan;
  report: ConfigurationValidation;
  revision: ConfigurationRevision;
}

export function localTaskProblem(detail: string, title = "Configuration task is incomplete"): AdminProblem {
  return { code: "request_invalid", detail, retryable: false, status: 0, title };
}

export function useConfigurationTask(area: string) {
  const queryClient = useQueryClient();
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  const environment = workspace?.environment;
  const [published, setPublished] = useState<{ data: ConfigurationRevision; etag?: string }>();
  const [draft, setDraft] = useState<TaskConfigurationDraft>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const configuration = useQuery({
    enabled: Boolean(environment?.id),
    queryFn: async () => adminRequest(`/admin/v1/environments/${environment?.id}/config`, RevisionSchema),
    queryKey: ["environment", environment?.id ?? "none", "active-configuration", area],
    retry: false
  });
  const response = published?.data.environment_id === environment?.id ? published : configuration.data;
  const source = response?.data;
  const activeDraft = draft?.revision.environment_id === environment?.id ? draft : undefined;
  const canConfigure = session.data?.mode === "configured" && (session.data.session?.capabilities.includes("activate_configuration") ?? false);

  async function refreshLatest(): Promise<void> {
    if (!environment) return;
    await queryClient.invalidateQueries({ queryKey: latestConfigurationRevisionQueryOptions(environment.id).queryKey });
  }

  async function stage(document: JSONRecord, description: string): Promise<TaskConfigurationDraft | undefined> {
    if (!environment || !source) return undefined;
    setBusy(true);
    setProblem(undefined);
    setDraft(undefined);
    try {
      const result = await applyConfigurationSliceChange({
        activate: false,
        description,
        document,
        environmentID: environment.id,
        sourceRevisionID: source.id
      });
      const next = { etag: result.etag, report: result.report, revision: result.revision, ...(result.plan ? { plan: result.plan } : {}) };
      setDraft(next);
      await refreshLatest();
      return next;
    } catch (error) {
      setProblem(problemFromError(error));
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  async function publish(): Promise<ConfigurationRevision | undefined> {
    if (!activeDraft || !activeDraft.report.valid || !environment) return undefined;
    setBusy(true);
    setProblem(undefined);
    try {
      const activated = await adminRequest(`/admin/v1/config-revisions/${activeDraft.revision.id}/activate`, RevisionSchema, {
        etag: activeDraft.etag,
        method: "POST"
      });
      if (activated.data.environment_id !== environment.id) throw new Error("environment_mismatch");
      setPublished({ data: activated.data, ...(activated.etag ? { etag: activated.etag } : {}) });
      setDraft(undefined);
      await refreshLatest();
      return activated.data;
    } catch (error) {
      setProblem(error instanceof Error && error.message === "environment_mismatch"
        ? { code: "invalid_response", detail: "The activated revision did not match the selected environment.", retryable: true, status: 0, title: "Publish context mismatch" }
        : problemFromError(error));
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  return {
    activeDraft,
    application: workspace?.application,
    busy,
    canConfigure,
    configuration,
    environment,
    problem,
    publish,
    setDraft,
    setProblem,
    source,
    sourceETag: response?.etag,
    stage
  };
}

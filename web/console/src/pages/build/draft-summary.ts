import { changeSetSummary, configurationDiff } from "../changes/config-diff";
import type { JSONRecord } from "../configuration-slice";
import type { EnvironmentDraft } from "./environment-draft";

/** The status rail line for the working draft. A draft that equals live has nothing to publish and isn't shown. */
export function draftSummary(draft: EnvironmentDraft): { chip: string; text: string; title: string } | undefined {
  const revision = draft.draft;
  if (!revision) return undefined;
  const entries = configurationDiff(draft.activeDocument, revision.document as JSONRecord);
  if (!entries.length) return undefined;
  const issues = revision.validation?.issues.filter((issue) => issue.severity === "error").length ?? 0;
  const where = draft.environment ? ` in ${draft.environment.display_name}` : "";
  const state = revision.state === "valid"
    ? "Checked, ready to publish."
    : revision.state === "invalid"
      ? `${issues || "Some"} problem${issues === 1 ? "" : "s"} to fix before publishing.`
      : "Not validated yet.";
  return {
    chip: revision.state === "valid" ? "Draft ready" : revision.state === "invalid" ? "Draft has problems" : "Unpublished draft",
    text: `${entries.length} change${entries.length === 1 ? "" : "s"}${where} (${changeSetSummary(entries)}). ${state} Requests keep using the live configuration until it's published.`,
    title: "Unpublished changes."
  };
}

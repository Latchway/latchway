import type { EnvironmentDraft } from "./environment-draft";

/** The status rail line for the working draft. */
export function draftSummary(draft: EnvironmentDraft): { chip: string; text: string; title: string } | undefined {
  const revision = draft.draft;
  if (!revision) return undefined;
  const issues = revision.validation?.issues.filter((issue) => issue.severity === "error").length ?? 0;
  const where = draft.environment ? ` in ${draft.environment.display_name}` : "";
  const state = revision.state === "valid"
    ? "Checked, ready to publish."
    : revision.state === "invalid"
      ? `${issues || "Some"} problem${issues === 1 ? "" : "s"} to fix before publishing.`
      : "Not validated yet.";
  return {
    chip: revision.state === "valid" ? "Draft ready" : revision.state === "invalid" ? "Draft has problems" : "Unpublished draft",
    text: `Draft ${revision.id}${where}. ${state} Requests keep using the live configuration until it's published.`,
    title: "Unpublished changes."
  };
}

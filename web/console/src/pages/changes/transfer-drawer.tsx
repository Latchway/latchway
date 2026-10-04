import { useState } from "react";

import { downloadText } from "../../components/download";
import { Button, ConfirmDialog, DetailPanel, Field, Notice, Segmented } from "../../ui";
import type { EnvironmentDraft } from "../build/environment-draft";
import type { JSONRecord } from "../configuration-slice";
import { ConfigurationTransferError, type ConfigurationDocument, parseConfigurationDocument, readConfigurationFile, redactionSafeConfigurationYAML } from "../configuration-transfer";
import { ProblemNotice } from "../control-plane-pages";
import { configurationDiff } from "./config-diff";

function exportText(document: unknown, format: "yaml" | "json"): string {
  // The YAML writer refuses credential-shaped fields, so it gates both formats.
  const yaml = redactionSafeConfigurationYAML(document);
  return format === "yaml" ? yaml : `${JSON.stringify(document, null, 2)}\n`;
}

/**
 * Export the live configuration or the draft, and import a file or pasted document into the draft. Nothing goes live
 * from here: an import replaces the draft and is reviewed and published under Draft like any other change.
 */
export function TransferDrawer({ draft, onClose }: { draft: EnvironmentDraft; onClose: () => void }) {
  const [source, setSource] = useState<"live" | "draft">(draft.draft ? "draft" : "live");
  const [format, setFormat] = useState<"yaml" | "json">("yaml");
  const [pasted, setPasted] = useState("");
  const [loaded, setLoaded] = useState<{ document: ConfigurationDocument; name: string }>();
  const [error, setError] = useState<string>();
  const [confirming, setConfirming] = useState(false);
  const [done, setDone] = useState<string>();
  const slug = draft.environment?.slug ?? "environment";
  const document = source === "draft" ? (draft.draft?.document as JSONRecord | undefined) : draft.activeDocument;
  let preview = "";
  let previewError: string | undefined;
  try {
    preview = document ? exportText(document, format) : "";
  } catch (failure) {
    previewError = failure instanceof Error ? failure.message : "This configuration can't be exported safely.";
  }
  const draftChanges = draft.draft ? configurationDiff(draft.activeDocument, draft.draft.document as JSONRecord).length : 0;

  async function choose(file?: File): Promise<void> {
    setError(undefined);
    setLoaded(undefined);
    if (!file) return;
    try {
      setLoaded({ document: await readConfigurationFile(file), name: file.name });
    } catch (failure) {
      setError(failure instanceof ConfigurationTransferError ? failure.message : "The file couldn't be read.");
    }
  }

  function parsePasted(): void {
    setError(undefined);
    try {
      setLoaded({ document: parseConfigurationDocument(pasted), name: "pasted text" });
    } catch (failure) {
      setError(failure instanceof ConfigurationTransferError ? failure.message : "That isn't a valid YAML or JSON document.");
    }
  }

  async function importToDraft(): Promise<void> {
    if (!loaded) return;
    const imported = loaded.document as unknown as JSONRecord;
    if (imported.kind !== "EnvironmentConfig" || !imported.spec) {
      setConfirming(false);
      setError("The document must be one EnvironmentConfig with apiVersion, kind, metadata and spec.");
      return;
    }
    const saved = await draft.save(() => imported, undefined, `Imported from ${loaded.name}`);
    setConfirming(false);
    if (saved) {
      setDone(`${loaded.name} is now the draft. Review it under Draft, then publish.`);
      setLoaded(undefined);
      setPasted("");
    }
  }

  return (
    <>
      <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">Applies to {draft.application?.display_name} · {draft.environment?.display_name} only</span>} title="Import / Export">
        <div className="lw-stack">
          <h3 className="lw-section-title">Export</h3>
          <div className="lw-row">
            <Segmented items={[{ id: "live", label: "Live" }, ...(draft.draft ? [{ id: "draft" as const, label: "Draft" }] : [])]} label="Export source" onChange={setSource} value={source} />
            <Segmented items={[{ id: "yaml", label: "YAML" }, { id: "json", label: "JSON" }]} label="Format" onChange={setFormat} value={format} />
          </div>
          {previewError ? <Notice tone="danger">{previewError}</Notice> : document ? <pre className="lw-code-block lw-bundle-preview">{preview}</pre> : <p className="lw-secondary lw-note">Nothing to export yet.</p>}
          <div className="lw-row"><Button disabled={!preview} icon="upload" onClick={() => downloadText(`latchway-${slug}-${source}.${format}`, preview, format === "yaml" ? "application/yaml" : "application/json")} size="sm">Download</Button></div>
          <p className="lw-secondary lw-note">Secrets appear only as references (secret/&lt;name&gt;), never as values.</p>

          <h3 className="lw-section-title">Import</h3>
          <Field hint="One YAML or JSON document, up to 1 MiB. Anchors, aliases, custom tags and duplicate keys are refused." id="import-file" label="File">
            <input accept=".json,.yaml,.yml,application/json,application/yaml,text/yaml" className="lw-file-input" id="import-file" onChange={(event) => void choose(event.currentTarget.files?.[0])} type="file" />
          </Field>
          <Field id="import-paste" label="Or paste">
            <textarea className="lw-json-editor lw-json-editor--short" id="import-paste" onChange={(event) => setPasted(event.target.value)} rows={6} spellCheck={false} value={pasted} />
          </Field>
          <div className="lw-row"><Button disabled={!pasted.trim()} onClick={parsePasted} size="sm">Check Pasted Text</Button></div>
          {error ? <Notice title="Can't import" tone="danger">{error}</Notice> : null}
          {loaded ? <Notice action={<Button disabled={!draft.canConfigure} onClick={() => (draftChanges ? setConfirming(true) : void importToDraft())} size="sm" variant="primary">Import to Draft</Button>} title="Ready to import" tone="info">{loaded.name} passed the local checks. Nothing has been sent yet.</Notice> : null}
          {done ? <Notice tone="success">{done}</Notice> : null}
          {draft.problem ? <ProblemNotice problem={draft.problem} /> : null}
          <p className="lw-secondary lw-note">Importing replaces the draft. The server validates it, and it goes live only when the draft is published.</p>
        </div>
      </DetailPanel>
      {confirming ? (
        <ConfirmDialog confirmLabel="Replace the Draft" description={`The draft has ${draftChanges} unpublished change${draftChanges === 1 ? "" : "s"}. Importing replaces them for everyone on the team. Live isn't affected.`} destructive onCancel={() => setConfirming(false)} onConfirm={() => void importToDraft()} pending={draft.busy} title="Replace the draft?" />
      ) : null}
    </>
  );
}

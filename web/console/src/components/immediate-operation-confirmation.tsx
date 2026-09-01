import { type FormEvent, type ReactNode, useId, useState } from "react";

interface ImmediateOperationConfirmationProps {
  acknowledgement: ReactNode;
  affectedScope: ReactNode;
  busy: boolean;
  confirmLabel: string;
  credentialRestoration: ReactNode;
  heading: ReactNode;
  onCancel: () => void;
  onConfirm: (reason: string | undefined) => void;
  reasonMaximumLength?: number;
  requiresReason?: boolean;
  reversibility: ReactNode;
  summary: ReactNode;
  timing: ReactNode;
}

export function ImmediateOperationConfirmation({
  acknowledgement,
  affectedScope,
  busy,
  confirmLabel,
  credentialRestoration,
  heading,
  onCancel,
  onConfirm,
  reasonMaximumLength = 100,
  requiresReason = false,
  reversibility,
  summary,
  timing
}: ImmediateOperationConfirmationProps) {
  const headingID = useId();
  const [acknowledged, setAcknowledged] = useState(false);
  const [reason, setReason] = useState("");
  const boundedReason = reason.trim();
  const canConfirm = acknowledged && (!requiresReason || boundedReason.length > 0);

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!canConfirm || busy) return;
    onConfirm(requiresReason ? boundedReason : undefined);
  }

  return <form aria-labelledby={headingID} className="control-form destructive-confirmation" onSubmit={submit}>
    <div><p className="eyebrow">Immediate operational action</p><h2 id={headingID}>{heading}</h2><p>{summary}</p></div>
    <div className="impact-grid">
      <div><strong>Takes effect</strong><span>{timing}</span></div>
      <div><strong>Reversible</strong><span>{reversibility}</span></div>
      <div><strong>Credential restoration</strong><span>{credentialRestoration}</span></div>
      <div><strong>Affected scope</strong><span>{affectedScope}</span></div>
    </div>
    {requiresReason ? <label>Operator reason<input autoComplete="off" maxLength={reasonMaximumLength} required value={reason} onChange={(event) => setReason(event.target.value)} /></label> : null}
    <label className="check-field"><input autoFocus checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" />{acknowledgement}</label>
    <div className="button-row"><button className="primary-action primary-action--danger" disabled={busy || !canConfirm} type="submit">{confirmLabel}</button><button className="secondary-action" disabled={busy} onClick={onCancel} type="button">Cancel</button></div>
  </form>;
}

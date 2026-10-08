import { useState } from "react";

import { ROLE_LABEL, ROLE_SUMMARY } from "../pages/team/roles";
import { ConfirmDialog } from "../ui";
import type { PreviewRole } from "./permissions";

const CHOICES: readonly PreviewRole[] = ["admin", "operator", "viewer"];

/** Owners pick a role to see the console as; the preview changes only what this console shows. */
export function RolePreviewDialog({ onCancel, onStart }: { onCancel: () => void; onStart: (role: PreviewRole) => void }) {
  const [role, setRole] = useState<PreviewRole>("viewer");
  return (
    <ConfirmDialog confirmLabel="Start Preview" description="See the console the way a member with this role does. Changes are off while you preview, and the server still checks every request against your own role." onCancel={onCancel} onConfirm={() => onStart(role)} title="Preview as a role">
      <div aria-label="Role" className="lw-stack" role="radiogroup">
        {CHOICES.map((choice) => (
          <label className="lw-check" key={choice}>
            <input checked={role === choice} name="preview-role" onChange={() => setRole(choice)} type="radio" value={choice} />
            <span><strong>{ROLE_LABEL[choice]}</strong> <span className="lw-secondary">{ROLE_SUMMARY[choice]}</span></span>
          </label>
        ))}
      </div>
    </ConfirmDialog>
  );
}

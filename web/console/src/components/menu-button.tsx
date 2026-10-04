import { type ReactNode, useCallback, useRef, useState } from "react";

import { Icon, type IconName, Menu, type MenuEntry } from "../ui";
import { useDismiss } from "./use-dismiss";

/** A button that opens a menu below it, closing on Escape, a choice, or a press outside. */
export function MenuButton({ children, entries, icon, label, size }: { children: ReactNode; entries: readonly MenuEntry[]; icon?: IconName; label: string; size?: "sm" }) {
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, anchor, close);
  return (
    <span className="lw-anchor" ref={anchor}>
      <button aria-expanded={open} aria-haspopup="menu" className={`lw-btn lw-btn--secondary${size ? ` lw-btn--${size}` : " lw-btn--lead"}`} onClick={() => setOpen(!open)} ref={button} type="button">
        {icon ? <Icon name={icon} /> : null}{children}
      </button>
      {open ? <div className="lw-popover lw-popover--end"><Menu entries={entries} label={label} onClose={() => { setOpen(false); button.current?.focus(); }} /></div> : null}
    </span>
  );
}

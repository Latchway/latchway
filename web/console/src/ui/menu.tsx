import { type KeyboardEvent, type ReactNode, useEffect, useRef } from "react";

import { cx } from "./cx";
import { Icon, type IconName } from "./icon";

export type MenuEntry =
  | { heading: ReactNode; kind: "heading" }
  | { kind: "separator" }
  | { checked?: boolean; destructive?: boolean; icon?: IconName; kind?: "item"; label: ReactNode; meta?: ReactNode; onSelect: () => void };

interface MenuProps {
  className?: string;
  entries: readonly MenuEntry[];
  label: string;
  onClose: () => void;
}

/**
 * Popup menu. Focus moves to the first item on open; arrow keys, Home and End move between items; Escape closes and
 * returns focus to the opener (the caller's trigger).
 */
export function Menu({ className, entries, label, onClose }: MenuProps) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    root.current?.querySelector<HTMLElement>("[role='menuitem']")?.focus();
  }, []);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>): void {
    const items = Array.from(root.current?.querySelectorAll<HTMLElement>("[role='menuitem']") ?? []);
    const index = items.indexOf(document.activeElement as HTMLElement);
    const move = (next: number) => {
      event.preventDefault();
      items.at(next % items.length)?.focus();
    };
    if (event.key === "ArrowDown") move(index + 1);
    else if (event.key === "ArrowUp") move(index - 1);
    else if (event.key === "Home") move(0);
    else if (event.key === "End") move(-1);
    else if (event.key === "Escape" || event.key === "Tab") onClose();
  }

  return (
    <div aria-label={label} className={cx("lw-menu", className)} onKeyDown={onKeyDown} ref={root} role="menu">
      {entries.map((entry, index) => {
        if (entry.kind === "separator") return <div className="lw-menu__sep" key={index} role="separator" />;
        if (entry.kind === "heading") return <div className="lw-menu__label" key={index}>{entry.heading}</div>;
        return (
          <button
            className={cx("lw-menu__item", entry.destructive && "lw-menu__item--destructive")}
            key={index}
            onClick={() => {
              onClose();
              entry.onSelect();
            }}
            role="menuitem"
            tabIndex={-1}
            type="button"
          >
            {entry.icon ? <Icon name={entry.icon} /> : <span style={{ width: 16 }} />}
            <span className="lw-menu__item-label">{entry.label}</span>
            {entry.meta}
            {entry.checked ? <Icon name="check" style={{ color: "var(--accent-primary)" }} /> : null}
          </button>
        );
      })}
    </div>
  );
}

import { type RefObject, useEffect, useRef } from "react";

const FOCUSABLE = "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

/**
 * Keeps keyboard focus inside a modal surface while it is open: focuses the first `[data-autofocus]` (or first
 * focusable) element, cycles Tab within it, closes on Escape, and returns focus to whatever opened it.
 */
export function useFocusTrap(container: RefObject<HTMLElement | null>, onEscape?: () => void): void {
  const escape = useRef(onEscape);
  useEffect(() => {
    escape.current = onEscape;
  });

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const root = container.current;
    const focusables = () => Array.from(root?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []).filter((element) => !element.closest("[aria-hidden='true']"));
    (root?.querySelector<HTMLElement>("[data-autofocus]") ?? focusables()[0] ?? root)?.focus();

    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape" && escape.current) {
        event.preventDefault();
        escape.current();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusables();
      const first = items[0];
      const last = items.at(-1);
      if (!first || !last) {
        event.preventDefault();
        return;
      }
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      if (opener?.isConnected) opener.focus();
    };
  }, [container]);
}

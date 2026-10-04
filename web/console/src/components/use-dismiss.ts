import { type RefObject, useEffect } from "react";

/** Closes a popover on Escape or a press outside its anchor. */
export function useDismiss(open: boolean, anchor: RefObject<HTMLElement | null>, close: () => void): void {
  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent): void {
      if (event.target instanceof Node && !anchor.current?.contains(event.target)) close();
    }
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape") {
        event.stopPropagation();
        close();
      }
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown, true);
    };
  }, [anchor, close, open]);
}

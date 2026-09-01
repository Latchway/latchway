import { useRouter } from "@tanstack/react-router";
import { useCallback, useEffect } from "react";

export const unsavedChangesMessage = "You have unsaved changes. Leave this page and discard them?";

/**
 * Protects an in-browser draft from both document unloads and TanStack Router
 * navigation. The router is optional so focused editor tests and reusable
 * embeds still receive native unload protection without requiring an app shell.
 */
export function useDirtyEditProtection(
  dirty: boolean,
  message = unsavedChangesMessage
): void {
  const router = useRouter({ warn: false });
  const shouldBlock = useCallback(() => dirty && !window.confirm(message), [dirty, message]);

  useEffect(() => {
    if (!dirty) return;
    const beforeUnload = (event: BeforeUnloadEvent): void => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [dirty]);

  useEffect(() => {
    if (!dirty || !router?.history) return;
    return router.history.block({
      blockerFn: shouldBlock,
      enableBeforeUnload: false
    });
  }, [dirty, router, shouldBlock]);
}

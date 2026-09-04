import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";

import {
  consoleCompatibilityBackgroundExpiry,
  consoleCompatibilityQueryOptions,
  evaluateConsoleCompatibility,
} from "../api/console-compatibility";
import type { SystemStatus } from "../api/admin";
import { useConsoleSession } from "../api/session";
import { ConsoleCompatibilityContext, type ConsoleCompatibilityState } from "./console-compatibility-context";

interface InactiveAt {
  monotonic: number;
  wall: number;
}

interface AcceptedCompatibilityAt extends InactiveAt {
  dataUpdatedAt: number;
}

function inactiveClock(): InactiveAt {
  return { monotonic: performance.now(), wall: Date.now() };
}

export function ConsoleCompatibilityProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const session = useConsoleSession();
  const authenticatedSession = session.data?.mode === "configured"
    ? session.data.session
    : undefined;
  const configured = Boolean(authenticatedSession);
  const sessionKey = authenticatedSession
    ? `${authenticatedSession.administrator.id}:${authenticatedSession.organization_id}:${session.generation}`
    : undefined;
  const queryIdentity = useMemo(() => ({
    administratorID: authenticatedSession?.administrator.id ?? "signed-out",
    generation: session.generation,
    organizationID: authenticatedSession?.organization_id ?? "signed-out"
  }), [authenticatedSession?.administrator.id, authenticatedSession?.organization_id, session.generation]);
  const options = consoleCompatibilityQueryOptions(queryIdentity);
  const query = useQuery({
    ...options,
    enabled: configured
  });
  const compatibilityGeneration = queryClient.getQueryState(options.queryKey)?.dataUpdateCount ?? 0;
  const compatibility = useMemo(
    () => query.data ? evaluateConsoleCompatibility(query.data) : undefined,
    [query.data]
  );
  const acceptedCompatibility = useRef<AcceptedCompatibilityAt | undefined>(undefined);
  const grantExpiryTimer = useRef<number | undefined>(undefined);
  const [revokedObservation, setRevokedObservation] = useState<{
    generation: number;
    sessionKey: string;
  }>();
  const observationBlocked = Boolean(
    sessionKey
    && revokedObservation?.sessionKey === sessionKey
    && compatibilityGeneration <= revokedObservation.generation
  );

  useLayoutEffect(() => {
    window.clearTimeout(grantExpiryTimer.current);
    grantExpiryTimer.current = undefined;
    if (
      !sessionKey
      || !query.data
      || query.error !== null
      || !compatibility
      || compatibility.readOnlySafeMode
      || observationBlocked
    ) {
      acceptedCompatibility.current = undefined;
      return;
    }
    const accepted = inactiveClock();
    acceptedCompatibility.current = {
      ...accepted,
      dataUpdatedAt: query.dataUpdatedAt
    };
    grantExpiryTimer.current = window.setTimeout(() => {
      acceptedCompatibility.current = undefined;
      setRevokedObservation({ generation: compatibilityGeneration, sessionKey });
    }, consoleCompatibilityBackgroundExpiry);
    return () => {
      window.clearTimeout(grantExpiryTimer.current);
      grantExpiryTimer.current = undefined;
    };
  }, [compatibility, compatibilityGeneration, observationBlocked, query.data, query.dataUpdatedAt, query.error, sessionKey]);

  const { refetch } = query;
  const refresh = useCallback(async (): Promise<SystemStatus | undefined> => {
    const result = await refetch();
    return result.status === "success" ? result.data : undefined;
  }, [refetch]);

  const inactiveSince = useRef<InactiveAt | undefined>(undefined);
  const closeGrantSynchronously = useCallback(() => {
    window.clearTimeout(grantExpiryTimer.current);
    grantExpiryTimer.current = undefined;
    acceptedCompatibility.current = undefined;
    if (!sessionKey) return;
    flushSync(() => setRevokedObservation({ generation: compatibilityGeneration, sessionKey }));
  }, [compatibilityGeneration, sessionKey]);

  useEffect(() => {
    const beginInactive = () => {
      inactiveSince.current ??= inactiveClock();
    };
    const resume = () => {
      if (document.visibilityState === "hidden") return;
      const started = inactiveSince.current;
      if (!started) return;
      inactiveSince.current = undefined;
      const current = inactiveClock();
      const accepted = acceptedCompatibility.current;
      const inactiveExpired = current.wall - started.wall >= consoleCompatibilityBackgroundExpiry
        || current.monotonic - started.monotonic >= consoleCompatibilityBackgroundExpiry;
      const observationExpired = !accepted
        || current.wall - accepted.dataUpdatedAt >= consoleCompatibilityBackgroundExpiry
        || current.monotonic - accepted.monotonic >= consoleCompatibilityBackgroundExpiry;
      if (!inactiveExpired && !observationExpired) return;
      // Secret-bearing forms consume mutationAllowed. Commit the closed grant
      // before a re-entry request can resolve or any lower-priority focus
      // listener can begin its own refetch work.
      closeGrantSynchronously();
      void refetch();
    };
    const visibilityChanged = () => {
      if (document.visibilityState === "hidden") {
        beginInactive();
      } else {
        resume();
      }
    };
    if (document.visibilityState === "hidden") beginInactive();
    window.addEventListener("blur", beginInactive, true);
    window.addEventListener("focus", resume, true);
    document.addEventListener("visibilitychange", visibilityChanged, true);
    return () => {
      window.removeEventListener("blur", beginInactive, true);
      window.removeEventListener("focus", resume, true);
      document.removeEventListener("visibilitychange", visibilityChanged, true);
    };
  }, [closeGrantSynchronously, refetch]);

  const value = useMemo<ConsoleCompatibilityState>(() => ({
    compatibility,
    error: query.error,
    isFetching: query.isFetching,
    mutationAllowed: Boolean(
      configured
      && sessionKey
      && !observationBlocked
      && query.error === null
      && compatibility
      && !compatibility.readOnlySafeMode
    ),
    refresh,
    status: query.data
  }), [compatibility, configured, observationBlocked, query.data, query.error, query.isFetching, refresh, sessionKey]);

  return <ConsoleCompatibilityContext.Provider value={value}>{children}</ConsoleCompatibilityContext.Provider>;
}
